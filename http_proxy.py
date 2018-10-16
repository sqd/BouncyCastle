# -*- coding: utf-8 -*-

import socket
import errno
import select

from enum import Enum
from typing import Tuple, List, Union

from event_server import EventConsumer, EventServer
from config import HTTPProxyServerConfig
from http_parser import HTTPHeaderParser, HTTPParseStatus, HTTPBodyParser, HTTPRequestHeader
from bfcp.node import BFCNode
from bfcp.connection import OriginalSenderConnection
from protos.bfcp_pb2 import EndNodeRequirement
from utils import Ref

from logger import getLogger
_log = getLogger(__name__)


class _WorkerState(Enum):
    CREATED = 1
    RELAYING = 2


class _Worker(EventConsumer):
    """Handles a worker connection."""
    def __init__(self, client_socket, client_address, bfc: BFCNode, ev_server: EventServer):
        self._client_socket = client_socket
        self._client_address = client_address
        self._client_recv_buf = b""
        """Data RECEIVED from the client."""
        self._client_send_buf = b""
        """Data to SEND to the client."""
        self._client_writable: bool = False
        """If the client is ready to accept data."""
        self._state = _WorkerState.CREATED
        self._ev_server = ev_server
        self._http_header_parser  = HTTPHeaderParser()
        self._http_body_parser: HTTPBodyParser = None
        self._cur_session: _WorkerSession = None
        self._bfc = bfc

    def start(self):
        # Nothing to do here
        _log.debug("Worker starts on (%s:%s) <-> (%s:%s)", *self._bindings())

    def events(self):
        yield self._client_socket.fileno(), select.EPOLLIN | select.EPOLLOUT | select.EPOLLET

    def terminate(self):
        """Abort and do the cleanups."""
        _log.debug("Terminating worker on (%s:%s) <-> (%s:%s)", *self._bindings())

        self._ev_server.unregister(self)
        if self._cur_session:
            self._cur_session.end()
        self._client_socket.close()

    def queue_send(self, s: bytes=b"")->int:
        """
        Try to send data to the client. Returns the number of bytes sent. All data will be queued for sending later
        nonetheless.
        return: Number of bytes sent.
        """
        total_byte_sent = 0
        self._client_send_buf += s
        try:
            while self._client_send_buf and self._client_writable:
                byte_sent = self._client_socket.send(self._client_send_buf)
                total_byte_sent += byte_sent
                self._client_send_buf = self._client_send_buf[byte_sent:]
        except socket.error as e:
            if e.errno != errno.EAGAIN:
                raise e
            else:
                self._client_writable = False
        return total_byte_sent

    def _bindings(self)->List[Union[str, int]]:
        addr = self._client_socket.getsockname()
        return [addr[0], addr[1], self._client_address[0], self._client_address[1]]

    def _handle_created(self, ev: int):
        """Event handler for state == CREATED"""
        if not ev & select.EPOLLIN:
            # We care only when we have something to parse.
            return
        ref_client_recv_buf = Ref(self._client_recv_buf)
        parse_result = self._http_header_parser.feed(ref_client_recv_buf)
        self._client_recv_buf = ref_client_recv_buf.v

        if parse_result == HTTPParseStatus.PARTIAL:
            return
        elif parse_result == HTTPParseStatus.ERROR:
            _log.debug("Worker got illegal input on (%s:%s) <-> (%s:%s)", *self._bindings())
            self.terminate()
        elif isinstance(parse_result, HTTPRequestHeader):
            header = parse_result
            if header.method != b"CONNECT":
                # if we are not doing HTTP CONNECT, then the header consumed is also a part of the request. (after
                # conversion to non-proxy header)
                header.unproxify()
                self._client_recv_buf = header.reconstruct() + self._client_recv_buf

            # This is the best we can do. Because HTTPS should use CONNECT anyway.
            port = header.location.port if header.location.port else 80
            self._state = _WorkerState.RELAYING
            self._http_body_parser = HTTPBodyParser(header)
            self._cur_session = _WorkerSession((header.location.netloc, port), self, self._bfc)
            self._cur_session.start()
            self._handle_relaying(ev)

    def _handle_relaying(self, ev: int):
        """Event handler for state == RELAYING"""
        if ev & select.EPOLLIN:
            # I got some data from the client, I want to send it to the BFC.
            # but first, I need to determine if all the data belong to the current session.
            parse_result = self._http_body_parser.feed(self._client_recv_buf)
            if parse_result == HTTPParseStatus.PARTIAL:
                self._cur_session.send(self._client_recv_buf)
                self._client_recv_buf = b""
            elif parse_result == HTTPParseStatus.ERROR:
                self.terminate()
            elif isinstance(parse_result, int):
                # part of the buffer is the tail of the current session.
                self._cur_session.send(self._client_recv_buf[:parse_result])
                # the rest belongs to the coming new session.
                self._client_recv_buf = self._client_recv_buf[parse_result:]

                self._cur_session.end()
                self._state = _WorkerState.CREATED
                self._handle_created(ev)
        if ev & select.EPOLLOUT:
            # I can write to the client, try to send the buffer I have
            self.queue_send()

    def handle_event(self, fileno: int, ev: int):
        if ev & select.EPOLLIN:
            try:
                while True:
                    r = self._client_socket.recv(1024)
                    if not r:
                        # died
                        self.terminate()
                        break
                    self._client_recv_buf += r
            except socket.error as e:
                if e.errno != errno.EAGAIN:
                    raise e

        if ev & select.EPOLLOUT:
            self._client_writable = True

        if self._state == _WorkerState.CREATED:
            self._handle_created(ev)
        elif self._state == _WorkerState.RELAYING:
            self._handle_relaying(ev)


class _Listener(EventConsumer):
    def __init__(self, ingress: Tuple[str, int], bfc: BFCNode, ev_server: EventServer):
        self._listen_socket = None
        self._ingress = ingress
        self._bfc = bfc
        self._ev_server = ev_server

    def handle_event(self, fileno, ev):
        # Only EPOLLIN is possible
        client_socket, addr = self._listen_socket.accept()

        client_socket.setblocking(0)
        worker = _Worker(client_socket, addr, self._bfc, self._ev_server)
        worker.start()
        self._ev_server.register(worker)

    def start(self):
        _log.info("HTTP proxy listening on %s", self._ingress)
        self._listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_socket.bind(self._ingress)
        self._listen_socket.listen(5)
        self._listen_socket.setblocking(False)

    def events(self):
        yield self._listen_socket.fileno(), select.EPOLLIN


class HTTPProxyServer:
    def __init__(self, config: HTTPProxyServerConfig, bfc: BFCNode, ev_server: EventServer):
        super().__init__()
        self._config = config
        self._bfc = bfc
        self._ev_server = ev_server

    def start(self):
        for addr in self._config.listen_address:
            listen_socket = _Listener(addr, self._bfc, self._ev_server)
            listen_socket.start()
            self._ev_server.register(listen_socket)


class _WorkerSession:
    """
    Handles a worker session to get things sent through a BFC node. Since a connection can have multiple HTTP
    requests passing through.
    """
    def __init__(self, location: Tuple[str, int], worker: _Worker, bfc: BFCNode):
        self._location = location
        self._worker = worker
        self._bfc = bfc
        self._bfc_conn: OriginalSenderConnection = None

    def send(self, s: bytes):
        """Send a message out through the BFC."""
        self._bfc_conn.send(s)

    def start(self):
        _log.info("Relaying to %s.", self._location)
        self._bfc_conn = self._bfc.new_connection(EndNodeRequirement(), self._location)
        _log.info("%s: got BFC connection.", self._location)
        self._bfc_conn.register_on_new_data(self.recv_callback)

    def recv_callback(self, s: bytes):
        self._worker.queue_send(s)

    def end(self):
        """
        End this session.
        """
        self._bfc_conn.close()

