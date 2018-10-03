# -*- coding: utf-8 -*-

import socket
import errno
import select

from enum import Enum
from typing import List, Tuple, Iterable, Dict

from event_server import EventConsumer, EventServer
from config import HTTPProxyServerConfig
from http_parser import HTTPParser, HTTPParseState
from utils import Ref


class _WorkerSession:
    """
    Handles a worker session to get things sent through a BFC node. Since a connection can have multiple HTTP requests passing through.
    """
    def __init__(self, bfc: BFCServer):
        pass


class _WorkerState(Enum):
    CREATED = 1
    RELAYING = 2


class _WorkerSocket(EventConsumer):
    """Handles a worker connection."""
    def __init__(self, client_socket, bfc: BFCNode, server: EventServer):
        self._client_socket = client_socket
        self._client_recv_buf = b""
        """Data RECEIVED from the client."""
        self._client_send_buf = b""
        """Data to SEND to the client."""
        self._client_writable: bool = False
        """If the client is ready to accept data."""
        self._state = _WorkerState.CREATED
        self._server = server
        self._http_header_parser: HTTPHeaderParser = None
        self._http_body_parser: HTTPBodyParser = None
        self._cur_session: _WorkerSession = None
        self._bfc = bfc

    def start(self):
        pass

    def events(self):
        yield self._client_socket.fileno(), select.EPOLLIN|select.EPOLLOUT|select.EPOLLET

    @classmethod
    def _transform_proxy_header(header: HTTPRequestHeader)->HTTPRequestHeader:
        """
        Transform an proxy HTTPRequestHeader to none-proxy HTTPRequestHeader.
        """
        raise NotImplementedError()

    def terminate(self):
        """Abort and do the cleanups."""
        self._server.unregister(self)
        self._client_socket.close()
        raise NotImplementedError()

    def queue_send(self, s=b"")->int:
        """
        Try to send data to the client. Returns the number of bytes sent. All data will be queued for sending later nonetheless.
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

    def _handle_created(self, ev: int):
        """Event handler for state == CREATED"""
        if not ev & select.EPOLLIN:
            # We care only when we have something to parse.
            return
        ref_client_sent_buf = Ref(self._client_send_buf)
        self._http_header_parser = HTTPHeaderParser()
        parse_result = self._http_header_parser.feed(ref_client_sent_buf)
        self._client_send_buf = ref_client_sent_buf.v

        if parse_result == HTTPParseState.PARTIAL:
            return
        elif parse_result == HTTPParseState.ERROR:
            self.terminate()
        elif isinstance(parse_result, HTTPRequestHeader):
            header = parse_result
            if header.method != "CONNECT":
                # if we are not doing HTTP CONNECT, then the header consumed is also a part of the request. (after conversion to non-proxy header)
                new_header = _WorkerSocket._transform_proxy_header(header)
                self._client_recv_buf = new_header.reconstruct() + self._client_recv_buf

            # This is the best we can do. Because HTTPS should use CONNECT anyway.
            port = header.location.port if header.location.port else 80
            self._cur_session = _WorkerSession((header.location.host, port), self, self._bfc)
            self._state = _WorkerState.RELAYING
            self._http_body_parser = HTTPBodyParser(header)
            self._handle_relaying(ev)

    def _handle_relaying(self, ev: int):
        """Event handler for state == RELAYING"""
        if ev & select.EPOLLIN:
            # I got some data from the client, I want to send it to the BFC.
            # but first, I need to determine if all the data belong to the current session.
            parse_result = self._http_body_parser.feed(self._client_recv_buf)
            if parse_result = HTTPParseState.PARTIAL:
                self._cur_session.send(self._client_recv_buf)
                self._client_recv_buf = b""
            elif parse_result == HTTPParseState.ERROR:
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


class _ListenSocket(EventConsumer):
    def __init__(self, ingress: Tuple[str, int], server: EventServer):
        self._listen_socket = None
        self._ingress = ingress
        self._server = server

    def handle_event(self, fileno, ev):
        # Only EPOLLIN is possible
        client_socket, addr = self._listen_socket.accept()

        client_socket.setblocking(0)
        worker = _WorkerSocket(client_socket, self._server)
        worker.start()
        self._server.register(worker)

    def start(self):
        self._listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_socket.bind(self._ingress)
        self._listen_socket.listen(5)
        self._listen_socket.setblocking(0)

    def events(self):
        yield self._listen_socket.fileno(), select.EPOLLIN


class HTTPProxyServer(EventServer):
    def __init__(self, config: HTTPProxyServerConfig):
        super().__init__()
        self._config = config

    def start(self):
        for addr in self._config.listen_addr:
            listen_socket = _ListenSocket(addr, self)
            listen_socket.start()
            self.register(listen_socket)
