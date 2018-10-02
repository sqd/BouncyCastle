# -*- coding: utf-8 -*-

import socket
import errno
import select

from enum import Enum
from typing import List, Tuple, Iterable, Dict

from event_server import EventConsumer, EventServer
from BFC import BFCServer #TODO
from config import HTTPProxyServerConfig
from http_parser import HTTPParser, HTTPParseState
from utils import Ref


class _WorkerState(Enum):
    CREATED = 1
    RELAYING = 2


class _WorkerSocket(EventConsumer):
    def __init__(self, client_socket, server: EventServer):
        self._client_socket = client_socket
        self._client_recv_buf = b""
        """Data RECEIVED from the client."""
        self._client_send_buf = b""
        """Data to SEND to the client."""
        self._client_writable: bool = False
        """If the client is ready to accept data."""
        self._state = _WorkerState.CREATED
        self._server = server
        self._http_parser = HTTPParser()

    def start(self):
        pass

    def events(self):
        yield self._client_socket.fileno(), select.EPOLLIN|select.EPOLLOUT|select.EPOLLET

    def _handle_created(self, ev: int):
        """Event handler for state == CREATED"""
        if not ev & select.EPOLLIN:
            # We care only when we have something to parse.
            return
        ref_client_sent_buf = Ref(self._client_send_buf)
        parse_state = self._http_parser.feed(ref_client_sent_buf)
        self._client_send_buf = ref_client_sent_buf.v

        if parse_state == HTTPParseState.PARTIAL:
            return
        elif parse_state == HTTPParseState.ERROR:
            pass
        elif parse_state == HTTPParseState.SUCCESS:
            parse_result = self._http_parser.get_result()
            handle_verb(parse_result.method) #TODO
            self._state = _WorkerState.RELAYING
            self._handle_relaying(ev)

    def _handle_relaying(self, ev: int):
        """Event handler for state == RELAYING"""
        pass

    def handle_event(self, fileno: int, ev: int):
        if ev & select.EPOLLIN:
            try:
                while True:
                    r = self._client_socket.recv(1024)
                    if not r:
                        # died
                        self._server.unregister(self)
                        self._client_socket.close()
                        break
                    self._client_recv_buf += r
            except socket.error as e:
                if e.errno == errno.ENOTCONN:
                    # Only happens when this is a client socket which failed to connect.
                    self._client_socket.close()
                elif e.errno != errno.EAGAIN:
                    raise e

        if ev & select.EPOLLOUT:
            self._client_writable = True
            try:
                while self._client_send_buf:
                    byte_sent = self._client_socket.send(self._client_send_buf)
                    self._client_send_buf = self._client_send_buf[byte_sent:]
            except socket.error as e:
                if e.errno != errno.EAGAIN:
                    raise e
                else:
                    self._client_writable = False

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
