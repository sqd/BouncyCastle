# -*- coding: utf-8 -*-
from enum import Enum
from typing import Tuple, List, Union

from config import HTTPProxyServerConfig
from http_parser import HTTPHeaderParser, HTTPParseStatus, HTTPBodyParser, HTTPRequestHeader
from bfcp.node import BFCNode
from bfcp.connection import OriginalSenderConnection
import protos.bfcp_pb2 as bfcp_pb2
from utils import Ref

import asyncio

from logger import getLogger
_log = getLogger(__name__)


class _WorkerState(Enum):
    CREATED = 1
    RELAYING = 2


class _Worker:
    """Handles a worker connection."""
    def __init__(self, bfc: BFCNode, reader, writer):
        self._client_recv_buf = b""
        """Data RECEIVED from the client."""
        self._client_send_buf = b""
        """Data to SEND to the client."""
        self._client_writable: bool = False
        """If the client is ready to accept data."""
        self._state = _WorkerState.CREATED
        self._http_header_parser  = HTTPHeaderParser()
        self._http_body_parser: HTTPBodyParser = None
        self._cur_session: _WorkerSession = None
        self._bfc = bfc
        self.reader = reader
        self.writer = writer

    async def start(self):
        _log.debug("Got connection from (%s:%s)", *self.writer.get_extra_info('sockname'))

        while True:
            data = await self.reader.read(1)
            self._client_recv_buf += data
            if self._state == _WorkerState.CREATED:
                await self._handle_created()
            elif self._state == _WorkerState.RELAYING:
                await self._handle_relaying()

    async def _handle_created(self):
        """Event handler for state == CREATED"""
        ref_client_recv_buf = Ref(self._client_recv_buf)
        parse_result = self._http_header_parser.feed(ref_client_recv_buf)
        self._client_recv_buf = ref_client_recv_buf.v

        if parse_result == HTTPParseStatus.PARTIAL:
            return
        elif parse_result == HTTPParseStatus.ERROR:
            _log.debug("Worker got illegal input on (%s:%s)", *self.writer.get_extra_info('sockname'))
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
            await self._cur_session.start()
            await self._handle_relaying()

    async def _handle_relaying(self):
        """Event handler for state == RELAYING"""
        # I got some data from the client, I want to send it to the BFC.
        # but first, I need to determine if all the data belong to the current session.
        parse_result = self._http_body_parser.feed(self._client_recv_buf)
        if parse_result == HTTPParseStatus.PARTIAL:
            await self._cur_session.send(self._client_recv_buf)
            self._client_recv_buf = b""
        elif parse_result == HTTPParseStatus.ERROR:
            await self.terminate()
        elif isinstance(parse_result, int):
            # part of the buffer is the tail of the current session.
            await self._cur_session.send(self._client_recv_buf[:parse_result])
            # the rest belongs to the coming new session.
            self._client_recv_buf = self._client_recv_buf[parse_result:]

            await self._cur_session.end()
            self._state = _WorkerState.CREATED
            await self._handle_created()


class HTTPProxyServer:
    def __init__(self, config: HTTPProxyServerConfig, bfc: BFCNode):
        super().__init__()
        self._config = config
        self._bfc = bfc

    async def start(self):
        print('proxy start')
        addr = self._config.listen_address
        await asyncio.start_server(self.handle_conn, addr[0], addr[1])

    async def handle_conn(self, reader, writer):
        worker = _Worker(self._bfc, reader, writer)
        await worker.start()


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
        print('new worker session')

    async def send(self, s: bytes):
        """Send a message out through the BFC."""
        await self._bfc_conn.send(s)

    async def start(self):
        self._bfc_conn = await self._bfc.new_connection(bfcp_pb2.EndNodeRequirement(), self._location)
        self._bfc_conn.register_on_new_data(self.recv_callback)

    async def recv_callback(self, s: bytes):
        await self._worker.writer.write(s)

    async def end(self):
        """
        End this session.
        """
        self._bfc_conn.close()

