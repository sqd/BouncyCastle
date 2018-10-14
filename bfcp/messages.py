"""
This module builds a layer of abstraction for sending and receiving information in the form of
BouncyMessages instead of raw TCP traffic.
"""
import asyncio
import asyncore
import socket
import threading
from asyncio import StreamReader, StreamWriter
from typing import Callable, Optional, Dict, Union, Tuple, List

from Crypto.PublicKey.RSA import RsaKey
from google.protobuf.message import Message

from bfcp.handshake import pubkey_to_proto, PeerHandshake, pubkey_to_deterministic_string
from bfcp.trust import TrustTableManager
from protos import bfcp_pb2
from protos.bfcp_pb2 import BouncyMessage, ConnectionResponse

from logger import getLogger
from utils import BytesFifoQueue, recv_proto_msg, send_proto_msg

_log = getLogger(__name__)


MAX_MESSAGE_LENGTH = 64 * 2**10  # 64 KiB
READ_CHUNK_SIZE = 4096


class NodeNotFoundError(Exception):
    pass


class BfcpSocketHandler:
    def __init__(self, reader: StreamReader, writer: StreamWriter, own_rsa_key: RsaKey,
                 traffic_manager: 'TrafficManager', own_serving_port: Optional[int]):
        self._writer = writer
        self._reader = reader
        self._own_serving_port = own_serving_port
        self._own_rsa_key = own_rsa_key
        self._traffic_manager = traffic_manager

        self._handshake_task = None
        self._handshake = PeerHandshake(reader, writer, own_rsa_key, own_serving_port)

    async def establish(self):
        self._handshake_task = asyncio.ensure_future(self._handshake.execute())
        await self._handshake_task

    async def wait_till_established(self):
        if self._handshake_task is None:
            raise ValueError('wait_till_established() can only be called after establish()')
        await self._handshake_task

    async def next_message(self) -> BouncyMessage:
        await self._handshake_task

        msg = BouncyMessage()
        await recv_proto_msg(self._reader, msg, MAX_MESSAGE_LENGTH)
        return msg

    async def send_bouncy_message(self, msg: BouncyMessage):
        await self._handshake_task
        await send_proto_msg(self._writer, msg)

    def get_peer_key(self):
        return self._handshake.peer_pub_key


class TrafficManager:
    """
    TrafficManager manages the TCP traffic of this BFCP node and converts it into BouncyMessages.
    It will also call the provided handler on each new message. This is an async based class.

    Example usage:

    def handle_message(bouncy_message, sender_key, traffic_manager):
        # Sends the connection request back to the sender
        if m.message.HasField('connection_request'):
            traffic_manager.send(sender_key, bouncy_message)

    TrafficManager(trust_table_man, handle_message)
    TrafficManager.run()  # never returns
    """

    def __init__(self, trust_table_manager: TrustTableManager, own_rsa_key: RsaKey,
                 loop: asyncio.AbstractEventLoop, serving_host: Optional[Tuple[str, int]]=None,
                 max_clients=60, max_servers=60):
        self._async_loop = loop
        self._serving_host = serving_host
        self._own_rsa_key = own_rsa_key
        self._max_clients = max_clients
        self._max_servers = max_servers
        self._trust_table_manager = trust_table_manager
        self._next_message_futures = set()

        # This will be used so that new_messages() can block if there are no sockets to listen to
        # TODO: modify this accordingly when sockets are removed
        self._sockets_available_future = self._async_loop.create_future()

        self._open_client_sockets: Dict[bytes, BfcpSocketHandler] = {}
        self._open_server_sockets: Dict[bytes, BfcpSocketHandler] = {}

        if self._serving_host is not None:
            self._server = self._async_loop.run_until_complete(
                asyncio.start_server(
                    lambda reader, writer: self._on_new_server_socket(reader, writer),
                    self._serving_host[0], self._serving_host[1], loop=self._async_loop)
            )

    async def send(self, pub_key: RsaKey, msg: BouncyMessage) -> None:
        """
        Sends the provided BouncyMessage to the node in the network identified by the given public
        key. It's also possible to send a message to the node itself.
        """
        pub_key_index = pubkey_to_deterministic_string(pub_key)
        if pub_key_index in self._open_client_sockets:
            await self._open_client_sockets[pub_key_index].send_bouncy_message(msg)
        elif pub_key_index in self._open_server_sockets:
            await self._open_server_sockets[pub_key_index].send_bouncy_message(msg)
        else:
            # We need to form a new connection
            node = self._trust_table_manager.get_node_by_pubkey(pub_key)
            if node is None:
                raise NodeNotFoundError('A node with the provided public key does not exist in the '
                                        'trust table')

            reader, writer = await asyncio.open_connection(
                node.node.last_known_address, node.node.last_port, loop=self._async_loop)
            handler = await self._open_new_socket_handler(reader, writer)
            self._register_client_socket_handler(handler)
            self._open_client_sockets[pub_key_index] = handler
            await handler.send_bouncy_message(msg)

    @staticmethod
    async def _wrap_future_with_socket_handler(future, socket_handler):
        return await future, socket_handler

    def _add_future_for_next_message_from(self, socket_handler: BfcpSocketHandler):
        self._next_message_futures.add(
            self._wrap_future_with_socket_handler(socket_handler.next_message(), socket_handler)
        )

    async def new_messages(self) -> List[Tuple[RsaKey, BouncyMessage]]:
        if self._next_message_futures == []:
            await self._sockets_available_future

        done, self._next_message_futures = await asyncio.wait(
            self._next_message_futures, loop=self._async_loop, return_when=asyncio.FIRST_COMPLETED)

        msgs = []
        for f in done:
            msg, socket_handler = await f
            msgs.append((socket_handler.get_peer_key(), msg))
            self._add_future_for_next_message_from(socket_handler)
        return msgs

    def _register_server_socket_handler(self, socket_handler: BfcpSocketHandler):
        pub_key_index = pubkey_to_deterministic_string(socket_handler.get_peer_key())
        self._open_server_sockets[pub_key_index] = socket_handler

    def _register_client_socket_handler(self, socket_handler: BfcpSocketHandler):
        pub_key_index = pubkey_to_deterministic_string(socket_handler.get_peer_key())
        self._open_client_sockets[pub_key_index] = socket_handler

    async def _open_new_socket_handler(self, reader, writer) -> BfcpSocketHandler:
        serving_port = None if self._serving_host is None else self._serving_host[1]
        socket_handler = BfcpSocketHandler(reader, writer, self._own_rsa_key, self, serving_port)
        await socket_handler.establish()
        self._add_future_for_next_message_from(socket_handler)

        if not self._sockets_available_future.done():
            self._sockets_available_future.set_result(True)

        return socket_handler

    async def _on_new_server_socket(self, reader, writer):
        handler = await self._open_new_socket_handler(reader, writer)
        self._register_server_socket_handler(handler)
