"""
This module builds a layer of abstraction for sending and receiving information in the form of
BouncyMessages instead of raw TCP traffic.
"""
import asyncio
import threading
from asyncio import StreamReader, StreamWriter
from random import randint
from typing import Optional, Dict, Tuple, List

from Crypto.PublicKey.RSA import RsaKey

from bfcp.protocol import PeerHandshake, pubkey_to_deterministic_string, pubkey_to_proto, get_node_pub_key
from bfcp.trust import TrustTableManager
from protos import bfcp_pb2
from protos.bfcp_pb2 import BouncyMessage

from logger import getLogger
from utils import recv_proto_msg, send_proto_msg

from config import *

_log = getLogger(__name__)


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
        await recv_proto_msg(self._reader, msg, GLOBAL_VARS['MAX_MESSAGE_LENGTH'], self._handshake.session_key)
        return msg

    async def send_bouncy_message(self, msg: BouncyMessage):
        await self._handshake_task
        await send_proto_msg(self._writer, msg, self._handshake.session_key)

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

    def __init__(self, bfc: 'BFCNode', own_rsa_key: RsaKey,
                 loop: asyncio.AbstractEventLoop, serving_host: Optional[Tuple[str, int]]=None,
                 max_clients=60, max_servers=60):
        self._async_loop = loop
        self._serving_host = serving_host
        self._own_rsa_key = own_rsa_key
        self._max_clients = max_clients
        self._max_servers = max_servers
        self._bfc = bfc
        self._next_message_futures = set()

        # This will be used so that new_messages() can block if there are no sockets to listen to
        self._new_socket_available = self._async_loop.create_future()

        self._open_client_sockets: Dict[bytes, BfcpSocketHandler] = {}
        self._open_server_sockets: Dict[bytes, BfcpSocketHandler] = {}

    async def start(self):
        if self._serving_host is not None:
            print('listening on ',self._serving_host )
            await asyncio.start_server(self._on_new_server_socket, self._serving_host[0], self._serving_host[1]) 

    async def send(self, msg: BouncyMessage, pub_key: Optional[RsaKey] = None) -> None:
        """
        Sends the provided BouncyMessage to the node in the network identified by the given public
        key. It's also possible to send a message to the node itself.
        """
        msg = self._wrap_into_bouncy_message(msg)

        if pub_key is None:
            node = self._bfc.trust_table_manager.get_random_node()
            pub_key = get_node_pub_key(node)

        _log.debug('Sending message: %s  %s->%s', msg.WhichOneof('message'),
                   self._bfc.trust_table_manager.get_node_by_pubkey(self._own_rsa_key).node.last_port,
                   self._bfc.trust_table_manager.get_node_by_pubkey(pub_key).node.last_port)

        pub_key_index = pubkey_to_deterministic_string(pub_key)
        if pub_key_index in self._open_client_sockets:
            await self._open_client_sockets[pub_key_index].send_bouncy_message(msg)
        elif pub_key_index in self._open_server_sockets:
            await self._open_server_sockets[pub_key_index].send_bouncy_message(msg)
        else:
            # We need to form a new connection
            node = self._bfc.trust_table_manager.get_node_by_pubkey(pub_key)
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
            # It is essential to wrap these into Tasks. Otherwise, after calling asyncio.wait()
            # our list of "done" tasks will contain different objects than the _new_message_futures
            # list. Therefore, we wouldn't be able to remove the completed tasks.
            asyncio.ensure_future(
                self._wrap_future_with_socket_handler(socket_handler.next_message(), socket_handler)
            )
        )

    async def new_messages(self) -> List[Tuple[RsaKey, BouncyMessage]]:
        if not self._next_message_futures:
            await self._new_socket_available

        # We will also wait on self._new_socket_available. If we get a new socket, we will keep
        # blocking on the call below even when the new socket has messages. This is because the
        # initial call was made without that socket in mind.
        self._new_socket_available = self._async_loop.create_future()
        done, _ = await asyncio.wait(self._next_message_futures | {self._new_socket_available},
                                     loop=self._async_loop, return_when=asyncio.FIRST_COMPLETED)

        msgs = []
        found_new_socket = False
        for f in done:
            if f == self._new_socket_available:
                found_new_socket = True
            else:
                msg, socket_handler = await f
                msgs.append((socket_handler.get_peer_key(), msg))

                self._next_message_futures.remove(f)
                self._add_future_for_next_message_from(socket_handler)

        if msgs == [] and found_new_socket:
            # retry
            return await self.new_messages()
        else:
            for pub_key, msg in msgs:
                _log.debug('Received message: %s  %s<-%s', msg.WhichOneof('message'),
                           self._bfc.trust_table_manager.get_node_by_pubkey(self._own_rsa_key).node.last_port,
                           self._bfc.trust_table_manager.get_node_by_pubkey(pub_key).node.last_port)
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

        if not self._new_socket_available.done():
            self._new_socket_available.set_result(True)

        return socket_handler

    async def _on_new_server_socket(self, reader: StreamReader, writer: StreamWriter):
        handler = await self._open_new_socket_handler(reader, writer)
        self._register_server_socket_handler(handler)

    def close(self):
        pass

    def get_loop(self) -> asyncio.AbstractEventLoop:
        return self._async_loop

    def _wrap_into_bouncy_message(self, msg):
        if isinstance(msg, BouncyMessage):
            return msg

        wrapped = BouncyMessage()
        if isinstance(msg, bfcp_pb2.DiscoveryRequest):
            wrapped.discovery_request.CopyFrom(msg)
        elif isinstance(msg, bfcp_pb2.NodeTable):
            wrapped.node_table.CopyFrom(msg)
        elif isinstance(msg, bfcp_pb2.ConnectionRequest):
            wrapped.connection_request.CopyFrom(msg)
        elif isinstance(msg, bfcp_pb2.ConnectionResponse):
            wrapped.connection_response.CopyFrom(msg)
        elif isinstance(msg, bfcp_pb2.ChannelRequest):
            wrapped.channel_request.CopyFrom(msg)
        elif isinstance(msg, bfcp_pb2.ChannelResponse):
            wrapped.channel_response.CopyFrom(msg)
        elif isinstance(msg, bfcp_pb2.ToOriginalSender):
            wrapped.to_original_sender.CopyFrom(msg)
        elif isinstance(msg, bfcp_pb2.ToTargetServer):
            wrapped.to_target_server.CopyFrom(msg)

        wrapped.ballast = b'\0' * randint(0, GLOBAL_VARS['MAX_BALLAST_BYTES'])
        return wrapped
