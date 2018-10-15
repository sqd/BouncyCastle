import asyncio
import threading
from typing import Callable, List, Tuple, Dict, Union, Optional, Set
from enum import Enum, auto
from random import randint
from uuid import uuid4
from asyncio import ensure_future, open_connection, gather

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

import protos.bfcp_pb2 as bfcp_pb2
from Crypto.PublicKey.RSA import RsaKey

from bfcp.protocol import pubkey_to_proto, proto_to_pubkey, get_node_pub_key
from bfcp.messages import TrafficManager, NodeNotFoundError
import utils

from config import *


class ConnectionType(Enum):
    origin = auto()
    relay = auto()
    end = auto()
    neither = auto()


class ConnectionManager:
    def __init__(self, bfc_node: 'BFCNode'):
        self._bfc_node = bfc_node
        self._traffic_manager = bfc_node.traffic_manager
        self._trust_table = bfc_node.trust_table_manager

        #: Connections that originated from this node. uuid(str) -> OriginalSenderConnection
        self._os_conn: Dict[str, OriginalSenderConnection] = dict()

        #: Connections for which this node is the end node.
        # uuid(str) -> (EndNodeConnection, set of (prev channel uuid, prev channel hop))
        self._en_conn: Dict[str, Tuple[EndNodeConnection, Set[Tuple[str, RsaKey]]]] = dict()

        #: Connection requests that pass through this node. uuid(str) -> (pub key of prev hop, pub key of next hop)
        self._relay_conn_requests: Dict[str, Tuple[RsaKey, RsaKey]] = dict()
        #: Channels that pass through this node. uuid(str) -> (pub key of prev hop, pub key of next hop)
        self._relay_channels: Dict[str, Tuple[RsaKey, RsaKey]] = dict()

    def _check_conn_type(self, conn_uuid: str) -> ConnectionType:
        """
        Determine if a connection originated from ths node.
        :param conn_uuid: the uuid of the connection being checked.
        :return: the type of the connection.
        """
        if conn_uuid in self._os_conn:
            return ConnectionType.origin
        elif conn_uuid in self._relay_conn_requests:
            return ConnectionType.relay
        elif conn_uuid in self._en_conn:
            return ConnectionType.end
        else:
            return ConnectionType.neither

    def new_connection(self, en_requirement: bfcp_pb2.EndNodeRequirement, addr: Tuple[str, int]) -> 'OriginalSenderConnection':
        conn = OriginalSenderConnection(self, self._traffic_manager)
        conn.initiate_connection(en_requirement, addr)
        self._os_conn[conn.uuid] = conn
        return conn

    async def on_conn_request(self, msg: bfcp_pb2.ConnectionRequest, sender_key: RsaKey) -> None:
        msg.connection_params.remaining_hops -= 1
        remaining_hops = msg.connection_params.remaining_hops

        async def send_randomly():
            next_node = self._trust_table.get_random_node()
            if msg.conn_uuid in self._relay_conn_requests:
                (prev_node, _) = self._relay_conn_requests[msg.conn_uuid]
                self._relay_conn_requests[msg.conn_uuid] = (prev_node, get_node_pub_key(next_node))
            else:
                self._relay_conn_requests[msg.conn_uuid] = (sender_key, get_node_pub_key(next_node))
            await self._traffic_manager.send(msg, get_node_pub_key(next_node))

        if remaining_hops > 0:
            await send_randomly()
        else:
            if self._bfc_node.meets_requirements(msg.end_node_requirement):
                await self._become_end_node(msg, sender_key)
            else:
                node = self._trust_table.get_node_with_requirement(msg.end_node_requirement)
                if node is None:
                    if remaining_hops < -GLOBAL_VARS['MAX_HOPS_WITHOUT_END_NODE']:
                        raise NodeNotFoundError('A node suitable for becoming EN was not found')
                    else:
                        await send_randomly()
                else:
                    self._relay_conn_requests[msg.conn_uuid] = (sender_key, get_node_pub_key(node))
                    await self._traffic_manager.send(msg, get_node_pub_key(node))

    async def on_conn_response(self, msg: bfcp_pb2.ConnectionResponse, sender_key: RsaKey):
        receiver_type = self._check_conn_type(msg.uuid)
        if receiver_type == ConnectionType.origin:
            await self._os_conn[msg.uuid].on_end_node_found(msg)
        elif receiver_type == ConnectionType.relay:
            await self._traffic_manager.send(msg, self._relay_conn_requests[msg.uuid][0])

    async def on_channel_request(self, msg: bfcp_pb2.ChannelRequest, sender_key: RsaKey):
        if proto_to_pubkey(msg.end_node.public_key) == self._bfc_node.rsa_key:
            # I am the end node
            self._en_conn[msg.routing_params.connection_uuid][1].add((msg.channel_uuid, sender_key))
        elif self._check_conn_type(msg.routing_params.connection_uuid) == ConnectionType.neither:
            msg.connection_params.remaining_hops -= 1
            next_node = self._trust_table.get_random_node().node \
                if msg.connection_params.remaining_hops > 0 else msg.end_node

            self._relay_channels[msg.channel_uuid] = (sender_key, get_node_pub_key(next_node))
            await self._traffic_manager.send(msg, proto_to_pubkey(next_node.public_key))

    async def on_channel_response(self, msg: bfcp_pb2.ChannelResponse, sender_key: RsaKey):
        receiver_type = self._check_conn_type(msg.channel_id.connection_uuid)
        if receiver_type == ConnectionType.origin:
            self._os_conn[msg.channel_id.connection_uuid].on_channel_established(msg.channel_uuid, sender_key)
        elif receiver_type == ConnectionType.relay:
            await self._traffic_manager.send(msg, self._relay_channels[msg.channel_uuid][0])

    async def on_payload_received(self, msg: Union[bfcp_pb2.ToOriginalSender, bfcp_pb2.ToTargetServer], sender_key: RsaKey):
        receiver_type = self._check_conn_type(msg.channel_id.connection_uuid)
        if receiver_type == ConnectionType.origin:
            self._os_conn[msg.channel_id.connection_uuid].on_payload_received(msg, sender_key)
        elif receiver_type == ConnectionType.relay:
            dir_idx = 1 if isinstance(msg, bfcp_pb2.ToTargetServer) else 0
            await self._traffic_manager.send(msg, self._relay_channels[msg.channel_id][dir_idx])
        elif receiver_type == ConnectionType.end:
            await self._en_conn[msg.channel_id.connection_uuid][0].send(msg.payload)

    async def _become_end_node(self, conn_request: bfcp_pb2.ConnectionRequest, sender_key: RsaKey):
        """
        Respond to a ConnectionRequest, saying that "I'll be the end node". And prepare to be one.
        """
        # solve the challenge
        solved_challenge = pkcs1_15.new(self._bfc_node.rsa_key).sign(
            conn_request.signature_challenge)

        conn_resp = bfcp_pb2.ConnectionResponse()
        conn_resp.uuid = conn_request.connection_params.uuid
        conn_resp.selected_end_node.public_key.CopyFrom(
            pubkey_to_proto(self._bfc_node.rsa_key.publickey()))
        conn_resp.selected_end_node.last_known_address = self._bfc_node.host[0]
        conn_resp.selected_end_node.last_known_port = self._bfc_node.host[1]

        conn_resp.signature_challenge_response = solved_challenge

        # Prepare the session key
        session_key = utils.generate_aes_key(GLOBAL_VARS['OS_EN_KEY_SIZE'])

        original_sender_pub_key = proto_to_pubkey(conn_request.sender_connection_key)
        cipher_rsa = PKCS1_OAEP.new(original_sender_pub_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        conn_resp.session_key.key = encrypted_session_key

        prev_hops = set()
        en_conn = EndNodeConnection(self._traffic_manager,
                                    conn_request.routing_params.uuid,
                                    conn_request.channel_uuid,
                                    prev_hops)
        self._en_conn[conn_request.routing_params.uuid] = (en_conn, prev_hops)

        gather(
            en_conn.initiate_connection((conn_request.target_server_address, conn_request.target_server_port)),
            self._traffic_manager.send(conn_resp)
        )


class EndNodeConnection:
    def __init__(self, tm: TrafficManager, conn_uuid: str, channel_uuid: str, prev_hops: Set[Tuple[str, RsaKey]]):
        self._traffic_manager = tm
        self._conn_uuid = conn_uuid
        self._channel_uuid = channel_uuid
        self._prev_hops = prev_hops
        self._reader_writer_future = None

    async def initiate_connection(self, addr: Tuple[str, int]):
        self._reader_writer_future = ensure_future(open_connection(*addr))

        reader, _ = await self._reader_writer_future
        while True:
            data = await reader.read()
            if not data:
                break
            ensure_future(self.on_recv(data))

    async def on_recv(self, data: bytes):
        # Send the data back to the OS
        msg = bfcp_pb2.ToOriginalSender()
        msg.channel_id.connection_uuid = self._conn_uuid
        msg.payload = data
        for (uuid, key) in self._prev_hops:
            msg.channel_id.channel_uuid = uuid
            ensure_future(self._traffic_manager.send(msg, key))

    async def send(self, data: bytes):
        _, writer = await self._reader_writer_future
        writer.write(data)


class OriginalSenderConnection:
    """
    A single connection from the original sender to the target server. This should be held by the
    original sender to keep track of the connection to the target server.

    It is required to call initiate_connection() after creating the Connection object. Only then
    will the connection be formed.
    """
    def __init__(self, conn_manager: ConnectionManager, traffic_manager: TrafficManager):
        #: On new data callbacks
        self._on_new_data: List[Callable[[bytes], None]] = []
        #: On connection closed callbacks
        self._on_closed: List[Callable[[Exception], None]] = []
        #: On established connection callbacks
        self._on_established: List[Callable[[Exception], None]] = []
        self._establish_event_fired = False

        # Managers
        self._conn_manager = conn_manager
        self._traffic_manager = traffic_manager

        #: A list of (channel uuid, next hop pub key)
        self._channels: List[Tuple[str, RsaKey]] = []

        # Packet piecing stuffs
        self._next_recv_index = 0
        self._close_connection_packet_index: Optional[int] = None
        self._is_closed = False

        #: Packets that arrive too early
        self._future_packets: Dict[int, bfcp_pb2.BouncyMessage] = dict()
        self._next_send_index = 0

        # Info
        self.uuid: str = str(uuid4())

        # Encryption:
        self._sender_connection_key: RsaKey = RSA.generate(GLOBAL_VARS['SENDER_CONNECTION_KEY_BITS'])
        self._challenge_bytes: bytes = get_random_bytes(GLOBAL_VARS['SIGNATURE_CHALLENGE_BYTES'])
        self._session_key: Optional[bytes] = None

    def initiate_connection(self, en_requirement: bfcp_pb2.EndNodeRequirement, ts_address: Tuple[str, int]):
        """
        This function can only be called once.
        @param en_requirement: EndNodeRequirement from client configurations.
        @param ts_address: the address clients want to connect to.
        """
        conn_request = bfcp_pb2.ConnectionRequest()

        conn_request.conn_params.uuid = self.uuid
        conn_request.conn_params.remaining_hops = randint(GLOBAL_VARS['MIN_CHANNEL_LENGTH'], GLOBAL_VARS['MAX_CHANNEL_LENGTH'])

        conn_request.end_node_requirement.CopyFrom(en_requirement)
        conn_request.target_server_address = ts_address[0]
        conn_request.target_server_port = ts_address[1]

        conn_request.sender_connection_key = pubkey_to_proto(
            self._sender_connection_key.publickey())
        conn_request.signature_challenge = self._challenge_bytes

        self._sync_send(conn_request)

    async def on_end_node_found(self, conn_resp: bfcp_pb2.ConnectionResponse):
        if self._is_closed:
            return

        # Verify the challenge
        end_node_key = proto_to_pubkey(conn_resp.selected_end_node.public_key)
        pkcs1_15.new(end_node_key).verify(self._challenge_bytes,
                                          conn_resp.signature_challenge_response)

        rsa_cipher = PKCS1_OAEP.new(self._sender_connection_key)
        self._session_key = rsa_cipher.decrypt(conn_resp.session_key.key)

        # Found an EN, now try to establish channels
        for i in range(GLOBAL_VARS['CHANNELS_PER_CONNECTION']):
            channel_uuid = str(uuid4())
            channel_request = bfcp_pb2.ChannelRequest()
            channel_request.end_node.CopyFrom(conn_resp.selected_end_node)
            channel_request.channel_uuid = channel_uuid
            channel_request.routing_params.uuid = self.uuid
            channel_request.routing_params.remaining_hops = self._make_channel_length()

            await self._traffic_manager.send(channel_request)

    def on_channel_established(self, channel_uuid: str, next_hop_pub_key: RsaKey):
        if self._is_closed:
            return

        self._channels.append((channel_uuid, next_hop_pub_key))
        if (not self._establish_event_fired) and \
                len(self._channels) >= GLOBAL_VARS['MIN_CHANNELS_TO_FIRE_ESTABLISH_EVENT']:
            self._establish_event_fired = True
            for callback in self._on_established:
                # TODO how do we know what exceptions are raised when there's a failure?
                callback(None)

    def on_payload_received(self, encrypted_msg: bfcp_pb2.ToOriginalSender, pubkey: RsaKey):
        if self._is_closed:
            return

        bouncy_tcp_bytes = utils.aes_decrypt(encrypted_msg.payload, self._session_key)
        msg = bfcp_pb2.BouncyTcpMessage()
        msg.ParseFromString(bouncy_tcp_bytes)

        if msg.payload == b'':
            # The connection has been closed
            self._close_connection_packet_index = msg.index
        else:
            # A new packet is ready to be processed
            if self._close_connection_packet_index is not None and \
                    msg.index > self._close_connection_packet_index:
                raise ConnectionError('Received a packet after the connection was closed by the '
                                      'server')
            if msg.index >= self._next_recv_index:
                self._future_packets[msg.index] = msg

            while self._next_recv_index in self._future_packets:
                for callback in self._on_new_data:
                    callback(msg.payload)
                del(self._future_packets[self._next_recv_index])
                self._next_recv_index += 1

        if self._next_recv_index == self._close_connection_packet_index:
            # Connection is ready to be closed
            self._close_internal()

    async def _send_internal(self, data: bytes):
        bouncy_tcp_msg = bfcp_pb2.BouncyTcpMessage()
        bouncy_tcp_msg.payload = data
        bouncy_tcp_msg.index = self._next_send_index
        self._next_send_index += 1

        encrypted_tcp_msg = utils.aes_encrypt(bouncy_tcp_msg.SerializeToString(),
                                              self._session_key)

        for (channel_uuid, next_hop_pub_key) in self._channels:
            msg = bfcp_pb2.ToTargetServer()
            msg.payload = encrypted_tcp_msg

            msg.channel_id.connection_uuid = self.uuid
            msg.channel_id.channel_uuid = channel_uuid

            await self._traffic_manager.send(msg, next_hop_pub_key)

    def send(self, data: bytes):
        """
        Sends the specified data to the target server. This is a non-blocking call
        """
        if data != b'':
            asyncio.ensure_future(self._send_internal(data))

    def close(self):
        """
        Closes the connection with the target server.
        """
        asyncio.ensure_future(self._send_internal(b''))
        self._close_internal()

    def register_on_new_data(self, callback: Callable[[bytes], None]) -> None:
        """
        Registers a callback for whenever new data is available from the target server. The callback
        will be called with the bytes retrieved from the connection.
        """
        self._on_new_data.append(callback)

    def unregister_on_new_data(self, callback: Callable[[bytes], None]) -> None:
        """
        Unregisters the specified callback function. Note, this needs to be the same object as was
        passed into register_on_new_data().
        """
        self._on_new_data.remove(callback)

    def register_on_established(self, callback: Callable[[Exception], None]) -> None:
        """
        Registers a callback for whenever the connection is securely established. If the Connection
        fails to be established, an Exception is passed to the callback. Otherwise, None is passed.
        """
        self._on_established.append(callback)

    def unregister_on_established(self, callback: Callable[[Exception], None]) -> None:
        """
        Unregisters the specified callback function. Note, this needs to be the same object as was
        passed into register_on_established().
        """
        self._on_established.remove(callback)

    def register_on_closed(self, callback: Callable[[Exception], None]) -> None:
        """
        Registers a callback for whenever the target server closes the connection.
        :param callback: The callback should accept a single parameter. The parameter will be None
        if the connection was closed correctly. If the connection was closed due to an error, an
        appropriate exception will be passed.
        """
        self._on_closed.append(callback)

    def unregister_on_closed(self, callback: Callable[[Exception], None]) -> None:
        """
        Unregisters the specified callback function. Note, this needs to be the same object as was
        passed into register_on_closed().
        """
        self._on_closed.remove(callback)

    def _sync_send(self, msg: bfcp_pb2.BouncyMessage, pub_key: Optional[bytes] = None):
        ensure_future(self._traffic_manager.send(msg, pub_key))

    def _make_channel_length(self):
        return randint(GLOBAL_VARS['MIN_CHANNEL_LENGTH'], GLOBAL_VARS['MAX_CHANNEL_LENGTH'])

    def _close_internal(self):
        if self._is_closed:
            return

        self._is_closed = True
        for callback in self._on_closed:
            callback()


class SocketConnection:
    """
    SocketConnection wraps the Connection class to provide the user with an interface similar to the
    Python's built in socket object.
    """

    def __init__(self, connection: OriginalSenderConnection):
        """
        :param connection: The connection to wrap
        """
        self._buffer = utils.BytesFifoQueue()
        self._connection = connection
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._closed = False
        self._close_reason = None

        self._connection.register_on_closed(lambda err: self._handle_closed(err))
        self._connection.register_on_new_data(lambda data: self._handle_new_data(data))

    def send(self, data: bytes) -> int:
        """
        Sends the specified data to the target server. This is a non-blocking call.

        :return: len(data). This is done to ensure compatibility with Python's built-in socket class
        """
        self.sendall(data)
        return len(data)

    def sendall(self, data: bytes) -> None:
        """
        Sends the specified data to the target server. This is a non-blocking call.
        """
        self._connection.send(data)

    def recv(self, max_bytes: int) -> bytes:
        """
        Takes at most max_bytes from the buffer of the socket and returns them. If the buffer is
        empty, this will block until some data is available. Otherwise, the function will return
        immediately.

        If the underlying Connection is closed, and there are no more bytes in the buffer, this will
        return an empty bytestring (b''). Moreover, if the connection was closed forcibly, a
        ConnectionError will be raised.
        """
        with self._lock:
            if self._buffer.available() == 0:
                if self._closed:
                    if self._close_reason is None:
                        return b''
                    else:
                        raise ConnectionError('Connection was forcibly closed', self._close_reason)
                self._condition.wait()
            return self._buffer.read(max_bytes)

    def recv_all(self, byte_count: int) -> bytes:
        """
        Takes byte_count bytes from the buffer of the socket. If the buffer does not have enough
        bytes, this function will block until it does.
        """
        with self._lock:
            while self._buffer.available() < byte_count:
                if self._closed:
                    raise ConnectionError('The connection was closed before enough data was '
                                          'transferred.', self._close_reason)
                self._condition.wait()
            return self._buffer.read(byte_count)

    def bytes_available(self) -> int:
        """
        :return: The number of bytes in the buffer
        """
        with self._lock:
            return self._buffer.available()

    def is_closed(self) -> bool:
        """
        :return: Indicates whether the socket is closed
        """
        return self._closed

    def get_close_reason(self) -> Exception:
        """
        :return: If the connection is closed, this will be the Exception given as the reason for
        closing the connection. If the connection was closed correctly this will be set to None.
        :raises ValueError: Raised if the connection is still open.
        """
        if not self._closed:
            raise ValueError('The connection is still open')
        return self._close_reason

    def _handle_closed(self, err: Exception) -> None:
        with self._lock:
            self._closed = True
            self._close_reason = err
            self._condition.notify_all()

    def _handle_new_data(self, data: bytes) -> None:
        with self._lock:
            self._buffer.write(data)
            self._condition.notify_all()
