import threading
from typing import Callable, List, Tuple, Dict, Union, Optional
from enum import Enum, auto
from random import randint
from uuid import uuid4
from asyncio import ensure_future

import protos.bfcp_pb2 as bfcp_pb2
from Crypto.PublicKey.RSA import RsaKey

from bfcp.messages import TrafficManager, NodeNotFoundError
from bfcp.trust import TrustTableManager
import utils


class ConnectionType(Enum):
    origin = auto()
    relay = auto()
    neither = auto()


class ConnectionManager:
    def __init__(self, bfc_node: 'BFCNode'):
        #: Connections that originated from this node. uuid(str) -> Connection
        self._os_conn: Dict[str, Connection] = dict()

        #: Connection requests that pass through this node. uuid(str) -> (pub key of prev hop, pub key of next hop)
        self._relay_conn_requests: Dict[str, Tuple[RsaKey, RsaKey]] = dict()
        #: Channels that pass through this node. uuid(str) -> (pub key of prev hop, pub key of next hop)
        self._relay_channels: Dict[str, Tuple[RsaKey, RsaKey]] = dict()

        self._traffic_manager: TrafficManager = bfc_node.traffic_manager
        self._trust_table: TrustTableManager = bfc_node.trust_table_manager

    def check_conn_type(self, conn_uuid: str) -> ConnectionType:
        """
        Determine if a connection originated from ths node.
        :param conn_uuid: the uuid of the connection being checked.
        :return: the type of the connection.
        """
        if conn_uuid in self._os_conn:
            return ConnectionType.origin
        elif conn_uuid in self._relay_conn_requests:
            return ConnectionType.relay
        else:
            return ConnectionType.neither

    def new_connection(self, en_requirement: bfcp_pb2.EndNodeRequirement, addr: Tuple[str, int]) -> 'Connection':
        conn = Connection(self, self._traffic_manager)
        conn.initiate_connection(en_requirement, addr)
        self._os_conn[conn.uuid] = conn
        return conn

    def on_conn_request(self, msg: bfcp_pb2.ConnectionRequest, sender_key: RsaKey) -> None:
        if self.check_conn_type(msg.connection_params.uuid) != ConnectionType.neither:
            # Probably an error/malicious attempt
            return

        msg.connection_params.remaining_hops -= 1
        remaining_hops = msg.connection_params.remaining_hops

        def send_randomly():
            next_node = self._trust_table.get_random_node()
            self._relay_conn_requests[msg.conn_uuid] = (sender_key, next_node.pub_key)
            self._sync_send(msg, next_node.pub_key)

        if remaining_hops > 0:
            send_randomly()
        else:
            node = self._trust_table.get_node_with_requirement(msg.end_node_requirement)
            if node is None:
                if remaining_hops < -5:  # TODO config this
                    raise NodeNotFoundError('A node suitable for becoming EN was not found')
                else:
                    send_randomly()
            else:
                self._relay_conn_requests[msg.conn_uuid] = (sender_key, node.pub_key)
                self._sync_send(msg, node.pub_key)

    def on_conn_response(self, msg: bfcp_pb2.ConnectionResponse, sender_key: RsaKey):
        receiver_type = self.check_conn_type(msg.uuid)
        if receiver_type == ConnectionType.origin:
            self._os_conn[msg.uuid].on_end_node_found(msg.selected_end_node)
        elif receiver_type == ConnectionType.relay:
            self._sync_send(msg, self._relay_conn_requests[msg.uuid][0])

    def on_channel_request(self, msg: bfcp_pb2.ChannelRequest, sender_key):
        if self.check_conn_type(msg.channel_uuid) == ConnectionType.neither:
            next_node = self._trust_table.get_random_node()
            self._relay_channels[msg.channel_uuid] = (sender_key, next_node.pub_key)
            self._sync_send(msg, next_node.pub_key)

    def on_channel_response(self, msg: bfcp_pb2.ChannelResponse, sender_key):
        receiver_type = self.check_conn_type(msg.channel_id.connection_uuid)
        if receiver_type == ConnectionType.origin:
            self._os_conn[msg.channel_id.connection_uuid].on_channel_established(msg.channel_uuid, sender_key)
        elif receiver_type == ConnectionType.relay:
            self._sync_send(msg, self._relay_channels[msg.channel_id][0])

    def on_payload_received(self, msg: Union[bfcp_pb2.ToOriginalSender, bfcp_pb2.ToTargetServer]):
        receiver_type = self.check_conn_type(msg.channel_id.connection_uuid)
        if receiver_type == ConnectionType.origin:
            self._os_conn[msg.channel_id.connection_uuid].on_payload_received(msg)
        elif receiver_type == ConnectionType.relay:
            dir_idx = 1 if isinstance(msg, bfcp_pb2.ToTargetServer) else 0
            self._sync_send(msg, self._relay_channels[msg.channel_id][dir_idx])

    def _sync_send(self, msg: bfcp_pb2.BouncyMessage, pub_key: Optional[RsaKey] = None):
        ensure_future(self._traffic_manager.send(msg, pub_key))


class Connection:
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

        # Managers
        self._conn_manager = conn_manager
        self._traffic_manager = traffic_manager

        #: A list of (channel uuid, next hop pub key)
        self._channels: List[Tuple[str, RsaKey]] = []

        # Packet piecing stuffs
        self._next_recv_index = 0
        #: Packets that arrive too early
        self._future_packets: Dict[int, bfcp_pb2.BouncyMessage] = dict()
        self._next_send_index = 0

        # Info
        self.uuid: str = None

    def initiate_connection(self, en_requirement: bfcp_pb2.EndNodeRequirement, ts_address: Tuple[str, int]):
        """
        This function can only be called once.
        @param en_requirement: EndNodeRequirement from client configurations.
        @param ts_address: the address clients want to connect to.
        """
        conn_params = bfcp_pb2.ConnectionRoutingParams()
        conn_params.uuid = str(uuid4())
        self.uuid = conn_params.uuid
        conn_params.remaining_hops = randint(10, 20)  # TODO config

        # TODO self.sender_connection_signing_key = self.generate_public_key()

        conn_request = bfcp_pb2.ConnectionRequest()
        conn_request.connection_params = conn_params
        conn_request.end_node_requirement = en_requirement
        conn_request.target_server_address = ts_address[0]
        conn_request.target_server_port = ts_address[1]
        # TODO conn_request.sender_connection_signing_key = sender_connection_signing_key

        self._sync_send(conn_request)

    def on_end_node_found(self, en):
        # Found an EN, now try to establish channels
        # TODO config
        for i in range(5):
            channel_uuid = str(uuid4())
            channel_request = bfcp_pb2.ChannelRequest()
            # TODO channel_request.challenge = handshake.make_rsa_challenge() # TODO
            channel_request.end_node = en
            channel_request.channel_uuid = channel_uuid
            # TODO channel_request.original_sender_signature = raise NotImplementedError()

            self._sync_send(channel_request)

    def on_channel_established(self, channel_uuid: str, next_hop_pub_key: RsaKey):
        self._channels.append((channel_uuid, next_hop_pub_key))
        if len(self._channels) >= 5:  # TODO config this
            for callback in self._on_established:
                # TODO how do we know what exceptions are raised when there's a failure?
                callback(None)

    def on_payload_received(self, msg: bfcp_pb2.ToOriginalSender):
        if not isinstance(msg, bfcp_pb2.ToOriginalSender):
            # TODO panic this should not happen
            return

        if msg.index >= self._next_recv_index:
            self._future_packets[msg.index] = msg

        while self._next_recv_index in self._future_packets:
            for callback in self._on_new_data:
                callback(msg.payload)
            del(self._future_packets[self._next_recv_index])
            self._next_recv_index += 1

    def send(self, data: bytes):
        """
        Sends the specified data to the target server. This is a non-blocking call.
        """
        for (channel_uuid, next_hop_pub_key) in self._channels:
            channel_id = bfcp_pb2.ChannelID
            channel_id.connection_uuid = self.uuid
            channel_id.channel_uuid = channel_uuid

            payload_message = bfcp_pb2.ToTargetServer()
            payload_message.payload = data
            payload_message.channel_id = channel_id
            payload_message.index = self._next_send_index
            # TODO payload_message.original_sender_signature
            self._sync_send(payload_message, next_hop_pub_key)
        self._next_send_index += 1

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


class SocketConnection:
    """
    SocketConnection wraps the Connection class to provide the user with an interface similar to the
    Python's built in socket object.
    """

    def __init__(self, connection: Connection):
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
