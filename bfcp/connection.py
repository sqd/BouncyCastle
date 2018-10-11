import threading
from typing import Callable, List, Tuple
import protos.bfcp_pb2 as bfcp_pb2
from random import randint
from uuid import uuid4
import handshake
from bfcp.messages import TrafficManager, NodeNotFoundError
from bfcp.trust import TrustTableManager

import utils

class ConnectionManager:
    def __init__(self, traffic_manager):
        self._connections = dict()
        self._traffic_manager = traffic_manager

    def new_connection(self, en_requirement: bfcp_pb2.EndNodeRequirement, ts_address: Tuple[str, int]):
        conn = connection.Connection(self._traffic_manager)
        conn.initiate_connection(en_requirement, ts_address)
        return conn

    def on_conn_response(self, msg: bfcp_pb2.ConnectionResponse, sender_key):
        try:
            conn = self._connections[msg.UUID]
        except KeyError:
            raise NotImplementedError()
        conn.on_en_found(msg.selected_end_node)


class Connection:
    """
    A single connection from the original sender to the target server. This should be held by the
    original sender to keep track of the connection to the target server.

    It is required to call initiate_connection() after creating the Connection object. Only then
    will the connection be formed.
    """
    def __init__(self, traffic_manager):
        self._on_new_data: List[Callable[[bytes], None]] = []
        self._on_closed: List[Callable[[Exception], None]] = []
        self._on_established: List[Callable[[Exception], None]] = []
        self._traffic_manager = traffic_manager
        self._channels = []

    def initiate_connection(self, en_requirement: bfcp_pb2.EndNodeRequirement, ts_address: Tuple[str, int]):
        """
        This function can only be called once.
        @param en_requirement: EndNodeRequirement from client configurations
        @param ts_address: string address clients want to connect to
        """
        connection_params = bfcp_pb2.ConnectionRoutingParams()
        connection_params.UUID = str(uuid4())
        connection_params.remaining_hops = float(randint(10,20))

        self._end_node_requirement = en_requirement
        self._target_server_address = ts_address

        self.sender_connection_signing_key = self.generate_public_key()

        connection_request = bfcp_pb2.ConnectionRequest()
        connection_request.connection_params = connection_params
        connection_request.end_node_requirement = end_node_requirement
        connection_request.target_server_address = ts_address[0]
        connection_request.target_server_port = ts_address[1]
        connection_request.sender_connection_signing_key = sender_connection_signing_key

        handle_connection_request(connection_request, self._traffic_manager)


    def send(self, data: bytes):
        """
        Sends the specified data to the target server. This is a non-blocking call.
        """
        payload_message = bfcp_pb2.ToTargetServer()
        payload_message.payload = data
        for channel in self._channels:
            payload_message.channel_id = channel.id
            self._traffic_manager.send(channel.next_hop_pub_key, payload_message)

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

        Example:

            callback = lambda data: print(data.decode())
            connection.register_on_new_data(callback)

            # Do something ...

            connection.unregister_on_new_data(callback)
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

        Example:

            callback = lambda err: print(err)
            connection.register_on_established(callback)

            # Do something ...

            connection.unregister_on_established(callback)
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

        Example:

            callback = lambda err: print(str(err))
            connection.register_on_closed(callback)

            # Do something ...

            connection.unregister_on_closed(callback)
        """
        self._on_closed.remove(callback)


def handle_connection_request(conn_request: bfcp_pb2.ConnectionRequest, traffic_manager: TrafficManager):
    """
    Static function that receives a connections request and 
    decides where should the connection request be sent
    """
    remaining_hops = conn_request.connection_params.conn_request
    conn_request.connection_params.conn_request -= 1
    if remaining_hops >= 0:
        if remaining_hops == 1:
            # send to bouncy node that is well-suited to become EN 
            # if we want to access contents from China, EN should be in China
            trust_table_manager = TrustTableManager()
            pub_key = trust_table_manager.get_pubkey_by_node_requirement(conn_request.end_node_requirement)
            traffic_manager.send(pub_key, conn_request)
        else:
            # bounce to any random bouncy node
            # TODO: implement TrafficManager.run and provide arguments
            traffic_manager.run()
    else:
        # remaining_hops is negative, meaning that we were not able to
        # find a connection with desired requirements
        # thus, drop the connection
        raise NodeNotFoundError('A node suitable for becoming EN was not found')


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

    def on_en_found(self, en):
        # Found an EN, now try to establish channels
        raise NotImplementedError()
        channel_uuid = uuid.uuid4()
        channel_request = bfcp_pb2.ChannelRequest()
        channel_request.challenge = handshake.make_rsa_challenge() # TODO
        channel_request.end_node =  en
        channel_request.channel_UUID = channel_uuid
        channel_request.original_sender_signature = raise NotImplementedError()

        self._traffic_manager.on_new_message(channel_request, my_key, self._traffic_manager)
