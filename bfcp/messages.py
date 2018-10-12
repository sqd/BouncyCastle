"""
This module builds a layer of abstraction for sending and receiving information in the form of
BouncyMessages instead of raw TCP traffic.
"""
import asyncore
import socket
import threading
from typing import Callable, Optional

from Crypto.PublicKey.RSA import RsaKey
from google.protobuf.message import Message

from bfcp.handshake import pubkey_to_proto, PeerHandshake
from bfcp.trust import TrustTableManager
from protos import bfcp_pb2
from protos.bfcp_pb2 import BouncyMessage, ConnectionResponse

from logger import getLogger
from utils import BytesFifoQueue

_log = getLogger(__name__)


MAX_MESSAGE_LENGTH = 64 * 2**10  # 64 KiB
READ_CHUNK_SIZE = 4096


class NodeNotFoundError(Exception):
    pass


class ProtocolError(Exception):
    pass


class BfcpSocketHandler(asyncore.dispatcher_with_send):
    def __init__(self, sock: socket.socket, own_rsa_key: RsaKey, traffic_manager: TrafficManager,
                 own_serving_port: Optional[int]):
        asyncore.dispatcher_with_send.__init__(self, sock)

        self._own_serving_port = own_serving_port
        self._own_rsa_key = own_rsa_key
        self._traffic_manager = traffic_manager

        self._message_reading_state = 'waiting'  # one of: 'waiting', 'recv_len', 'recv_bytes'
        self._next_message_len: int = 0
        self._received_bytes = BytesFifoQueue()
        self._received_bytes_lock = threading.RLock()

        self._handshake_state: Optional[PeerHandshake] = None

    def handle_close(self):
        self._traffic_manager.notify_socket_closed(self)

    def send_message(self, proto_message: Message):
        msg = proto_message.SerializeToString()
        self.send(len(msg).to_bytes(4, 'big'))
        self.send(msg.encode())

    def handle_connect(self):
        self._handshake_state = PeerHandshake(self._own_rsa_key, self._own_serving_port,
                                              lambda msg: self.send_message(msg))

    def handle_read(self):
        data = self.recv(READ_CHUNK_SIZE)
        if data:
            with self._received_bytes_lock:
                self._received_bytes.write(data)
                self._process_received_bytes()

    def _handle_message(self, message_bytes: bytes):
        if self._handshake_state.complete:
            msg = BouncyMessage()
            msg.ParseFromString(message_bytes)
            self._traffic_manager.on_new_message(msg, self._handshake_state.peer_pub_key)
        else:
            self._handshake_state.handle_message(message_bytes)

    def _process_received_bytes(self):
        previous_state = ''
        while previous_state != self._message_reading_state:
            with self._received_bytes_lock:
                if self._message_reading_state == 'waiting':
                    if self._received_bytes.available() != 0:
                        self._message_reading_state = 'recv_len'
                elif self._message_reading_state == 'recv_len':
                    if self._received_bytes.available() >= 4:
                        self._next_message_len = int.from_bytes(self._received_bytes.read(4), 'big')
                        if self._next_message_len > MAX_MESSAGE_LENGTH:
                            self._terminate(ProtocolError('Received message is too large'))
                        self._message_reading_state = 'recv_bytes'
                elif self._message_reading_state == 'recv_bytes':
                    if self._received_bytes.available() >= self._next_message_len:
                        self._handle_message(self._received_bytes.read(self._next_message_len))
                        self._message_reading_state = 'waiting'

    def _terminate(self, reason_error):
        raise NotImplementedError()


class IncomingTrafficListener(asyncore.dispatcher):
    def __init__(self, host, port, traffic_manager: TrafficManager):
        asyncore.dispatcher.__init__(self)
        self._traffic_manager = traffic_manager
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            _log.info('Incoming connection from %s' % repr(addr))
            handler = BfcpSocketHandler(sock, self._traffic_manager)
            self._traffic_manager.add()


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

    def __init__(self, trust_table_manager: TrustTableManager,
                 on_new_message: Callable[[BouncyMessage, RsaKey, TrafficManager], None],
                 max_clients=60, max_servers=60):
        self._on_new_message = on_new_message
        self._max_clients = max_clients
        self._max_servers = max_servers
        self._trust_table_manager = trust_table_manager

        self._open_client_sockets = {}
        self._open_server_sockets = {}

    def send(self, pub_key: RsaKey, msg: BouncyMessage) -> None:
        """
        Sends the provided BouncyMessage to the node in the network identified by the given public
        key. This is a non-blocking call. It's also possible to send a message to the node itself.
        """
        node = self._trust_table_manager.get_node_by_pubkey(pub_key)
        if node is None:
            raise NodeNotFoundError('A node with the provided public key does not exist in the '
                                    'trust table')

    def on_new_message(self, msg: BouncyMessage, sender_key: RsaKey):
        if isinstance(msg, bfcp_pb2.ConnectionResponse):
            conn_manager.on_conn_response(msg, sender_key)
        elif isinstance(msg, bfcp_pb2.ChannelResponse):
            conn_manager.on_channel_response(msg, sender_key)
        elif isinstance(msg, bfcp_pb2.ToOriginalSender):
            conn_manager.on_payload_received(msg)
        # we're helping out other people below this line
        elif isinstance(msg, bfcp_pb2.ToTargetServer):
            pass
        elif isinstance(msg, bfcp_pb2.ToTargetServer):
            pass

    def handle_message_bytes(self, data: bytes) -> None:
        new_message = BouncyMessage()
        new_message.ParseFromString(data.decode())
        self._on_new_message(new_message, )

    def run(self):
        """
        Starts the async loop for routing traffic between nodes in the Bouncy Network. Note that
        this function never returns.
        """
        raise NotImplementedError()
