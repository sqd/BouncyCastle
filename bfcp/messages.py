"""
This module builds a layer of abstraction for sending and receiving information in the form of
BouncyMessages instead of raw TCP traffic.
"""
from typing import Tuple, Callable

from Crypto.PublicKey.RSA import RsaKey

from bfcp.trust import TrustTableManager
from protos.bfcp_pb2 import BouncyMessage


class NodeNotFoundError(Exception):
    pass


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
                 on_new_message: Callable[[BouncyMessage, RsaKey, 'TrafficManager'], None],
                 max_clients=60, max_servers=60):
        self._max_clients = max_clients
        self._max_servers = max_servers
        self._trust_table_manager = trust_table_manager

    def send(self, pub_key: RsaKey, msg: BouncyMessage):
        """
        Sends the provided BouncyMessage to the node in the network identified by the given public
        key. This is a non-blocking call.
        """
        node = self._trust_table_manager.get_node_by_pubkey(pub_key)
        if node is None:
            raise NodeNotFoundError('A node with the provided public key does not exist in the '
                                    'trust table')

    def run(self):
        """
        Starts the async loop for routing traffic between nodes in the Bouncy Network. Note that
        this function never returns.
        """
        raise NotImplementedError()
