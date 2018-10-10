"""
This module builds a layer of abstraction for sending and receiving information in the form of
BouncyMessages instead of raw TCP traffic.
"""
from typing import Tuple

from Crypto.PublicKey.RSA import RsaKey

from bfcp.trust import TrustTableManager
from protos.bfcp_pb2 import BouncyMessage


class MessageManager:
    """
    MessageManager manages the TCP traffic of this BFCP node and converts it into BouncyMessages
    """

    def __init__(self, trust_table_manager: TrustTableManager):
        self.trust_table_manager = trust_table_manager

    async def next_message(self) -> Tuple[RsaKey, BouncyMessage]:
        pass

    def send(self, pub_key: RsaKey, msg: BouncyMessage):
        node = self.trust_table_manager.get_node_by_pubkey(pub_key)

