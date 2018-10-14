"""
TrustTableManager
"""
from typing import Tuple, Dict

from Crypto.PublicKey.RSA import RsaKey

from protos.bfcp_pb2 import NodeTable, NodeTableEntry, EndNodeRequirement


class Node:
    """
    A node. Corresponds to proto NodeTableEntry.
    """
    def __init__(self, pub_key: RsaKey, last_addr: Tuple[str, int], trust_score: float):
        self.pub_key = pub_key
        self.last_addr = last_addr
        self.trust_score = trust_score

    def toNodeTableEntry(self):
        raise NotImplementedError()

    @classmethod
    def fromNodeTableEntry(cls, entry: NodeTableEntry):
        # TODO rsa key deserialization
        return Node(entry.node.public_key, (entry.node.last_known_address, entry.node.last_port), entry.trust_score)


class TrustTableManager:
    def __init__(self):
        self._nodes: Dict[RsaKey, Node] = dict()
        raise NotImplementedError()

    def get_node_table(self) -> NodeTable:
        """
        Gets the node table of this node in the bfcp
        """
        raise NotImplementedError()

    def update_table(self):
        raise NotImplementedError()

    def get_node_by_pubkey(self, pubkey: RsaKey) -> Node:
        """ Returns NodeTableEntry in self.node_table contains an entry that match given pubkey,
          else return None """
        for node_table_entry in self.node_table.entries:
            node = node_table_entry.node
            # TODO check if node.public_key == pubkey
            # either convert node.public_key to `RsaKey` OR pubkey to `bytes`
            pub_key_match = None
            raise NotImplementedError()
        return None

    def get_node_with_requirement(self, en_requirement: EndNodeRequirement) -> RsaKey:
        """ Returns a node public key, given EndNodeRequirement like location must be in China"""
        raise NotImplementedError()

    def get_random_node(self) -> Node:
        """
        Get a random node for sending stuffs.
        :return: a random node.
        """
        raise NotImplementedError()