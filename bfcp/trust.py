"""
TrustTableManager
"""
from typing import Tuple

from Crypto.PublicKey.RSA import RsaKey

from protos.bfcp_pb2 import NodeTable, NodeTableEntry, EndNodeRequirement


class Node:
    """
    A node. Corresponds to proto NodeTableEntry.
    """
    def __init__(self, pub_key: bytes, last_addr: [str, int], trust_score: float):
        self.pub_key = pub_key
        self.last_addr = last_addr
        self.trust_score = trust_score

    def toNodeTableEntry(self):
        raise NotImplementedError()

    @classmethod
    def fromNodeTableEntry(cls):
        pass


class TrustTableManager:
    def __init__(self, bfc_node: 'BFCNode'):
        """ Should contain self.node_table property """
        self.node_table = None # TODO
        raise NotImplementedError()

    def get_node_table(self) -> NodeTable:
        """
        Gets the node table of this node in the bfcp
        """
        return self.node_table

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