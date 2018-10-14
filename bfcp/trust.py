"""
TrustTableManager
"""
from typing import Tuple, Dict, Optional

from Crypto.PublicKey.RSA import RsaKey
from randomdict import RandomDict
import protos.bfcp_pb2 as bfcp_pb2

from protos.bfcp_pb2 import NodeTable, NodeTableEntry, EndNodeRequirement


class TrustTableManagerTask:
    def run(self, tm: 'TrustTableManager') -> None:
        raise NotImplementedError()


class SendNodeTableTask(TrustTableManagerTask):
    def __init__(self, recipient: RsaKey):
        self._recipient = recipient

    def run(self, tm: 'TrustTableManager'):
        raise NotImplementedError() # TODO


class MergeNodeTableTask(TrustTableManagerTask):
    def __init__(self, source: RsaKey, table:bfcp_pb2.NodeTable):
        self._source = source
        self._table = table

    def run(self, tm: 'TrustTableManager'):
        raise NotImplementedError() # TODO


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
        # TODO
        self._nodes: Dict[RsaKey, Node] = RandomDict()

    def get_node_table(self) -> NodeTable:
        """
        Gets the node table of this node in the bfcp
        """
        raise NotImplementedError()

    def update_table(self):
        raise NotImplementedError()

    def get_node_by_pubkey(self, pub_key: RsaKey) -> Optional[Node]:
        """
        Returns a Node with the pub key, else return None
        """
        return self._nodes.get(pub_key, None)

    def get_node_with_requirement(self, en_requirement: EndNodeRequirement) -> RsaKey:
        """ Returns a node public key, given EndNodeRequirement like location must be in China"""
        raise NotImplementedError()

    def get_random_node(self) -> Node:
        """
        Get a random node for sending stuffs.
        :raises ValueError if there is no node.
        :return: a random node.
        """
        if len(self._nodes) == 0:
            raise ValueError("No node in the trust table.")
        # TODO there may be a better solution
        return self._nodes.random_value()
