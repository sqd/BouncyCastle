"""
TODO(han): just a stub.
"""
from Crypto.PublicKey.RSA import RsaKey

from protos.bfcp_pb2 import NodeTable, NodeTableEntry, EndNodeRequirement


class TrustTableManager:
    def get_node_table(self) -> NodeTable:
        """
        Gets the node table of this node in the bfcp
        """
        raise NotImplementedError()

    async def update_table(self):
        raise NotImplementedError()

    def get_node_by_pubkey(self, pubkey: RsaKey) -> NodeTableEntry:
        """Returns None if not found"""
        raise NotImplementedError()

    def get_pubkey_by_node_requirement(self, en_requirement: EndNodeRequirement) -> RsaKey:
        """ Returns a node public key, given EndNodeRequirement like location must be in China """
        raise NotImplementedError()