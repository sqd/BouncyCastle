"""
TODO(han): just a stub.
"""
from Crypto.PublicKey.RSA import RsaKey

from protos.bfcp_pb2 import NodeTable, NodeTableEntry, EndNodeRequirement


class TrustTableManager:
    def __init__(self):
        """ Should contain self.node_table property """
        self.node_table = None # TODO
        raise NotImplementedError()

    def get_node_table(self) -> NodeTable:
        """
        Gets the node table of this node in the bfcp
        """
        return self.node_table

    async def update_table(self):
        raise NotImplementedError()

    def get_node_by_pubkey(self, pubkey: RsaKey) -> NodeTableEntry:
        for node_table_entry in self.node_table.entries:
            node = node_table_entry.node
            # TODO check if node.public_key == pubkey
            # either convert node.public_key to `RsaKey` OR pubkey to `bytes`
            pub_key_match = None
            raise NotImplementedError()
            if pub_key_match:
                return node_table_entry
        return None

    def get_pubkey_by_node_requirement(self, en_requirement: EndNodeRequirement) -> RsaKey:
        """ Returns a node public key, given EndNodeRequirement like location must be in China """
        raise NotImplementedError()