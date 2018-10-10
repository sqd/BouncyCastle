"""
TODO(han): just a stub.
"""
from protos.bfcp_pb2 import NodeTable


def TrustTableManager:
    def get_node_table() -> NodeTable:
        """
        Gets the node table of this node in the bfcp
        """
        raise NotImplementedError()

    async def update_table():
        raise NotImplementedError()
