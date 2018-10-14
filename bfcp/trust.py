"""
TrustTableManager
"""
from typing import Tuple, Dict, Optional, List
from queue import Queue
from threading import Thread

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

    def run(self, tm: 'TrustTableManager') -> None:
        tm.send_node_table(self._recipient)


class MergeNodeTableTask(TrustTableManagerTask):
    def __init__(self, source: RsaKey, table: bfcp_pb2.NodeTable):
        self._source = source
        self._table = table

    def run(self, tm: 'TrustTableManager') -> None:
        tm.merge_node_table(self._source, self._table)


class UpdateNodeTableTask(TrustTableManagerTask):
    def run(self, tm: 'TrustTableManager') -> None:
        tm.update_node_table()


class Node:
    """
    A node. Corresponds to proto NodeTableEntry.
    """
    def __init__(self, pub_key: RsaKey, last_addr: Tuple[str, int], trust_score: float):
        self.pub_key = pub_key
        self.last_addr = last_addr
        self.trust_score = trust_score

    def toNodeTableEntry(self) -> bfcp_pb2.NodeTableEntry:
        raise NotImplementedError()

    @classmethod
    def fromNodeTableEntry(cls, entry: NodeTableEntry) -> "Node":
        # TODO rsa key deserialization
        return Node(entry.node.public_key, (entry.node.last_known_address, entry.node.last_port), entry.trust_score)


class TrustTableManager:
    def __init__(self, bfc_node: 'BFCNode'):
        self._nodes: Dict[RsaKey, Node] = RandomDict()
        self._task_queue = Queue()
        self._traffic_manager = bfc_node.traffic_manager
        self._thread = Thread(target=self._loop())

    def update_table(self):
        raise NotImplementedError()

    def send_node_table(self, recipient: RsaKey):
        pass

    def merge_node_table(self, source: RsaKey, table: bfcp_pb2.NodeTable):
        pass

    def update_node_table(self):
        pass

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

    def run(self) -> None:
        """
        Spin up a new thread for this manager.
        """
        self._thread.start()

    def _loop(self):
        while True:  # TODO maybe have an exit signal for faster ctrl-c
            task: TrustTableManagerTask = self._task_queue.get(True, 10)  # TODO config timeout
            task.run(self)
