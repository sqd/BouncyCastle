"""
TrustTableManager
"""
from typing import Tuple, Dict, Optional, List, Set
from queue import Queue
from threading import Thread
from time import time

from Crypto.PublicKey.RSA import RsaKey
from randomdict import RandomDict

import protos.bfcp_pb2 as bfcp_pb2

from bfcp.messages import TrafficManager


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


"""
Statuc functions for bfcp_pb2.Node struct
"""

def to_node_table_entry(node: bfcp_pb2.Node) -> bfcp_pb2.NodeTableEntry:
    """ Constructs and returns NodeTableEntry, given a Node """
    node_table_entry = bfcp_pb2.NodeTableEntry()
    node_table_entry.node = node
    # TODO develop trust_score logic, currently trust_score is set to 1.0
    node_table_entry.trust_score = 1.0
    return node_table_entry

def from_node_table_entry(entry: bfcp_pb2.NodeTableEntry) -> bfcp_pb2.Node:
    """ Returns NodeTableEntry's Node property """
    return entry.node

def new_trust_score(node: bfcp_pb2.Node, src_trust_score: float, new_trust_score: float) -> float:
    """
    Compute node's trust score from scratch.
    :param src_trust_score: the trust score of a node S.
    :param new_trust_score: S's trust on this node.
    :return the new trust score.
    """
    node.avg_n = 1.0
    node.avg_sum = 0.0
    node.trust_score = src_trust_score*new_trust_score
    return node.trust_score

def update_trust_score(node: bfcp_pb2.Node, src_trust_score: float, new_trust_score: float) -> float:
    """
    Update node's trust score.
    :param src_trust_score: the trust score of a node S.
    :param new_trust_score: S's trust on this node.
    :return the new trust score.
    """
    # TODO whatever algo
    node.avg_n += src_trust_score
    node.avg_sum += src_trust_score*new_trust_score
    node.trust_score = node.avg_sum/node.avg_n
    return node.trust_score

class TrustTableManager:
    def __init__(self, bfc_node: 'BFCNode'):
        self._nodes: Dict[RsaKey, Node] = RandomDict()
        self._task_queue = Queue()
        self._traffic_manager: TrafficManager = bfc_node.traffic_manager
        self._thread = Thread(target=self._loop())

        self._last_update_timestamp = 0
        #: the set of nodes that we are waiting for update from
        self._wait_update_nodes: Set[RsaKey] = set()

    def update_node_table(self):
        self._last_update_timestamp = time()
        # TODO config this
        for i in range(10):
            node = self.get_random_node()
            self._traffic_manager.send(bfcp_pb2.DiscoveryRequest(), node.pub_key)
            self._wait_update_nodes.add(node.pub_key)

    def send_node_table(self, recipient: RsaKey):
        # TODO lock and dirty state
        node_table_msg = bfcp_pb2.NodeTable()
        for key, node in self._nodes.items():
            node_table_msg.entries.append(node.to_node_table_entry(node))
        self._traffic_manager.send(node_table_msg, recipient)

    def merge_node_table(self, src: RsaKey, table: bfcp_pb2.NodeTable):
        if src not in self._wait_update_nodes:
            # probably an error/malicious
            return
        self._wait_update_nodes.remove(src)
        for entry in table.entries:
            node = Node.from_node_table_entry(entry)
            if node.pub_key in self._nodes:
                self._nodes[node.pub_key].update_trust_score(self._nodes[src].trust_score, node.trust_score)
            else:
                self._nodes[node.pub_key] = node
                self._nodes[node.pub_key].new_trust_score(self._nodes[src].trust_score, node.trust_score)

    def get_node_by_pubkey(self, pub_key: RsaKey) -> Optional[Node]:
        """
        Returns a Node with the pub key, else return None
        """
        return self._nodes.get(pub_key, None)

    def get_node_with_requirement(self, en_requirement: bfcp_pb2.EndNodeRequirement) -> RsaKey:
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

    def add_task(self, task: TrustTableManagerTask):
        self._task_queue.put(task)

    def run(self) -> None:
        """
        Spin up a new thread for this manager.
        """
        self._thread.start()

    def _loop(self):
        while True:  # TODO maybe have an exit signal for faster ctrl-c
            task: TrustTableManagerTask = self._task_queue.get(True, 10)  # TODO config timeout
            task.run(self)
            if time() - self._last_update_timestamp >= 10:  # TODO config
                self.add_task(UpdateNodeTableTask())
