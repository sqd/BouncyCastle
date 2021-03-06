"""
TrustTableManager
"""
from typing import Tuple, Dict, Optional, List, Set
from queue import Queue, Empty
from threading import Thread
from time import time

from Crypto.PublicKey.RSA import RsaKey
from randomdict import RandomDict

import protos.bfcp_pb2 as bfcp_pb2
from bfcp.protocol import proto_to_pubkey, pubkey_to_deterministic_string, get_node_pub_key, \
    matches_requirements

from config import *


class TrustTableManagerTask:
    async def run(self, tm: 'TrustTableManager') -> None:
        raise NotImplementedError()


class SendNodeTableTask(TrustTableManagerTask):
    def __init__(self, recipient: RsaKey):
        self._recipient = recipient

    async def run(self, tm: 'TrustTableManager') -> None:
        await tm.send_node_table(self._recipient)


class MergeNodeTableTask(TrustTableManagerTask):
    def __init__(self, source: RsaKey, table: bfcp_pb2.NodeTable):
        self._source = source
        self._table = table

    async def run(self, tm: 'TrustTableManager') -> None:
        tm.merge_node_table(self._source, self._table)


class UpdateNodeTableTask(TrustTableManagerTask):
    async def run(self, tm: 'TrustTableManager') -> None:
        await tm.update_node_table()


"""
Status functions for bfcp_pb2.NodeTableEntry struct
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


def new_trust_score(node: bfcp_pb2.NodeTableEntry, src_trust_score: float, new_trust_score: float) -> float:
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


def update_trust_score(node: bfcp_pb2.NodeTableEntry, src_trust_score: float, new_trust_score: float) -> float:
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
    def __init__(self, bfc: 'BFCNode', initial_node_table: bfcp_pb2.NodeTable):
        self._nodes = self._parse_initial_node_table(initial_node_table)
        self._task_queue = Queue()
        self._bfc = bfc

        self._last_update_timestamp = 0
        #: the set of nodes (listed by Rsa key) that we are waiting for update from
        self._wait_update_nodes: Set[bytes] = set()

    async def update_node_table(self):
        self._last_update_timestamp = time()
        # TODO config this
        for i in range(10):
            node = self.get_random_node()
            await self._bfc.traffic_manager.send(bfcp_pb2.DiscoveryRequest(), get_node_pub_key(node))
            self._wait_update_nodes.add(pubkey_to_deterministic_string(get_node_pub_key(node)))

    async def send_node_table(self, recipient: RsaKey):
        # TODO lock and dirty state
        node_table_msg = bfcp_pb2.NodeTable()
        for key, node in self._nodes.items():
            node_table_msg.entries.append(node.to_node_table_entry(node))
        self._bfc.traffic_manager.send(node_table_msg, recipient)

    def merge_node_table(self, src: RsaKey, table: bfcp_pb2.NodeTable):
        src_key = pubkey_to_deterministic_string(src)
        if src_key not in self._wait_update_nodes:
            # probably an error/malicious
            return
        self._wait_update_nodes.remove(src)
        for entry in table.entries:
            node_key = pubkey_to_deterministic_string(get_node_pub_key(entry))
            if node_key in self._nodes:
                update_trust_score(self._nodes[node_key], self._nodes[src_key].trust_score, entry.trust_score)
            else:
                self._nodes[node_key] = entry
                self._nodes[node_key].new_trust_score(self._nodes[src].trust_score, entry.trust_score)

    def get_node_by_pubkey(self, pub_key: RsaKey) -> Optional[bfcp_pb2.NodeTableEntry]:
        """
        Returns a NodeTableEntry with the pub key, else return None
        """
        return self._nodes.get(pubkey_to_deterministic_string(pub_key), None)

    def get_node_with_requirement(self, en_requirement: bfcp_pb2.EndNodeRequirement) -> Optional[bfcp_pb2.NodeTableEntry]:
        """Returns a node public key, given EndNodeRequirement like location must be in China"""
        # TODO: this is really slow (O(n)), we should use tries and hashmaps for faster lookup
        for key, node in self._nodes.items():
            if matches_requirements(node.node, en_requirement):
                return node
        return None

    def get_random_node(self) -> bfcp_pb2.NodeTableEntry:
        """
        Get a random node for sending stuffs.
        :raises ValueError if there is no node.
        :return: a random node.
        """
        own_pub_key_index = pubkey_to_deterministic_string(self._bfc.rsa_key)
        if own_pub_key_index in self._nodes:
            del self._nodes[own_pub_key_index]

        if len(self._nodes) == 0:
            raise ValueError("No node in the trust table.")
        return self._nodes.random_value()

    async def run_task(self, task: TrustTableManagerTask):
        await task.run(self)

    @staticmethod
    def _parse_initial_node_table(initial_node_table: bfcp_pb2.NodeTable)\
            -> Dict[bytes, bfcp_pb2.NodeTableEntry]:
        result = RandomDict()
        for entry in initial_node_table.entries:
            pub_key = proto_to_pubkey(entry.node.public_key)
            result[pubkey_to_deterministic_string(pub_key)] = entry
        return result
