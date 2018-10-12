# -*- encoding: utf-8 -*-
from typing import Tuple

import protos.bfcp_pb2 as bfcp_pb2

import bfcp.connection
from bfcp.messages import TrafficManager
from bfcp.trust import TrustTableManager
from bfcp.channel import ChannelManager, Channel


class BFCNode:
    """
    A central manager of a BFCNode.
    """
    def __init__(self):
        self._trust_table_manager = TrustTableManager()
        self._channel_manager = ChannelManager()
        self._traffic_manager = TrafficManager(_trust_table_manager, self._on_new_message)

    def _on_new_message(self, msg: BouncyMessage, key: RsaKey):
        pass

    def new_connection(self, en_requirement: bfcp_pb2.EndNodeRequirement, ts_address: Tuple[str, int]):
        conn = connection.Connection(self._traffic_manager)
        conn.initiate_connection(en_requirement, ts_address)
        return conn

    def establish_new_channel(self):
        en = self._trust_table_manager.get_random_node()
        self._channel_manager.

        bfcp_pb2.ChannelRequest()
        bfcp_pb2.BouncyMessage
