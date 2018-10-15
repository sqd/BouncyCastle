# -*- encoding: utf-8 -*-
import asyncio
from typing import Tuple, Optional

from Crypto.PublicKey.RSA import RsaKey
import protos.bfcp_pb2 as bfcp_pb2

from bfcp.messages import TrafficManager
from bfcp.protocol import matches_requirements
from bfcp.trust import TrustTableManager, SendNodeTableTask, MergeNodeTableTask
from bfcp.connection import ConnectionManager, OriginalSenderConnection

from config import *

class BFCNode:
    """
    A BFCNode.
    """
    def __init__(self, self_node: bfcp_pb2.Node, host: Optional[Tuple[str, int]], rsa_key: RsaKey, node_table: bfcp_pb2.NodeTable):
        self._self_node = self_node
        self._async_loop = asyncio.get_event_loop()

        self.traffic_manager = TrafficManager(self, rsa_key, self._async_loop, host)
        self.trust_table_manager = TrustTableManager(self, node_table)
        self.connection_manager = ConnectionManager(self)

        self.host = host
        self.rsa_key = rsa_key

    def new_connection(self, en_requirement: bfcp_pb2.EndNodeRequirement, addr: Tuple[str, int])->OriginalSenderConnection:
        """
        Request a new connection through the BFC network.
        :param en_requirement: the requirement of the end node.
        :param addr: the address to connect to.
        :return: A BFC connection (that may not have been established yet!)
        """
        return self.connection_manager.new_connection(en_requirement, addr)

    async def handle_message(self, msg: bfcp_pb2.BouncyMessage, sender_key: RsaKey):
        if isinstance(msg, bfcp_pb2.ConnectionRequest):
            await self.connection_manager.on_conn_request(msg, sender_key)
        elif isinstance(msg, bfcp_pb2.ConnectionResponse):
            await self.connection_manager.on_conn_response(msg, sender_key)
        elif isinstance(msg, bfcp_pb2.ChannelRequest):
            await self.connection_manager.on_channel_request(msg, sender_key)
        elif isinstance(msg, bfcp_pb2.ChannelResponse):
            await self.connection_manager.on_channel_response(msg, sender_key)
        elif isinstance(msg, (bfcp_pb2.ToTargetServer, bfcp_pb2.ToOriginalSender)):
            await self.connection_manager.on_payload_received(msg, sender_key)
        elif isinstance(msg, bfcp_pb2.DiscoveryRequest):
            await self.trust_table_manager.run_task(SendNodeTableTask(sender_key))
        elif isinstance(msg, bfcp_pb2.NodeTable):
            await self.trust_table_manager.run_task(MergeNodeTableTask(sender_key, msg))

    async def main_loop(self):
        while True:
            new_messages = await self.traffic_manager.new_messages()
            for sender_key, msg in new_messages:
                await self.handle_message(msg, sender_key)

    def run(self)->None:
        """
        Spin up ths BFC node.
        """
        asyncio.ensure_future(self.main_loop())
        try:
            self._async_loop.run_forever()
        finally:
            self._async_loop.close()

    def meets_requirements(self, end_node_requirement: bfcp_pb2.EndNodeRequirement) -> bool:
        if self.host is None:
            return False
        return matches_requirements(self._self_node, end_node_requirement)
