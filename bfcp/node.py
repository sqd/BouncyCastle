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

    async def start(self):
        await self.traffic_manager.start()

    async def new_connection(self, en_requirement: bfcp_pb2.EndNodeRequirement, addr: Tuple[str, int])->OriginalSenderConnection:
        """
        Request a new connection through the BFC network.
        :param en_requirement: the requirement of the end node.
        :param addr: the address to connect to.
        :return: A BFC connection (that may not have been established yet!)
        """
        return await self.connection_manager.new_connection(en_requirement, addr)

    async def handle_message(self, msg: bfcp_pb2.BouncyMessage, sender_key: RsaKey):
        if msg.HasField('connection_request'):
            await self.connection_manager.on_conn_request(msg.connection_request, sender_key)
        elif msg.HasField('connection_response'):
            await self.connection_manager.on_conn_response(msg.connection_response, sender_key)
        elif msg.HasField('channel_request'):
            await self.connection_manager.on_channel_request(msg.channel_request, sender_key)
        elif msg.HasField('channel_response'):
            await self.connection_manager.on_channel_response(msg.channel_response, sender_key)
        elif msg.HasField('to_original_sender'):
            await self.connection_manager.on_payload_received(msg.to_original_sender, sender_key)
        elif msg.HasField('to_target_server'):
            await self.connection_manager.on_payload_received(msg.to_target_server, sender_key)
        elif msg.HasField('discovery_request'):
            await self.trust_table_manager.run_task(SendNodeTableTask(sender_key))
        elif msg.HasField('node_table'):
            await self.trust_table_manager.run_task(MergeNodeTableTask(sender_key, msg.node_table))

    async def main_loop(self):
        print('bfc start')
        while True:
            new_messages = await self.traffic_manager.new_messages()
            for sender_key, msg in new_messages:
                await self.handle_message(msg, sender_key)

    def meets_requirements(self, end_node_requirement: bfcp_pb2.EndNodeRequirement) -> bool:
        if self.host is None:
            return False
        return matches_requirements(self._self_node, end_node_requirement)
