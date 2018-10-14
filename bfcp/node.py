# -*- encoding: utf-8 -*-
import asyncio
from typing import Tuple

from Crypto.PublicKey.RSA import RsaKey
import protos.bfcp_pb2 as bfcp_pb2

from bfcp.messages import TrafficManager
from bfcp.trust import TrustTableManager, SendNodeTableTask, MergeNodeTableTask
from bfcp.connection import ConnectionManager, Connection


class BFCNode:
    """
    A BFCNode.
    """
    def __init__(self):
        self.trust_table_manager = TrustTableManager(self)
        self.connection_manager = ConnectionManager(self)
        self.traffic_manager = TrafficManager(self)

    def new_connection(self, en_requirement: bfcp_pb2.EndNodeRequirement, addr: Tuple[str, int])->Connection:
        """
        Request a new connection through the BFC network.
        :param en_requirement: the requirement of the end node.
        :param addr: the address to connect to.
        :return: A BFC connection (that may not have been established yet!)
        """
        return self.connection_manager.new_connection(en_requirement, addr)

    async def handle_message(self, msg: bfcp_pb2.BouncyMessage, sender_key: RsaKey):
        if isinstance(msg, bfcp_pb2.ConnectionRequest):
            self.connection_manager.on_conn_request(msg, sender_key)
        elif isinstance(msg, bfcp_pb2.ConnectionResponse):
            self.connection_manager.on_conn_response(msg, sender_key)
        elif isinstance(msg, bfcp_pb2.ChannelRequest):
            self.connection_manager.on_channel_request(msg, sender_key)
        elif isinstance(msg, bfcp_pb2.ChannelResponse):
            self.connection_manager.on_channel_response(msg, sender_key)
        elif isinstance(msg, (bfcp_pb2.ToTargetServer, bfcp_pb2.ToOriginalSender)):
            self.connection_manager.on_payload_received(msg, sender_key)
        elif isinstance(msg, bfcp_pb2.DiscoveryRequest):
            self.trust_table_manager.add_task(SendNodeTableTask(sender_key))
        elif isinstance(msg, bfcp_pb2.NodeTable):
            self.trust_table_manager.add_task(MergeNodeTableTask(sender_key, msg))
        elif isinstance(msg, bfcp_pb2.CloseConnectionRequest):
            # TODO
            raise NotImplementedError()

    def run(self)->None:
        """
        Spin up ths BFC node.
        """
        async def main_loop():
            while True:
                new_messages = await self.traffic_manager.new_messages()
                for sender_key, msg in new_messages:
                    await self.handle_message(msg, sender_key)

        loop = asyncio.get_event_loop()
        asyncio.ensure_future(main_loop())
        try:
            loop.run_forever()
        finally:
            loop.close()
