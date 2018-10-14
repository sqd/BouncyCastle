# -*- encoding: utf-8 -*-
import asyncio
from typing import Tuple

import protos.bfcp_pb2 as bfcp_pb2

from bfcp.messages import TrafficManager
from bfcp.trust import TrustTableManager
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

    def run(self)->None:
        """
        Spin up ths BFC node.
        """
        async def main_loop():
            while True:
                new_messages = await self.traffic_manager.new_messages()
                for msg, sender_key in new_messages:
                    if isinstance(msg, bfcp_pb2.ConnectionResponse):
                        self.connection_manager.on_conn_response(msg, sender_key)
                    elif isinstance(msg, bfcp_pb2.ChannelResponse):
                        self.connection_manager.on_channel_response(msg, sender_key)
                    elif isinstance(msg, bfcp_pb2.ToOriginalSender):
                        self.connection_manager.on_payload_received(msg)
                    # we're helping out other people below this line
                    elif isinstance(msg, bfcp_pb2.ToTargetServer):
                        pass
                    elif isinstance(msg, bfcp_pb2.ToTargetServer):
                        pass

        loop = asyncio.get_event_loop()
        asyncio.ensure_future(main_loop())
        try:
            loop.run_forever()
        finally:
            loop.close()
