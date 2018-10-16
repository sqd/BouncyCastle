# -*- coding: utf-8 -*-

import asyncio

from Crypto.PublicKey import RSA

from bfcp.node import BFCNode
import protos.bfcp_pb2 as bfcp_pb2
from protos.bfcp_pb2 import Node, NodeTable

from http_proxy import HTTPProxyServer
from config import *


from logger import getLogger
_log = getLogger(__name__)

def main():
    http_proxy_default_config = HTTPProxyServerConfig(("127.0.0.1", 8080))

    bfc = BFCNode(bfcp_pb2.EndNodeRequirement(), ("0.0.0.0", 9000), RSA.generate(2048), bfcp_pb2.NodeTable())
    http_proxy = HTTPProxyServer(http_proxy_default_config, bfc)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(http_proxy.start(), bfc.main_loop()))


if __name__ == "__main__":
    main()
