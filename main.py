# -*- coding: utf-8 -*-
import threading
from threading import Thread

from Crypto.PublicKey import RSA

from bfcp.node import BFCNode
from protos.bfcp_pb2 import Node, NodeTable

from event_server import EventServer
from http_proxy import HTTPProxyServer
from config import *
import asyncio


from logger import getLogger
_log = getLogger(__name__)


def main():
    http_proxy_default_config = HTTPProxyServerConfig([("127.0.0.1", 8080)])

    asyncio.set_event_loop(asyncio.new_event_loop())
    node = ProtoIO.read_from_file('node.txt', Node())
    node_table = ProtoIO.read_from_file('node_table.txt', NodeTable())
    bfc = BFCNode(node, ("0.0.0.0", node.last_port), RSA.generate(2048), node_table)

    def run_proxy():
        ev_server = EventServer()
        http_proxy = HTTPProxyServer(http_proxy_default_config, bfc, ev_server)
        _log.info("(Proxy) Epoll event looping...")
        http_proxy.start()
        ev_server.start()

    Thread(target=run_proxy).start()
    _log.info("Started BFC")
    bfc.run()


if __name__ == "__main__":
    main()
