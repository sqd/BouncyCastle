# -*- coding: utf-8 -*-

from threading import Thread

from Crypto.PublicKey import RSA

from bfcp.node import BFCNode
from protos.bfcp_pb2 import Node, NodeTable

from event_server import EventServer
from http_proxy import HTTPProxyServer
from config import *


from logger import getLogger
_log = getLogger(__name__)

def main():
    http_proxy_default_config = HTTPProxyServerConfig([("127.0.0.1", 8080)])

    bfc = None

    def run_bfc():
        nonlocal bfc
        # TODO: `node.txt` and `node_table.txt`
        node = ProtoIO.read_from_file('node.txt', Node())
        node_table = ProtoIO.read_from_file('node_table.txt', NodeTable())
        bfc = BFCNode(node, ("0.0.0.0", 9000), RSA.generate(2048), node_table)
        bfc.run()

    Thread(target=run_bfc).start()
    _log.info("Started BFC")

    ev_server = EventServer()

    http_proxy = HTTPProxyServer(http_proxy_default_config, bfc, ev_server)
    http_proxy.start()

    _log.info("(Proxy) Epoll event looping...")
    ev_server.start()


if __name__ == "__main__":
    main()
