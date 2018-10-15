# -*- coding: utf-8 -*-

from threading import Thread

from bfcp.node import BFCNode

from event_server import EventServer
from http_proxy import HTTPProxyServer
from config import HTTPProxyServerConfig


from logger import getLogger
_log = getLogger(__name__)

def main():
    http_proxy_default_config = HTTPProxyServerConfig([("127.0.0.1", 8080)])

    bfc = BFCNode(("0.0.0.0", 9000), )
    Thread(target=bfc.run).start()

    ev_server = EventServer()

    http_proxy = HTTPProxyServer(http_proxy_default_config, bfc, ev_server)
    http_proxy.start()

    _log.info("Event looping...")
    ev_server.start()


if __name__ == "__main__":
    main()
