# -*- coding: utf-8 -*-
from bfc import BFCNode
from event_server import EventServer
from http_proxy import HTTPProxyServer
from config import HTTPProxyServerConfig


def main():
    http_proxy_default_config = HTTPProxyServerConfig([("127.0.0.1", 8080)])

    bfc = None # BFCNode(config)
    ev_server = EventServer()
    http_proxy = HTTPProxyServer(http_proxy_default_config, bfc, ev_server)
    http_proxy.start()

    ev_server.start()


if __name__ == "__main__":
    main()
