# -*- coding: utf-8 -*-


class HTTPProxyServerConfig:
    """
    The config class for HTTPProxyServer.
    """
    def __init__(self):
        self.listen_addr = []
        """A list of tuple (address:str, port:int) specifying the locations the server should listen on."""
