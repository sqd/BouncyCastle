# -*- coding: utf-8 -*-
from typing import List, Tuple

""" GLOBAL VARIABLES """
# Specifies how many hops can be done after remaining_hops = 0 before the request is dropped. This
# is necessary, since some requirements might not be matched by any of the nodes, and the requests
# need to be dropped eventually.
MAX_HOPS_WITHOUT_END_NODE = 5

SIGNATURE_CHALLENGE_BYTES = 128

OS_EN_KEY_SIZE = 256
SENDER_CONNECTION_KEY_BITS = 4096

CHANNELS_PER_CONNECTION = 5
MIN_CHANNEL_LENGTH = 5
MAX_CHANNEL_LENGTH = 10
MIN_CHANNELS_TO_FIRE_ESTABLISH_EVENT = MIN_CHANNEL_LENGTH * (2/3)

CHALLENGE_SIZE = 64

MAX_MESSAGE_LENGTH = 64 * 2**10  # 64 KiB
READ_CHUNK_SIZE = 4096

class HTTPProxyServerConfig:
    """
    The config class for HTTPProxyServer.
    """
    def __init__(self, listen_address: List[Tuple[str, int]]):
        self.listen_address = listen_address
        """A list of tuple (address:str, port:int) specifying the locations the server should listen on."""
