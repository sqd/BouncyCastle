# -*- coding: utf-8 -*-

from enum import Enum
from typing import List, Tuple, Union

from utils import Ref


class HTTPLocation:
    """An HTTP location. Protocol and domain are guaranteed to be lower-case."""
    def __init__(self):
        self.protocol: str = None
        self.domain: str = None
        self.path: str = None
        self.url: str = None
        self.port: int = None


class HTTPRequestHeader:
    """
    Parsing result of an HTTPHeaderParser.
    """
    def __init__(self):
        self.method: str = None
        self.location: HTTPLocation = None
        self.version: str = None
        """This version string contains the whole HTTP/x.y part."""
        self.headers: List[Tuple[str, str]] = []
        self.consumed: bytes = b""

    def unproxify(self)->HTTPRequestHeader:
        """
        Transform this proxy HTTPRequestHeader to none-proxy HTTPRequestHeader.
        """
        raise NotImplementedError()

    def reconstruct(self)->bytes:
        """
        Reconstructing the header in string.
        """
        raise NotImplementedError()


class HTTPParseState(Enum):
    PARTIAL = 1
    """Incomplete, waiting for more."""
    ERROR = 2


class HTTPBodyEncoding(Enum):
    CONTENT_LENGTH = 1
    CHUNKED = 2


class HTTPBodyParser:
    def __init__(self, header: HTTPRequestHeader):
        self._buf = b""
        raise NotImplementedError()

    def feed(self, s: bytes)->Union[HTTPParseState, int]:
        """
        Feed a byte string to the parser.
        :return HTTPParseState.PARTIAL if more are expected; HTTPParseState.ERROR if an error occured; an integer n if only n characters are consumed, and the rest belongs to the next request.
        :raises RuntimeError when called after a result has been returned.
        """
        raise NotImplementedError()

class _HeaderParserState(Enum):
    # Waiting for H
    H = 1
    # Had H, waiting for T
    HT = 2
    HTT = 3
    HTTP = 4
    HTTP_space = 5
    # Had HTTP_, waiting for url; or in url already, waiting for more url
    HTTP_space_url = 6
    # Transition when get a space
    # Had a space, waiting for version; or in version already, waiting for more version
    HTTP_space_url_space_version = 7
    # Transition when get a \r
    first_line_rn = 8
    # Transition when get a \n

    # loop
    # Had an ending \r, waiting for \n
    ending_r = 9


class HTTPHeaderParser:
    def __init__(self):
        self._buf = b""
        self._parse_result = None
        self._result_ready = False

    def feed(self, s: Ref)->Union[HTTPParseState, HTTPRequestHeader]:
        """
        Feed the reference of a byte string into the parser for parsing. After this methods complete, if there are
        unconsumed characters, they'll be stored back into s.
        :param s: Reference of a string to be fed into the parser.
        :raises RuntimeError when called after has already been returned.
        :return: State of the parsing afterward, or the result.
        """
        self._buf += s.v
        while self
        one_of("HTTP ")
        raise NotImplementedError()
