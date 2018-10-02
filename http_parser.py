# -*- coding: utf-8 -*-

from enum import Enum
from typing import List, Tuple

from utils import Ref


class HTTPParserNoResultError(Exception):
    """Thrown when trying to get result from a parser, when parsing is not yet done."""
    pass


class HTTPParseState(Enum):
    PARTIAL = 1
    """Incomplete, waiting for more."""
    ERROR = 2
    SUCCESS = 3


class HTTPParseResult:
    def __init__(self):
        self.method: str = None
        self.url: str = None
        self.version: str = None
        """This version string contains the whole HTTP/x.y part."""
        self.headers: List[Tuple[str, str]] = []


class HTTPParser:
    def __init__(self):
        self._parse_result = None

    def feed(self, s: Ref)->HTTPParseState:
        """
        Feed the reference of a string into the parser for parsing. After this methods complete, if there are
        unconsumed characters, they'll be stored back into s.
        :param s: Reference of a string to be fed into the parser.
        :return: State of the parsing afterward.
        """
        pass

    def get_result(self)->HTTPParseResult:
        """
        Get the parsing result.
        :raise HTTPParserNoResultError
        :return: Parsing result.
        """
        if not self._parse_result:
            raise HTTPParserNoResultError();
        return self._parse_result
