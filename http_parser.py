# -*- coding: utf-8 -*-

from enum import Enum, auto
from typing import List, Tuple, Union
from string import ascii_letters, digits, punctuation
import urllib.parse as urlparse

from utils import Ref


# https://tools.ietf.org/html/rfc2616#page-17
_token_charset = (ascii_letters + digits + "-!#$%&'*+-.^_`|~").encode("ascii")

_uri_charset = (ascii_letters + digits + punctuation).encode("ascii")


class HTTPLocation(urlparse.ParseResult):
    """
    An HTTP location.
    """
    def __init__(self):
        super().__init__()


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
        self.uri: bytes = b""

    def unproxify(self)->"HTTPRequestHeader":
        """
        Transform this proxy HTTPRequestHeader to none-proxy HTTPRequestHeader.
        """
        raise NotImplementedError()

    def reconstruct(self)->bytes:
        """
        Reconstructing the header in string.
        """
        raise NotImplementedError()


class HTTPParseStatus(Enum):
    PARTIAL = auto()
    """Incomplete, waiting for more."""
    ERROR = auto()
    SUCCEED = auto()


class HTTPBodyEncoding(Enum):
    CONTENT_LENGTH = auto()
    CHUNKED = auto()


class HTTPBodyParser:
    def __init__(self, header: HTTPRequestHeader):
        self._buf = b""
        raise NotImplementedError()

    def feed(self, s: bytes)->Union[HTTPParseStatus, int]:
        """
        Feed a byte string to the parser.
        :return HTTPParseStatus.PARTIAL if more are expected; HTTPParseStatus.ERROR if an error occured; an integer n if only n characters are consumed, and the rest belongs to the next request.
        :raises RuntimeError when called after a result has been returned.
        """
        raise NotImplementedError()


class HTTPParseFailedError(Exception):
    """Thrown when trying to feed more value into a HTTP parser when it has failed."""
    pass


class HTTPParseReturnedAlreadyError(Exception):
    """Thrown when trying to feed more value into a HTTP parser when it has returned already."""
    pass


class HTTPHeaderParser:
    def __init__(self):
        self._buf = b""
        self._parse_result = HTTPRequestHeader()
        self._parse_status = HTTPParseStatus.PARTIAL
        self._parse_func = self._start

    def _post_process(self):
        """
        Post process self._parse_result:
        1. Parse location
        2. change headers to tuples
        """
        try:
            self._parse_result.location = urlparse.urlparse(self._parse_result.uri.decode("ascii"))
        except (ValueError, UnicodeDecodeError) as e:
            self._parse_result = HTTPParseStatus.ERROR
            return
        self._parse_result.headers = [(k, v) for [k, v] in self._parse_result.headers]

    def feed(self, ref_s: Ref[bytes])->Union[HTTPParseStatus, HTTPRequestHeader]:
        """
        Feed the reference of a byte string into the parser for parsing. After this methods complete, if there are
        unconsumed characters, they'll be stored back into s.
        :param s: Reference of a string to be fed into the parser.
        :raises HTTPParseReturnedAlreadyError when called after a result has already been returned.
        :raises HTTPParseFailedError when called after parsing has failed.
        :return: State of the parsing afterward, or the result.
        """
        if self._parse_status == HTTPParseStatus.SUCCEED:
            raise HTTPParseReturnedAlreadyError()
        elif self._parse_status == HTTPParseStatus.ERROR:
            raise HTTPParseFailedError()
        i = 0
        while i < len(ref_s.v):
            c = ref_s.v[i:i+1]
            self._parse_result.consumed += c
            result = self._parse_func(c)
            if result == HTTPParseStatus.ERROR:
                self._parse_status = result
                return result
            elif result == HTTPParseStatus.SUCCEED:
                self._parse_status = result
                self._post_process()
                ref_s.v = ref_s.v[i+1:]
                return self._parse_result
            i += 1
        # We have consumed every char, so empty the source.
        ref_s.v = b""
        return HTTPParseStatus.PARTIAL

    def _start(self, c:bytes):
        if c == b'\r':
            self._parse_func = self._prefix_r
        elif c in _token_charset:
            self._parse_func = self._method
            self._parse_result.method = c
        else:
            return HTTPParseStatus.ERROR

    def _prefix_r(self, c:bytes):
        if c == b'\n':
            self._parse_func = self._start
        else:
            return HTTPParseStatus.ERROR

    def _method(self, c:bytes):
        if c in _token_charset:
            self._parse_result.method += c
        elif c == b' ':
            self._parse_func = self._method_
        else:
            return HTTPParseStatus.ERROR

    def _method_(self, c:bytes):
        if c in _uri_charset:
            self._parse_result.uri += c
            self._parse_func = self._m_uri_charset
        else:
            return HTTPParseStatus.ERROR

    def _m_uri_charset(self, c:bytes):
        if c in _uri_charset:
            self._parse_result.uri += c
        elif c == b' ':
            self._parse_func = self._m_uri_charset_
        else:
            return HTTPParseStatus.ERROR

    def _m_uri_charset_(self, c:bytes):
        if c == b'H':
            self._parse_result.version = c
            self._parse_func = self._m_url_h
        else:
            return HTTPParseStatus.ERROR

    def _m_url_h(self, c:bytes):
        if c == b'T':
            self._parse_result.version += c
            self._parse_func = self._m_url_ht
        else:
            return HTTPParseStatus.ERROR

    def _m_url_ht(self, c:bytes):
        if c == b'T':
            self._parse_result.version += c
            self._parse_func = self._m_url_htt
        else:
            return HTTPParseStatus.ERROR

    def _m_url_htt(self, c:bytes):
        if c == b'P':
            self._parse_result.version += c
            self._parse_func = self._m_url_http
        else:
            return HTTPParseStatus.ERROR

    def _m_url_http(self, c:bytes):
        if c == b'/':
            self._parse_result.version += c
            self._parse_func = self._m_url_https
        else:
            return HTTPParseStatus.ERROR

    # s = slash
    def _m_url_https(self, c:bytes):
        if c.isdigit():
            self._parse_result.version += c
            self._parse_func = self._m_url_httpsd
        else:
            return HTTPParseStatus.ERROR

    # d1 = digit
    def _m_url_httpsd(self, c:bytes):
        if c == b'.':
            self._parse_result.version += c
            self._parse_func = self._m_url_httpsdd
        else:
            return HTTPParseStatus.ERROR

    # d1 = digit, d2 = dot
    def _m_url_httpsdd(self, c:bytes):
        if c.isdigit():
            self._parse_result.version += c
            self._parse_func = self._m_url_httpsddd
        else:
            return HTTPParseStatus.ERROR

    # d1 = digit, d2 = dot, d3 = digit
    def _m_url_httpsddd(self, c:bytes):
        if c == b'\r':
            self._parse_func = self._line_r
        else:
            return HTTPParseStatus.ERROR

    # Got an non-ending \r
    def _line_r(self, c:bytes):
        if c == b'\n':
            self._parse_func = self._line_rn
        else:
            return HTTPParseStatus.ERROR

    def _line_rn(self, c:bytes):
        if c in _token_charset:
            self._parse_func = self._header_key
            self._parse_result.headers.append([c, b""])
        elif c == b'\r':
            self._parse_func = self._end_r
        else:
            return HTTPParseStatus.ERROR

    def _header_key(self, c:bytes):
        if c == b':':
            self._parse_func = self._header_key_c
        elif c in _token_charset:
            self._parse_result.headers[-1][0] += c
        else:
            return HTTPParseStatus.ERROR

    # c = colon
    def _header_key_c(self, c:bytes):
        if c == b' ':
            pass
        elif c in b"\r\n":
            return HTTPParseStatus.ERROR
        else:
            # not completely compliant but fuck the messed up HTTP standards
            self._parse_result.headers[-1][1] += c
            self._parse_func = self._header_key_c_val

    def _header_key_c_val(self, c:bytes):
        if c == b'\r':
            self._parse_func = self._line_r
        else:
            self._parse_result.headers[-1][1] += c

    # Got an ending \r
    def _end_r(self, c:bytes):
        if c == b'\n':
            self._parse_func = self._end_rn
            return HTTPParseStatus.SUCCEED
        else:
            return HTTPParseStatus.ERROR

    def _end_rn(self, c:bytes):
        return HTTPParseStatus.ERROR
