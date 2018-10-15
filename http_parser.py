# -*- coding: utf-8 -*-

from enum import Enum, auto
from typing import Dict, Tuple, Union
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
        self.method: bytes = None
        self.location: HTTPLocation = None
        self.version: bytes = None
        """This version string contains the whole HTTP/x.y part."""
        self.headers: Dict[bytes, Tuple[int, bytes]] = []
        """Key: (Order, Value)"""
        self.consumed: bytes = b""
        self.uri: bytes = b""

    def unproxify(self):
        """
        Transform this proxy HTTPRequestHeader to none-proxy HTTPRequestHeader.
        """
        order_host = self.headers[b"Host"][0] if b"Host" in self.headers else len(self.headers)
        self.headers[b"Host"] = (order_host, self.location.netloc.encode("ascii"))
        self.uri = urlparse.urlunsplit(["", "", self.location.path, self.location.query, self.location.fragment]).encode("ascii")
        # TODO: maybe handle Connection

    def reconstruct(self)->bytes:
        """
        Reconstructing the header in string.
        """
        result = b""
        result += b"%s %s %s\r\n" % (self.method, self.uri, self.version)

        # Reorder the headers
        headers = [None] * len(self.headers)
        for (k, (i, v)) in self.headers.items():
            headers[i] = (k, v)
        for (k, v) in headers:
            result += b"%s: %s\r\n" % (k, v)
        result += b"\r\n"
        return result


class HTTPParseStatus(Enum):
    PARTIAL = auto()
    """Incomplete, waiting for more."""
    ERROR = auto()
    SUCCEED = auto()


class HTTPBodyEncoding(Enum):
    NONE = auto()
    CONTENT_LENGTH = auto()
    CHUNKED = auto()


class HTTPBodyParser:
    def __init__(self, header: HTTPRequestHeader):
        try:
            if b"Content-Length" in header.headers:
                self._encoding = HTTPBodyEncoding.CONTENT_LENGTH
                self._content_length = int(header.headers[b"Content-Length"][1])
            elif header.version == b"HTTP/1.1" and header.headers.get(b"Content-Encoding") == b"chunked":
                self._encoding = HTTPBodyEncoding.CHUNKED
                self._len_buffer = b""
                # When chunk length is 0, this means we have just finished reading a chunk/fresh start.
                # When chunk length is -1, this means we have started reading length, and are still waiting for length.
                # When chunk length is -2, this means we have gotten \r for ending length, and are waiting for \n.
                # When chunk length is -3, this means we have gotten 0-len for ending body, and are waiting for \r.
                # When chunk length is -4, this means we have gotten 0-len and \r for ending body, and are waiting for \n.
                # Otherwise, it's the remaining length of this chunk.
                self._chunk_length = 0
            else:
                self._encoding: HTTPBodyEncoding = HTTPBodyEncoding.NONE
        except:
            self._encoding: HTTPBodyEncoding = HTTPBodyEncoding.NONE

    def feed(self, s: bytes)->Union[HTTPParseStatus, int]:
        """
        Feed a byte string to the parser.
        :return HTTPParseStatus.PARTIAL if more are expected; HTTPParseStatus.ERROR
        if an error occured; an integer n if only n characters are consumed, and the rest belongs to the next
        request.
        :raises RuntimeError when called after a result has been returned.
        """
        if self._encoding == HTTPBodyEncoding.NONE:
            return HTTPParseStatus.PARTIAL
        elif self._encoding == HTTPBodyEncoding.CONTENT_LENGTH:
            if len(s) >= self._content_length:
                return self._content_length
            else:
                self._content_length -= len(s)
                return HTTPParseStatus.PARTIAL
        elif self._encoding == HTTPBodyEncoding.CHUNKED:
            for i in range(len(s)):
                c = s[i:i+1]
                # Fresh start/just finished a chunk
                print(self._chunk_length, c)
                if self._chunk_length == 0:
                    # Ending body
                    # Treat as length
                    self._len_buffer += c
                    self._chunk_length = -1
                # In length
                elif self._chunk_length == -1:
                    # Ending length
                    if c == b'\r':
                        self._chunk_length = -2
                    else:
                        self._len_buffer += c
                # Waiting for \n for ending length
                elif self._chunk_length == -2:
                    if c != b'\n':
                        return HTTPParseStatus.ERROR
                    if self._len_buffer == b'0':
                        self._chunk_length = -3
                    else:
                        try:
                            self._chunk_length = int(self._len_buffer, 16) + 2  # 2 more \r\n
                            self._len_buffer = b''
                        except ValueError:
                            return HTTPParseStatus.ERROR
                # Waiting for \n for ending body
                elif self._chunk_length == -3:
                    if c != b'\r':
                        return HTTPParseStatus.ERROR
                    self._chunk_length = -4
                # Waiting for \n for ending body
                elif self._chunk_length == -4:
                    if c != b'\n':
                        return HTTPParseStatus.ERROR
                    else:
                        return i + 1
                # Waiting for body
                else:
                    self._chunk_length -= 1

            return HTTPParseStatus.PARTIAL



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
        2. change headers to dict
        """
        try:
            self._parse_result.location = urlparse.urlparse(self._parse_result.uri.decode("ascii"))
        except (ValueError, UnicodeDecodeError) as e:
            self._parse_result = HTTPParseStatus.ERROR
            return
        header_dict = {}
        i = 0
        for (k, v) in self._parse_result.headers:
            header_dict[k] = (i, v)
            i += 1
        self._parse_result.headers = header_dict

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
