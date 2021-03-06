# -*- coding: utf-8 -*-

import pytest
from unittest.mock import Mock
import random
import string

import http_parser
from http_parser import HTTPHeaderParser, HTTPRequestHeader, HTTPParseStatus, HTTPBodyParser
from utils import Ref


def HTTP_10_GET(): return b"GET http://example.com/path?key=value HTTP/1.0\r\nHeader: header-val\r\n\r\n"


def test_header_happy_case():
    parser = HTTPHeaderParser()
    rst = parser.feed(Ref(HTTP_10_GET()))
    assert isinstance(rst, HTTPRequestHeader)
    assert rst.method == b'GET'
    assert rst.location.scheme == 'http'
    assert rst.location.netloc == 'example.com'
    assert rst.location.path == '/path'
    assert rst.location.query == 'key=value'
    assert rst.version == b'HTTP/1.0'
    assert rst.headers == {b'Header': (0, b'header-val')}


def test_header_bad_input():
    parser = HTTPHeaderParser()
    rst = parser.feed(Ref(b"a b c d e f g"))
    assert isinstance(rst, HTTPParseStatus)
    assert rst == HTTPParseStatus.ERROR


def partial_inputs(s):
    for i in range(len(s)-1):
        yield s[:i]


@pytest.mark.parametrize("s", list(partial_inputs(HTTP_10_GET())))
def test_header_partial_input(s):
    parser = HTTPHeaderParser()
    rst = parser.feed(Ref(s))
    assert isinstance(rst, HTTPParseStatus)
    assert rst == HTTPParseStatus.PARTIAL


def test_header_cut_input():
    parser = HTTPHeaderParser()
    ref = Ref(HTTP_10_GET() + b"extra data")
    rst = parser.feed(ref)
    assert isinstance(rst, HTTPRequestHeader)
    assert ref.v == b'extra data'


def random_strings(n=5, min_len=10, max_len=50):
    for i in range(n):
        length = random.randint(min_len, max_len)
        yield ''.join(random.choice(string.printable) for _ in range(length))


def random_bytes(*args):
    for s in random_strings(*args):
        yield s.encode('ascii')


@pytest.mark.parametrize("s", list(random_bytes()))
def test_content_length_body_happy_case(s):
    mock_header = Mock(headers={b'Content-Length': (0, str(len(s)).encode('ascii'))})
    parser = HTTPBodyParser(mock_header)
    assert parser._encoding == http_parser.HTTPBodyEncoding.CONTENT_LENGTH
    assert parser._content_length == len(s)
    assert parser.feed(s) == len(s)


@pytest.mark.parametrize("s", list(random_bytes()))
def test_content_length_body_happy_case(s):
    mock_header = Mock(headers={b'Content-Length': (0, str(len(s)).encode('ascii'))})
    parser = HTTPBodyParser(mock_header)
    assert parser._encoding == http_parser.HTTPBodyEncoding.CONTENT_LENGTH
    assert parser._content_length == len(s)
    assert parser.feed(s) == len(s)


@pytest.mark.parametrize("s", list(partial_inputs(HTTP_10_GET())))
def test_content_length_body_partial_input(s):
    mock_header = Mock(headers={b'Content-Length': (0, str(len(HTTP_10_GET())).encode('ascii'))})
    parser = HTTPBodyParser(mock_header)
    assert parser._encoding == http_parser.HTTPBodyEncoding.CONTENT_LENGTH
    assert parser.feed(s) == HTTPParseStatus.PARTIAL


def test_chunked_body_happy_case():
    mock_header = Mock(version=b'HTTP/1.1', headers={b'Content-Encoding': b'chunked'})
    parser = HTTPBodyParser(mock_header)
    assert parser._encoding == http_parser.HTTPBodyEncoding.CHUNKED

    extra = b'extra extra'
    s = b'4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n'
    rst = parser.feed(s+extra)
    assert rst == len(s)


def test_chunked_body_error_case():
    mock_header = Mock(version=b'HTTP/1.1', headers={b'Content-Encoding': b'chunked'})
    parser = HTTPBodyParser(mock_header)

    s = b'4\r\nWiki\r\n5\r\npedia\r\nE error\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n'
    rst = parser.feed(s)
    assert rst == HTTPParseStatus.ERROR


@pytest.mark.parametrize("s", list(partial_inputs(b'4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n')))
def test_chunked_body_partial_input(s):
    mock_header = Mock(version=b'HTTP/1.1', headers={b'Content-Encoding': b'chunked'})
    parser = HTTPBodyParser(mock_header)

    rst = parser.feed(s)
    assert rst == HTTPParseStatus.PARTIAL


def test_reconstruct_header():
    s = b"GET http://example.com/path?key=value HTTP/1.0\r\n2Header: header-val1\r\n1Header: header-val1\r\n\r\n"
    assert HTTPHeaderParser().feed(Ref(s)).reconstruct() == s


def test_unproxyify():
    rst = HTTPHeaderParser().feed(Ref(HTTP_10_GET()))
    rst.unproxify()
    assert rst.headers[b'Host'][1] == b'example.com'
    assert rst.uri == b'/path?key=value'
