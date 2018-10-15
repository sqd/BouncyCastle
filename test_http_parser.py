# -*- coding: utf-8 -*-

import pytest
from unittest.mock import Mock
import random
import string

import http_parser
from http_parser import HTTPHeaderParser, HTTPRequestHeader, HTTPParseStatus, HTTPBodyParser
from utils import Ref


HTTP_10_GET = lambda: b"GET http://example.com/path?key=value HTTP/1.0\r\nHeader: header-val\r\n\r\n"


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


@pytest.mark.parametrize("s", list(random_strings()))
def test_content_length_body_happy_case(s):
    mock_header = Mock(headers={b'Content-Length': str(len(s).encode('ascii'))})
    parser = HTTPBodyParser(mock_header)
    assert parser._encoding == http_parser.HTTPBodyEncoding.CONTENT_LENGTH
    assert parser._content_length == len(s)
    assert parser.feed(s) == len(s)


@pytest.mark.parametrize("s", list(random_strings()))
def test_content_length_body_happy_case(s):
    mock_header = Mock(headers={b'Content-Length': str(len(s).encode('ascii'))})
    parser = HTTPBodyParser(mock_header)
    assert parser._encoding == http_parser.HTTPBodyEncoding.CONTENT_LENGTH
    assert parser._content_length == len(s)
    assert parser.feed(s) == len(s)


@pytest.mark.parametrize("s", list(partial_inputs(HTTP_10_GET())))
def test_content_length_body_partial_input(s):
    mock_header = Mock(headers={b'Content-Length': str(len(s).encode('ascii'))})
    parser = HTTPBodyParser(mock_header)
    assert parser._encoding == http_parser.HTTPBodyEncoding.CONTENT_LENGTH
    assert parser._content_length == len(s)
    assert parser.feed(s) == http_parser.HTTPParseStatus.PARTIAL
