# -*- coding: utf-8 -*-

from threading import Thread
from Crypto.PublicKey import RSA
from retrying import retry
import socket
from time import sleep
from unittest.mock import Mock

from event_server import EventServer
from http_proxy import HTTPProxyServer
from config import HTTPProxyServerConfig


HTTP_TEST_LISTEN_PORT = 45000

def test_http_proxy():
    bfc = Mock()
    conn_mock = Mock()
    bfc.configure_mock(**{'new_connection.return_value': conn_mock})
    ev_server = EventServer()

    http_proxy_default_config = HTTPProxyServerConfig([("127.0.0.1", HTTP_TEST_LISTEN_PORT)])

    http_proxy = HTTPProxyServer(http_proxy_default_config, bfc, ev_server)
    http_proxy.start()

    def test_thread():
        sock = None

        @retry(stop_max_attempt_number=3, wait_fixed=1000)
        def try_connect():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", HTTP_TEST_LISTEN_PORT))
            sock.send(b'GET http://example.com/path?key=value HTTP/1.0\r\nHeader: header-val\r\n\r\n')

        try_connect()

        @retry(stop_max_attempt_number=3, wait_fixed=1000)
        def try_assert():
            bfc.new_connection.assert_called()
            bfc.new_connection.assert_called_with(None, ('example.com', 80))
            conn_mock.send.assert_called_with(b'GET /path?key=value HTTP/1.0\r\nHeader: header-val\r\nHost: example.com\r\n\r\n')

        try_assert()
        ev_server.stop()

    Thread(target=test_thread).start()
    ev_server.start()
