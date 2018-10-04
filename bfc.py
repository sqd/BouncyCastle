# -*- coding: utf-8 -*-

from event_server import EventConsumer, EventServer


class BFCSessionListener:
    def recv_callback(self, s: bytes):
        """Callback when some data is received."""
        raise NotImplementedError()


class BFCNode(EventConsumer):
    def __init__(self, config):
        pass

    def start(self):
        pass

    def events(self):
        pass

    def handle_event(self, fileno, ev):
        pass

    def new_session(self, listener: BFCSessionListener):
        pass


class _BFCRelayer(EventConsumer):
    pass


class BFCSession(EventConsumer):
    pass

    def queue_send(self, s: bytes)->int:
        """
        Queue data to send. Returns the number of bytes sent. All data will be queued for later sending nonetheless.
        :return: Number of bytes sent.
        """
        raise NotImplementedError()
