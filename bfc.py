# -*- coding: utf-8 -*-

from event_server import EventConsumer, EventServer


class BFCNode(EventConsumer):
    def __init__(self, config):
        pass

    def start(self):
        pass

    def events(self):
        pass

    def handle_event(self, fileno, ev):
        pass

    def new_session(self, listener: BFCListener):
        pass


class _BFCRelayer(EventConsumer):
    pass


class BFCSession(EventConsumer):
    pass


class BFCSessionListener:
    def recv_callback(self, s: bytes):
        """Callback when some data is received."""
        raise NotImplementedError()
