# -*- coding: utf-8 -*-

from event_server import EventConsumer, EventServer


class BFCSessionListener:
    """
    Virtual class. Any class that wants to receive data from BFC should inherit and implement this class.
    """
    def recv_callback(self, s: bytes):
        """Callback when some data is received."""
        raise NotImplementedError()

class BFCNode(EventConsumer):
    def __init__(self, config):
        raise NotImplementedError()

    def start(self):
        raise NotImplementedError()

    def events(self):
        raise NotImplementedError()

    def handle_event(self, fileno, ev):
        raise NotImplementedError()

    def new_session(self, listener: BFCSessionListener):
        raise NotImplementedError()


class _BFCRelayer(EventConsumer):
    pass


class BFCSession(EventConsumer):
    def queue_send(self, s: bytes)->int:
        """
        Queue data to send. Returns the number of bytes sent. All data will be queued for later sending nonetheless.
        :return: Number of bytes sent.
        """
        raise NotImplementedError()


    def end(self):
        """End this session."""
        raise NotImplementedError

class _Listener(EventConsumer):
    pass
