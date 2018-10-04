# -*- coding: utf-8 -*-

from typing import Iterable, Tuple, Dict


class EventConsumer:
    def handle_event(self, fileno: int, ev: int):
        """
        Handle event(s).
        :param fileno: the file descriptor on which event(s) occured.
        :param ev: events.
        """
        raise NotImplementedError()

    def events(self)->Iterable[Tuple[int, int]]:
        """
        :returns: an iterable of `(fileno, event)`. Where `fileno` is the file descriptor, and event is the epoll
        events to monitor for on fileno.
        """
        raise NotImplementedError()

    def start(self):
        """
        Start this consumer.
        """
        raise NotImplementedError()


class EventServer:
    """
    An abstract event server.
    """
    def __init__(self):
        self._event_consumers: Dict[int, EventConsumer] = {}
        """Consumers that subscribe for epoll events. Indexed by their file descriptors."""
        self._epoll = None

    def start(self):
        """
        Start the server.
        """
        while True:
            events = self._epoll.poll()
            for fileno, event in events:
                try:
                    self._event_consumers[fileno].handle_event(fileno, event)
                except Exception as e:
                    if __debug__:
                        raise e
                    pass  # TODO: logging

    def register(self, event_consumer):
        for fileno, events in event_consumer.events():
            self._event_consumers[fileno] = event_consumer
            self._epoll.register(fileno, events)

    def unregister(self, event_consumer):
        raise NotImplementedError()
