import threading
from typing import Callable, List

import utils


class Connection:
    """
    A single connection from the original sender to the target server. This should be held by the
    original sender to keep track of the connection to the target server.

    It is required to call initiate_connection() after creating the Connection object. Only then
    will the connection be formed.
    """
    def __init__(self):
        self._on_new_data: List[Callable[[bytes], None]] = []
        self._on_closed: List[Callable[[Exception], None]] = []

    async def initiate_connection(self):
        """
        This function can only be called once. This will initiate the connection and return once the
        connection is stable and ready to transfer information.
        """
        raise NotImplementedError()

    def send(self, data: bytes):
        """
        Sends the specified data to the target server. This is a non-blocking call.
        """
        raise NotImplementedError()

    def register_on_new_data(self, callback: Callable[[bytes], None]) -> None:
        """
        Registers a callback for whenever new data is available from the target server. The callback
        will be called with the bytes retrieved from the connection.
        """
        self._on_new_data.append(callback)

    def unregister_on_new_data(self, callback: Callable[[bytes], None]) -> None:
        """
        Unregisters the specified callback function. Note, this needs to be the same object as was
        passed into register_on_new_data().

        Example:

            callback = lambda data: print(data.decode())
            connection.register_on_new_data(callback)

            # Do something ...

            connection.unregister_on_new_data(callback)
        """
        self._on_new_data.remove(callback)

    def register_on_closed(self, callback: Callable[[Exception], None]) -> None:
        """
        Registers a callback for whenever the target server closes the connection.
        :param callback: The callback should accept a single parameter. The parameter will be None
        if the connection was closed correctly. If the connection was closed due to an error, an
        appropriate exception will be passed.
        """
        self._on_closed.append(callback)

    def unregister_on_closed(self, callback: Callable[[Exception], None]) -> None:
        """
        Unregisters the specified callback function. Note, this needs to be the same object as was
        passed into register_on_closed().

        Example:

            callback = lambda err: print(str(err))
            connection.register_on_closed(callback)

            # Do something ...

            connection.unregister_on_closed(callback)
        """
        self._on_closed.remove(callback)


class SocketConnection:
    """
    SocketConnection wraps the Connection class to provide the user with an interface similar to the
    Python's built in socket object.
    """

    def __init__(self, connection: Connection):
        """
        :param connection: The connection to wrap
        """
        self._buffer = utils.BytesFifoQueue()
        self._connection = connection
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._closed = False
        self._close_reason = None

        self._connection.register_on_closed(lambda err: self._handle_closed(err))
        self._connection.register_on_new_data(lambda data: self._handle_new_data(data))

    def send(self, data: bytes) -> int:
        """
        Sends the specified data to the target server. This is a non-blocking call.

        :return: len(data). This is done to ensure compatibility with Python's built-in socket class
        """
        self.sendall(data)
        return len(data)

    def sendall(self, data: bytes) -> None:
        """
        Sends the specified data to the target server. This is a non-blocking call.
        """
        self._connection.send(data)

    def recv(self, max_bytes: int) -> bytes:
        """
        Takes at most max_bytes from the buffer of the socket and returns them. If the buffer is
        empty, this will block until some data is available. Otherwise, the function will return
        immediately.

        If the underlying Connection is closed, and there are no more bytes in the buffer, this will
        return an empty bytestring (b''). Moreover, if the connection was closed forcibly, a
        ConnectionError will be raised.
        """
        with self._lock:
            if self._buffer.available() == 0:
                if self._closed:
                    if self._close_reason is None:
                        return b''
                    else:
                        raise ConnectionError('Connection was forcibly closed', self._close_reason)
                self._condition.wait()
            return self._buffer.read(max_bytes)

    def recv_all(self, byte_count: int) -> bytes:
        """
        Takes byte_count bytes from the buffer of the socket. If the buffer does not have enough
        bytes, this function will block until it does.
        """
        with self._lock:
            while self._buffer.available() < byte_count:
                if self._closed:
                    raise ConnectionError('The connection was closed before enough data was '
                                          'transferred.', self._close_reason)
                self._condition.wait()
            return self._buffer.read(byte_count)

    def bytes_available(self) -> int:
        """
        :return: The number of bytes in the buffer
        """
        with self._lock:
            return self._buffer.available()

    def is_closed(self) -> bool:
        """
        :return: Indicates whether the socket is closed
        """
        return self._closed

    def get_close_reason(self) -> Exception:
        """
        :return: If the connection is closed, this will be the Exception given as the reason for
        closing the connection. If the connection was closed correctly this will be set to None.
        :raises ValueError: Raised if the connection is still open.
        """
        if not self._closed:
            raise ValueError('The connection is still open')
        return self._close_reason

    def _handle_closed(self, err: Exception) -> None:
        with self._lock:
            self._closed = True
            self._close_reason = err
            self._condition.notify_all()

    def _handle_new_data(self, data: bytes) -> None:
        with self._lock:
            self._buffer.write(data)
            self._condition.notify_all()
