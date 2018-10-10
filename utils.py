# -*- coding: utf-8 -*-
import io
from typing import Generic, TypeVar

T = TypeVar('T')


class Ref(Generic[T]):
    """
    Pass statis values (str, int, etc) by reference.
    """
    def __init__(self, v: T):
        self.v: T = v


class BytesFifoQueue(object):
    """
    A queue of bytes where bytes are read and written in FIFO order.
    """

    def __init__(self):
        self._buffer = io.BytesIO()
        self._read_ptr: int = 0

    def available(self) -> int:
        """
        :return: The number of bytes available for reading.
        """
        return self._buffer.tell() - self._read_ptr
    
    def _utilization(self) -> float:
        return self.available() / self._buffer.tell()

    def read(self, size: int=-1) -> bytes:
        """
        Reads size bytes from the buffer. If size is negative, the entire buffer is read.
        """
        if size < 0 or size > self.available():
            return self._read_all()
        else:
            buffer_size = self._buffer.tell()
            self._buffer.seek(self._read_ptr)
            result = self._buffer.read(size)
            self._buffer.seek(buffer_size)

            self._read_ptr += size
            if self._utilization() < 0.5:
                # Transfer data to a new, smaller buffer
                available = self.available()
                self._buffer.seek(self._read_ptr)
                self._buffer = io.BytesIO(self._buffer.read(-1))
                self._buffer.seek(available)

                self._read_ptr = 0
            return result

    def _read_all(self) -> bytes:
        self._buffer.seek(self._read_ptr)
        result = self._buffer.read(-1)
        self._buffer = io.BytesIO()
        self._read_ptr = 0
        return result

    def write(self, data: bytes) -> None:
        """
        Appends data to the buffer.
        """
        self._buffer.write(data)
