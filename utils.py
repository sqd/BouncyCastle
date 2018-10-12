# -*- coding: utf-8 -*-
import hashlib
import io
import struct
from typing import Generic, TypeVar

from Crypto import Random
from Crypto.Cipher import AES

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


_rand_gen = Random.new()


def generate_aes_key(bits: int) -> bytes:
    if bits not in [128, 192, 256]:
        raise ValueError('Only keys with 128, 192 or 256 bits are supported')
    return _rand_gen.read(bits//8)


def aes_encrypt(message: bytes, key: bytes) -> bytes:
    checksum = hashlib.md5(message).digest()
    original_message = message
    message = checksum + struct.pack('>I', len(original_message)) + original_message

    # add empty spaces to round up to AES.block_size
    empty_bytes = AES.block_size - (len(message) % AES.block_size)
    if empty_bytes == AES.block_size:
        empty_bytes = 0
    for i in range(empty_bytes):
        message += b'\0'

    key = key[0:32]  # 256-bit key
    cbc_iv = Random.new().read(AES.block_size)

    encryptor = AES.new(key, AES.MODE_CBC, cbc_iv)
    cyphertext = encryptor.encrypt(message)

    output = cbc_iv + cyphertext
    return output


def aes_decrypt(to_decrypt: bytes, key: bytes) -> bytes:
    cbc_iv = to_decrypt[:AES.block_size]
    cyphertext = to_decrypt[AES.block_size:]

    decryptor = AES.new(key, AES.MODE_CBC, cbc_iv)
    message = decryptor.decrypt(cyphertext)
    expected_checksum = message[:16]
    message_length = struct.unpack(">I", message[16:20])[0]
    original_message = message[20:20+message_length]

    checksum = hashlib.md5(original_message).digest()
    if expected_checksum != checksum:
        # Incorrect key
        raise ValueError('The message was encrypted with a different key - the checksum failed')
    else:
        return original_message
