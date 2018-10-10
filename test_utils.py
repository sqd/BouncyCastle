import unittest

import utils


class TestBytesFifoQueue(unittest.TestCase):
    def test_bytes_queue(self):
        q = utils.BytesFifoQueue()
        q.write(b'1234567890')
        self.assertEqual(q.available(), 10)

        read = q.read(3)
        self.assertEqual(read, b'123')
        self.assertEqual(q.available(), 7)

        read = q.read(3)
        self.assertEqual(read, b'456')
        self.assertEqual(q.available(), 4)

        read = q.read(3)
        self.assertEqual(read, b'789')
        self.assertEqual(q.available(), 1)

        read = q.read(5)
        self.assertEqual(read, b'0')
        self.assertEqual(q.available(), 0)

        q.write(b'0987654321')
        self.assertEqual(q.available(), 10)

        read = q.read(6)
        self.assertEqual(read, b'098765')
        self.assertEqual(q.available(), 4)

        read = q.read(-1)
        self.assertEqual(read, b'4321')
        self.assertEqual(q.available(), 0)


if __name__ == '__main__':
    unittest.main()
