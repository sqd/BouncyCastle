import unittest

import utils


class TestUtils(unittest.TestCase):
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

    def test_aes_works_for_correct_key(self):
        k = utils.generate_aes_key(128)
        clear_text = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod ' \
                     b'tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ' \
                     b'veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea' \
                     b' commodo consequat. Duis aute irure dolor in reprehenderit in voluptate ' \
                     b'velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat' \
                     b' cupidatat non proident, sunt in culpa qui officia deserunt mollit anim ' \
                     b'id est laborum.'
        encrypted = utils.aes_encrypt(clear_text, k)
        decrypted = utils.aes_decrypt(encrypted, k)
        self.assertEqual(clear_text, decrypted)

    def test_aes_fail_for_wrong_key(self):
        k1 = utils.generate_aes_key(128)
        k2 = utils.generate_aes_key(128)

        clear_text = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod ' \
                     b'tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ' \
                     b'veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea' \
                     b' commodo consequat. Duis aute irure dolor in reprehenderit in voluptate ' \
                     b'velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat' \
                     b' cupidatat non proident, sunt in culpa qui officia deserunt mollit anim ' \
                     b'id est laborum.'
        encrypted = utils.aes_encrypt(clear_text, k1)
        self.assertRaises(ValueError, lambda: utils.aes_decrypt(encrypted, k2))


if __name__ == '__main__':
    unittest.main()
