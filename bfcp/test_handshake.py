import unittest

from Crypto.PublicKey import RSA

from bfcp import handshake


class TestHandshake(unittest.TestCase):
    def test_rsa_challenge_solved_with_valid_key(self):
        key = RSA.generate(2048)
        decrypted, challenge = handshake.make_rsa_challenge(key.publickey())
        solved = handshake.solve_rsa_challenge(key, challenge)
        self.assertTrue(handshake.verify_rsa_challenge(decrypted, solved))

    def test_rsa_challenge_fails_with_invalid_key(self):
        key = RSA.generate(2048)
        key2 = RSA.generate(2048)
        decrypted, challenge = handshake.make_rsa_challenge(key.publickey())
        self.assertRaises(ValueError, lambda: handshake.solve_rsa_challenge(key2, challenge))

    def test_pub_key_encoding(self):
        key = RSA.generate(1024).publickey()
        self.assertEqual(handshake.proto_to_pubkey(handshake.pubkey_to_proto(key)), key)


if __name__ == '__main__':
    unittest.main()
