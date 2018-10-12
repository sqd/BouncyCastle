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

    def test_handshake(self):
        peer1_rsa = RSA.generate(2048)
        peer2_rsa = RSA.generate(2048)

        peer1_serving_port = None
        peer2_serving_port = 1234

        messages_for_peer1 = []
        messages_for_peer2 = []

        peer1_handshake = handshake.PeerHandshake(peer1_rsa, peer1_serving_port,
                                                  lambda msg: messages_for_peer2.append(msg))
        peer2_handshake = handshake.PeerHandshake(peer2_rsa, peer2_serving_port,
                                                  lambda msg: messages_for_peer1.append(msg))

        while not (messages_for_peer1 == [] and messages_for_peer2 == []):
            for msg in messages_for_peer1:
                peer1_handshake.handle_message(msg.SerializeToString())
            messages_for_peer1 = []

            for msg in messages_for_peer2:
                peer2_handshake.handle_message(msg.SerializeToString())
            messages_for_peer2 = []

        self.assertTrue(peer1_handshake.complete)
        self.assertTrue(peer2_handshake.complete)

        self.assertIsNotNone(peer1_handshake.session_key)
        self.assertEqual(peer1_handshake.session_key, peer2_handshake.session_key)

        self.assertEqual(peer1_handshake.peer_pub_key, peer2_rsa.publickey())
        self.assertEqual(peer2_handshake.peer_pub_key, peer1_rsa.publickey())

        self.assertEqual(peer1_handshake.peer_serving_port, peer2_serving_port)
        self.assertEqual(peer2_handshake.peer_serving_port, peer1_serving_port)


if __name__ == '__main__':
    unittest.main()
