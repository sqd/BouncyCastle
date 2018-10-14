import asyncio
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
        client_rsa = RSA.generate(2048)
        server_rsa = RSA.generate(2048)

        serving_port = 41142

        client_handshake = None
        server_handshake = None

        async def server_handle_connection(reader, writer):
            nonlocal server_handshake
            
            server_handshake = handshake.PeerHandshake(reader, writer, server_rsa, serving_port)
            await server_handshake.execute()

        loop = asyncio.get_event_loop()
        server = loop.run_until_complete(
            asyncio.start_server(server_handle_connection, '127.0.0.1', serving_port, loop=loop)
        )

        async def client_scenario():
            nonlocal client_handshake
            
            reader, writer = await asyncio.open_connection('127.0.0.1', serving_port)
            client_handshake = handshake.PeerHandshake(reader, writer, client_rsa, None)
            await client_handshake.execute()
            writer.close()

        loop.run_until_complete(client_scenario())

        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()

        self.assertIsNotNone(client_handshake.session_key)
        self.assertEqual(client_handshake.session_key, server_handshake.session_key)

        self.assertEqual(client_handshake.peer_pub_key, server_rsa.publickey())
        self.assertEqual(server_handshake.peer_pub_key, client_rsa.publickey())

        self.assertEqual(client_handshake.peer_serving_port, serving_port)
        self.assertEqual(server_handshake.peer_serving_port, None)


if __name__ == '__main__':
    unittest.main()
