import asyncio
import unittest

from Crypto.PublicKey import RSA
from google.protobuf import text_format

from bfcp import protocol
from bfcp.protocol import matches_requirements
from protos.bfcp_pb2 import Node, EndNodeRequirement


class TestProtocol(unittest.TestCase):
    def test_rsa_challenge_solved_with_valid_key(self):
        key = RSA.generate(2048)
        decrypted, challenge = protocol.make_rsa_challenge(key.publickey())
        solved = protocol.solve_rsa_challenge(key, challenge)
        self.assertTrue(protocol.verify_rsa_challenge(decrypted, solved))

    def test_rsa_challenge_fails_with_invalid_key(self):
        key = RSA.generate(2048)
        key2 = RSA.generate(2048)
        decrypted, challenge = protocol.make_rsa_challenge(key.publickey())
        self.assertRaises(ValueError, lambda: protocol.solve_rsa_challenge(key2, challenge))

    def test_pub_key_encoding(self):
        key = RSA.generate(1024).publickey()
        self.assertEqual(protocol.proto_to_pubkey(protocol.pubkey_to_proto(key)), key)

    def test_handshake(self):
        client_rsa = RSA.generate(2048)
        server_rsa = RSA.generate(2048)

        serving_port = 41142

        client_handshake = None
        server_handshake = None

        async def server_handle_connection(reader, writer):
            nonlocal server_handshake

            server_handshake = protocol.PeerHandshake(reader, writer, server_rsa, serving_port)
            await server_handshake.execute()

        loop = asyncio.get_event_loop()
        server = loop.run_until_complete(
            asyncio.start_server(server_handle_connection, '127.0.0.1', serving_port, loop=loop)
        )

        async def client_scenario():
            nonlocal client_handshake

            reader, writer = await asyncio.open_connection('127.0.0.1', serving_port)
            client_handshake = protocol.PeerHandshake(reader, writer, client_rsa, None)
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

    def test_requirement_verification1(self):
        node = Node()
        text_format.Parse('''
            country_code: 123
            last_known_address: "192.168.10.10"
        ''', node)

        requirement = EndNodeRequirement()
        text_format.Parse('''
            or {
                requirements {
                    country: 999
                }
                requirements {
                    ip_subnet: "192.168.0.0/16"
                }
            }
        ''', requirement)

        self.assertTrue(matches_requirements(node, requirement))

    def test_requirement_verification2(self):
        node = Node()
        text_format.Parse('''
            country_code: 123
            last_known_address: "192.168.10.10"
        ''', node)

        requirement = EndNodeRequirement()
        text_format.Parse('''
            and {
                requirements {
                    country: 123
                }
                requirements {
                    ip_subnet: "192.168.10.0/24"
                }
            }
        ''', requirement)

        self.assertTrue(matches_requirements(node, requirement))

    def test_requirement_verification3(self):
        node = Node()
        text_format.Parse('''
            country_code: 999
            last_known_address: "192.168.10.10"
        ''', node)

        requirement = EndNodeRequirement()
        text_format.Parse('''
            and {
                requirements {
                    country: 999
                }
                requirements {
                    not {
                        ip_subnet: "10.10.0.0/16"
                    }
                }
            }
        ''', requirement)

        self.assertTrue(matches_requirements(node, requirement))

    def test_requirement_verification4(self):
        node = Node()
        text_format.Parse('''
            country_code: 123
            last_known_address: "192.168.10.10"
        ''', node)

        requirement = EndNodeRequirement()
        text_format.Parse('''
            and {
                requirements {
                    country: 999
                }
                requirements {
                    ip_subnet: "192.168.0.0/16"
                }
            }
        ''', requirement)

        self.assertFalse(matches_requirements(node, requirement))


if __name__ == '__main__':
    unittest.main()
