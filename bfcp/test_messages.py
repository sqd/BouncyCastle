import asyncio
import threading
import unittest
from unittest.mock import Mock

from Crypto.PublicKey import RSA
from google.protobuf import text_format

from bfcp.messages import TrafficManager
from protos.bfcp_pb2 import BouncyMessage, NodeTableEntry


class TestMessages(unittest.TestCase):
    def test_end_to_end(self):
        loop = asyncio.get_event_loop()
        trust_table_manager = Mock().return_value

        # Set up the nodes in the network
        node1_port = 53251
        node1_rsa_key = RSA.generate(2048)
        node1_manager = TrafficManager(trust_table_manager, node1_rsa_key, loop,
                                       ('127.0.0.1', node1_port))
        
        node2_port = 53252
        node2_rsa_key = RSA.generate(2048)
        node2_manager = TrafficManager(trust_table_manager, node2_rsa_key, loop,
                                       ('127.0.0.1', node2_port))
        
        node3_port = 53253
        node3_rsa_key = RSA.generate(2048)
        node3_manager = TrafficManager(trust_table_manager, node3_rsa_key, loop,
                                       ('127.0.0.1', node3_port))

        # Prepare messages for sending
        msg1 = BouncyMessage()
        text_format.Parse(
            '''
            connection_request {
                target_server_address: "test_message_1"
            }
            ''',
            msg1
        )
        msg2 = BouncyMessage()
        text_format.Parse(
            '''
            connection_request {
                target_server_address: "test_message_2"
            }
            ''',
            msg2
        )
        msg3 = BouncyMessage()
        text_format.Parse(
            '''
            connection_request {
                target_server_address: "test_message_3"
            }
            ''',
            msg3
        )
        msg4 = BouncyMessage()
        text_format.Parse(
            '''
            connection_request {
                target_server_address: "test_message_4"
            }
            ''',
            msg4
        )
        msg5 = BouncyMessage()
        text_format.Parse(
            '''
            connection_request {
                target_server_address: "test_message_5"
            }
            ''',
            msg5
        )

        # Prepare the trust manager
        def pub_key_to_address(pub_key):
            node = NodeTableEntry()

            if pub_key == node1_rsa_key.publickey():
                text_format.Parse(
                    '''
                    trust_score: 1.0
                    node {
                        last_known_address: "127.0.0.1",
                        last_port: ''' + str(node1_port) + '''
                    }
                    ''',
                    node
                )
            if pub_key == node2_rsa_key.publickey():
                text_format.Parse(
                    '''
                    trust_score: 1.0
                    node {
                        last_known_address: "127.0.0.1",
                        last_port: ''' + str(node2_port) + '''
                    }
                    ''',
                    node
                )
            if pub_key == node3_rsa_key.publickey():
                text_format.Parse(
                    '''
                    trust_score: 1.0
                    node {
                        last_known_address: "127.0.0.1",
                        last_port: ''' + str(node3_port) + '''
                    }
                    ''',
                    node
                )
            return node

        trust_table_manager.get_node_by_pubkey.side_effect = pub_key_to_address

        # We will hold the received messages here
        node1_messages = []
        node2_messages = []
        node3_messages = []

        async def scenario():
            nonlocal node1_messages
            nonlocal node2_messages
            nonlocal node3_messages

            await node1_manager.send(node2_rsa_key.publickey(), msg1)

            await node2_manager.send(node3_rsa_key.publickey(), msg2)
            node3_messages.extend(await node3_manager.new_messages())

            await node3_manager.send(node1_rsa_key.publickey(), msg3)
            node1_messages.extend(await node1_manager.new_messages())

            await node1_manager.send(node3_rsa_key.publickey(), msg4)
            await node2_manager.send(node1_rsa_key.publickey(), msg5)

            # Let the sockets communicate
            await asyncio.sleep(5)

            node1_messages.extend(await node1_manager.new_messages())
            node2_messages.extend(await node2_manager.new_messages())
            node3_messages.extend(await node3_manager.new_messages())

        loop.run_until_complete(scenario())

        self.assertCountEqual(
            node1_messages,
            [(node3_rsa_key.publickey(), msg3), (node2_rsa_key.publickey(), msg5)]
        )
        self.assertCountEqual(
            node2_messages,
            [(node1_rsa_key.publickey(), msg1)]
        )
        self.assertCountEqual(
            node3_messages,
            [(node2_rsa_key.publickey(), msg2), (node1_rsa_key.publickey(), msg4)]
        )


if __name__ == '__main__':
    unittest.main()
