import asyncio
import threading
import unittest
from asyncio import StreamReader, StreamWriter

from Crypto.PublicKey import RSA

from bfcp.connection import SocketConnection
from bfcp.node import BFCNode
from bfcp.protocol import pubkey_to_proto
from protos.bfcp_pb2 import NodeTable, Node, EndNodeRequirement


class EndToEndTests(unittest.TestCase):
    @staticmethod
    async def _echo_server(reader: StreamReader, writer: StreamWriter):
        """Reads 20 bytes from the stream, outputs them back, and then closes the connection."""
        data_read = 0
        while data_read != 20:
            data = await reader.read(20 - data_read)
            writer.write(data)
            await writer.drain()
            data_read += len(data)
        writer.close()

    def test_something(self):
        # Prepare the simulated machines
        node1_port = 54361
        node1_rsa_key = RSA.generate(2048)
        node1_info = Node()
        node1_info.public_key.CopyFrom(pubkey_to_proto(node1_rsa_key.publickey()))
        node1_info.last_known_address = '127.0.0.1'
        node1_info.last_port = node1_port
        node1_info.country_code = 616  # Poland

        node2_port = 54362
        node2_rsa_key = RSA.generate(2048)
        node2_info = Node()
        node2_info.public_key.CopyFrom(pubkey_to_proto(node2_rsa_key.publickey()))
        node2_info.last_known_address = '127.0.0.1'
        node2_info.last_port = node2_port
        node2_info.country_code = 496  # Mongolia
        
        node3_port = 54363
        node3_rsa_key = RSA.generate(2048)
        node3_info = Node()
        node3_info.public_key.CopyFrom(pubkey_to_proto(node3_rsa_key.publickey()))
        node3_info.last_known_address = '127.0.0.1'
        node3_info.last_port = node3_port
        node3_info.country_code = 156  # China Mainland
        
        node4_port = 54364
        node4_rsa_key = RSA.generate(2048)
        node4_info = Node()
        node4_info.public_key.CopyFrom(pubkey_to_proto(node4_rsa_key.publickey()))
        node4_info.last_known_address = '127.0.0.1'
        node4_info.last_port = node4_port
        node4_info.country_code = 356  # India
        
        node5_port = 54365
        node5_rsa_key = RSA.generate(2048)
        node5_info = Node()
        node5_info.public_key.CopyFrom(pubkey_to_proto(node5_rsa_key.publickey()))
        node5_info.last_known_address = '127.0.0.1'
        node5_info.last_port = node5_port
        node5_info.country_code = 404  # Kenya
        
        node6_port = 54366
        node6_rsa_key = RSA.generate(2048)
        node6_info = Node()
        node6_info.public_key.CopyFrom(pubkey_to_proto(node6_rsa_key.publickey()))
        node6_info.last_known_address = '127.0.0.1'
        node6_info.last_port = node6_port
        node6_info.country_code = 840  # USA
        
        node_table = NodeTable()
        node_table.entries.add().node.CopyFrom(node1_info)
        node_table.entries.add().node.CopyFrom(node2_info)
        node_table.entries.add().node.CopyFrom(node3_info)
        node_table.entries.add().node.CopyFrom(node4_info)
        node_table.entries.add().node.CopyFrom(node5_info)
        node_table.entries.add().node.CopyFrom(node6_info)

        node1 = BFCNode(node1_info, ('127.0.0.1', node1_port), node1_rsa_key, node_table)
        node1_loop_future = asyncio.ensure_future(node1.main_loop())
        node2 = BFCNode(node2_info, ('127.0.0.1', node2_port), node2_rsa_key, node_table)
        node2_loop_future = asyncio.ensure_future(node2.main_loop())
        node3 = BFCNode(node3_info, ('127.0.0.1', node3_port), node3_rsa_key, node_table)
        node3_loop_future = asyncio.ensure_future(node3.main_loop())
        node4 = BFCNode(node4_info, ('127.0.0.1', node4_port), node4_rsa_key, node_table)
        node4_loop_future = asyncio.ensure_future(node4.main_loop())
        node5 = BFCNode(node5_info, ('127.0.0.1', node5_port), node5_rsa_key, node_table)
        node5_loop_future = asyncio.ensure_future(node5.main_loop())
        node6 = BFCNode(node6_info, ('127.0.0.1', node6_port), node6_rsa_key, node_table)
        node6_loop_future = asyncio.ensure_future(node6.main_loop())

        target_server_port = 54360

        async def start_scenario():
            target_server = await asyncio.start_server(
                EndToEndTests._echo_server, '127.0.0.1', target_server_port)

            # Loop forever
            return await asyncio.gather(
                node1_loop_future,
                node2_loop_future,
                node3_loop_future,
                node4_loop_future,
                node5_loop_future,
                node6_loop_future,
            )

        def user_thread():
            # Sample connection
            reqs = EndNodeRequirement()
            reqs.country = 840
            conn = node1.connection_manager.new_connection(reqs, ('127.0.0.1', target_server_port))
            sock = SocketConnection(conn)
            sock.sendall(b'01234')
            sock.sendall(b'56789')
            self.assertEqual(sock.recv_all(7), b'0123456')
            sock.sendall(b'01234')
            sock.sendall(b'56789')
            self.assertEqual(sock.recv_all(4), b'7890')
            self.assertEqual(sock.recv_all(9), b'123456789')

            node1._async_loop.stop()

        thread = threading.Thread(target=user_thread)
        thread.start()

        asyncio.get_event_loop().run_forever()


if __name__ == '__main__':
    unittest.main()
