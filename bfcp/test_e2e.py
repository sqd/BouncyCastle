import asyncio
import threading
import unittest
from asyncio import StreamReader, StreamWriter

from Crypto.PublicKey import RSA

from bfcp.connection import SocketConnection
from bfcp.node import BFCNode
from bfcp.protocol import pubkey_to_proto
from config import HTTPProxyServerConfig
from event_server import EventServer
from http_proxy import HTTPProxyServer
from protos.bfcp_pb2 import NodeTable, Node, EndNodeRequirement


class EndToEndTests(unittest.TestCase):
    @staticmethod
    async def _echo_server(reader: StreamReader, writer: StreamWriter):
        """Reads 20 bytes from the stream, outputs them back, and then closes the connection."""
        data_read = 0
        while data_read != 20:
            data = await reader.read(20 - data_read)
            print('ECHO SERVER: ', data)
            writer.write(data)
            await writer.drain()
            print('ECHO SERVER SENT')
            data_read += len(data)
        writer.close()

    def test_something(self):
        # Prepare the simulated machines
        node1_port = 43211
        node1_rsa_key = RSA.generate(2048)
        node1_info = Node()
        node1_info.public_key.CopyFrom(pubkey_to_proto(node1_rsa_key.publickey()))
        node1_info.last_known_address = '127.0.0.1'
        node1_info.last_port = node1_port
        node1_info.country_code = 616  # Poland

        node2_port = 43212
        node2_rsa_key = RSA.generate(2048)
        node2_info = Node()
        node2_info.public_key.CopyFrom(pubkey_to_proto(node2_rsa_key.publickey()))
        node2_info.last_known_address = '127.0.0.1'
        node2_info.last_port = node2_port
        node2_info.country_code = 496  # Mongolia
        
        node3_port = 43213
        node3_rsa_key = RSA.generate(2048)
        node3_info = Node()
        node3_info.public_key.CopyFrom(pubkey_to_proto(node3_rsa_key.publickey()))
        node3_info.last_known_address = '127.0.0.1'
        node3_info.last_port = node3_port
        node3_info.country_code = 156  # China Mainland
        
        node4_port = 43214
        node4_rsa_key = RSA.generate(2048)
        node4_info = Node()
        node4_info.public_key.CopyFrom(pubkey_to_proto(node4_rsa_key.publickey()))
        node4_info.last_known_address = '127.0.0.1'
        node4_info.last_port = node4_port
        node4_info.country_code = 356  # India
        
        node5_port = 43215
        node5_rsa_key = RSA.generate(2048)
        node5_info = Node()
        node5_info.public_key.CopyFrom(pubkey_to_proto(node5_rsa_key.publickey()))
        node5_info.last_known_address = '127.0.0.1'
        node5_info.last_port = node5_port
        node5_info.country_code = 404  # Kenya
        
        node6_port = 43216
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
        node2 = BFCNode(node2_info, ('127.0.0.1', node2_port), node2_rsa_key, node_table)
        node3 = BFCNode(node3_info, ('127.0.0.1', node3_port), node3_rsa_key, node_table)
        node4 = BFCNode(node4_info, ('127.0.0.1', node4_port), node4_rsa_key, node_table)
        node5 = BFCNode(node5_info, ('127.0.0.1', node5_port), node5_rsa_key, node_table)
        node6 = BFCNode(node6_info, ('127.0.0.1', node6_port), node6_rsa_key, node_table)

        target_server_port = 43210

        async def start_scenario():
            target_server = await asyncio.start_server(
                EndToEndTests._echo_server, '127.0.0.1', target_server_port)

            # Loop forever
            return await asyncio.gather(
                node1.main_loop(),
                node2.main_loop(),
                node3.main_loop(),
                node4.main_loop(),
                node5.main_loop(),
                node6.main_loop(),
            )

        def user_thread():
            http_proxy_default_config = HTTPProxyServerConfig([("127.0.0.1", 8080)])
            ev_server = EventServer()
            http_proxy = HTTPProxyServer(http_proxy_default_config, node1, ev_server)
            print("(Proxy) Epoll event looping...")
            http_proxy.start()
            ev_server.start()

        # def user_thread():
        #     # Sample connection
        #     asyncio.set_event_loop(asyncio.new_event_loop())
        #     print('User_tread id', threading.get_ident())
        #     reqs = EndNodeRequirement()
        #     reqs.country = 840
        #     conn = node1.connection_manager.new_connection(reqs, ('127.0.0.1', target_server_port))
        #     sock = SocketConnection(conn)
        #     print('WTF1')
        #     sock.sendall(b'01234')
        #     print('WTF2')
        #     sock.sendall(b'56789')
        #     print('WTF3')
        #     self.assertEqual(sock.recv_all(7), b'0123456')
        #     sock.sendall(b'01234')
        #     print('WTF4')
        #     sock.sendall(b'56789')
        #     print('WTF5')
        #     self.assertEqual(sock.recv_all(4), b'7890')
        #     self.assertEqual(sock.recv_all(9), b'123456789')
        #     sock.close()
        #     print('WTF6')
        #     node1.traffic_manager.get_loop().stop()

        thread = threading.Thread(target=user_thread)
        thread.start()

        print('Main thread id', threading.get_ident())
        asyncio.get_event_loop().set_debug(True)
        asyncio.ensure_future(start_scenario())
        asyncio.get_event_loop().run_forever()


if __name__ == '__main__':
    unittest.main()
