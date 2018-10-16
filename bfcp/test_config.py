import unittest
from config import *
from Crypto.PublicKey import RSA
from protos.bfcp_pb2 import ConnectionRoutingParams, Node, NodeTableEntry, NodeTable
from utils import _int_to_bytes, pubkey_to_proto

class TestConfig(unittest.TestCase):
    def test_global_var(self):
        value = 5
        self.assertEqual(GLOBAL_VARS['MAX_HOPS_WITHOUT_END_NODE'], value)

    def test_proto_write(self):
        test_proto_obj = ConnectionRoutingParams()
        test_proto_obj.uuid = "8b109c15-5d83-4ec6-9cd0-32abda2c97af"
        test_proto_obj.remaining_hops = 5
        ProtoIO.write_to_file('../test_proto_io.txt', test_proto_obj)

    def test_proto_read(self):
        test_proto_obj = ProtoIO.read_from_file('../test_proto_io.txt', ConnectionRoutingParams())
        self.assertEqual(test_proto_obj.uuid, "8b109c15-5d83-4ec6-9cd0-32abda2c97af")
        self.assertEqual(test_proto_obj.remaining_hops, 5)

    def test_create_write_node(self):
        key = RSA.generate(1024).publickey()
        ProtoIO.create_write_node(key, 32, '0.0.0.0', 8080, '../node.txt')
        node = ProtoIO.read_from_file('../node.txt', Node())
        self.assertEqual(node.country_code, 32)

    def test_create_write_nodetable(self):
        node_entries = []
        node = Node()
        key = RSA.generate(1024).publickey()
        node.public_key.CopyFrom(pubkey_to_proto(key))
        node.country_code = 32
        node.last_known_address = '0.0.0.0'
        node.last_port = 8080
        entry = NodeTableEntry()
        entry.node.CopyFrom(node)
        entry.trust_score = 1.0
        entry.avg_n = 1.0
        entry.avg_sum = 0.0
        n = 2
        for i in range(n): node_entries.append(entry)
        ProtoIO.create_write_nodetable(node_entries, '../node_table.txt')
        node_table = ProtoIO.read_from_file('../node_table.txt', NodeTable())
        self.assertEqual(len(node_table.entries), n)

    def test_create_nodetable_aws(self):
        addresses = ['34.219.62.232', '34.217.12.64', '18.237.76.130']
        node_entries = []
        for address in addresses:
            node = Node()
            key = RSA.generate(1024).publickey()
            node.public_key.CopyFrom(pubkey_to_proto(key))
            node.country_code = 840
            node.last_known_address = address
            node.last_port = 8080
            entry = NodeTableEntry()
            entry.node.CopyFrom(node)
            entry.trust_score = 1.0
            entry.avg_n = 1.0
            entry.avg_sum = 0.0
            node_entries.append(entry)
        ProtoIO.create_write_nodetable(node_entries, '../node_table.txt')
        self.assertEqual(1, 1)