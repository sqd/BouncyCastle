import unittest
from config import *
from Crypto.PublicKey import RSA
from protos.bfcp_pb2 import ConnectionRoutingParams, Node

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
        test_proto_obj = ProtoIO.read_from_file('test_proto_io.txt', ConnectionRoutingParams())
        self.assertEqual(test_proto_obj.uuid, "8b109c15-5d83-4ec6-9cd0-32abda2c97af")
        self.assertEqual(test_proto_obj.remaining_hops, 5)

    def test_create_write_node(self):
        key = RSA.generate(1024).publickey()
        ProtoIO.create_write_node(key, 32, '0.0.0.0', 8080, '../node.txt')
        node = ProtoIO.read_from_file('../node.txt', Node())
        self.assertEqual(node.country_code, 32)