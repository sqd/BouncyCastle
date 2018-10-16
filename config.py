# -*- coding: utf-8 -*-
from typing import List, Tuple
import json
from protos.bfcp_pb2 import BouncyMessage, Node, NodeTable, NodeTableEntry, RsaPubKey
from google.protobuf import text_format
from Crypto.PublicKey.RSA import RsaKey
from utils import _int_to_bytes, pubkey_to_proto

""" GLOBAL VARIABLES """
GLOBAL_VARS = None
with open('constants.json') as f:
    data = json.load(f)
    GLOBAL_VARS = data['constants']


class HTTPProxyServerConfig:
    """
    The config class for HTTPProxyServer.
    """
    def __init__(self, listen_address: List[Tuple[str, int]]):
        self.listen_address = listen_address
        """A list of tuple (address:str, port:int) specifying the locations the server should listen on."""

class ProtoIO:
    """
    Helper class that reads/writes proto object into file
    """
    @staticmethod
    def read_from_file(file_path: str, proto_type_instance: BouncyMessage) -> BouncyMessage:
        """
        :param file_path: directory of file to be read
        :param proto_type_instance: NOTE: must be instance like NodeTable(), NOT class like NodeTable
        :return: NodeTable from reading a file
        usage: ProtoIO.read_from_file(<file-path>, NodeTable())
        """
        text_proto_file = open(file_path, 'r')
        text_proto = text_proto_file.read()
        text_proto_file.close()
        proto_object = text_format.Parse(text_proto, proto_type_instance)
        return proto_object

    @staticmethod
    def write_to_file(file_path: str, proto_object: BouncyMessage) -> None:
        """
        Writes NodeTable object into file
        :param file_path: directory of file to be written
        usage: ProtoIO.write_to_file(<file-path>, NodeTable())
        """
        text_proto = text_format.MessageToString(proto_object)
        file = open(file_path, 'w')
        file.write(text_proto)
        file.close()

    @staticmethod
    def create_write_node(key: RsaKey, country_code: int, address: str, port: int, file_path: str) -> None:
        """
        Writes a Node textfile given arguments
        :param key:
        :param country_code:
        :param address:
        :param port:
        :return: None
        """
        node = Node()
        node.public_key.CopyFrom(pubkey_to_proto(key))
        node.country_code = country_code
        node.last_known_address = address
        node.last_port = port
        ProtoIO.write_to_file(file_path, node)

    @staticmethod
    def create_write_nodetable(node_entries: List[NodeTableEntry], file_path: str) -> None:
        """
        Writes a NodeTable textfile given list of NodeTableEntry
        :param node_entries:
        :return: None
        """
        node_table = NodeTable()
        node_table.entries.extend(node_entries)
        ProtoIO.write_to_file(file_path, node_table)



