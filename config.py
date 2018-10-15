# -*- coding: utf-8 -*-
from typing import List, Tuple
import json
from protos.bfcp_pb2 import BouncyMessage
from google.protobuf import text_format


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

    def read_from_file(self, file_path: str, proto_type: BouncyMessage) -> BouncyMessage:
        """
        :param file_dir: directory of file to be read
        :return: NodeTable from reading a file
        usage: <protoio>.read_from_file(<file-path>, NodeTable())
        """
        text_proto = open(file_path, 'r')
        proto_object = text_format.Parse(text_proto, proto_type)
        return proto_object

    def write_to_file(self, file_path: str, proto_object: BouncyMessage) -> None:
        """
        Writes NodeTable object into file
        :param file_dir: directory of file to be written
        usage: <protoio>.write_to_file(<file-path>, NodeTable())
        """
        text_proto = text_format.MessageToString(proto_object)
        file = open(file_path, 'w')
        file.write(text_proto)
        file.close()

