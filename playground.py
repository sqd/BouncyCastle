import socket

from protos.bfcp_pb2 import BouncyMessage

b = BouncyMessage()
b.connection_request.target_server_port = 1234

print(b.message)