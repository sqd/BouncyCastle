import socket

# create an INET, STREAMing socket
from protos.bfcp_pb2 import PeerHello
from utils import recv_proto_msg

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# now connect to the web server on port 80 - the normal http port
s.connect(("localhost", 54362))

h = PeerHello()
l = int.from_bytes(s.recv(4), 'big')
bts = s.recv(l)
h.ParseFromString(bts)
print(str(h))
