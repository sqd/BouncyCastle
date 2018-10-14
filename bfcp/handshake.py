from asyncio import StreamReader, StreamWriter
from typing import Tuple, Callable, Optional

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from google.protobuf.message import Message

from protos.bfcp_pb2 import RsaChallenge, RsaChallengeResponse, RsaPubKey, PeerHello, AESKey, \
    NodeTableEntry
from utils import generate_aes_key, send_proto_msg, recv_proto_msg

from config import *


def make_rsa_challenge(challenged_pub_key: RsaKey) -> Tuple[bytes, RsaChallenge]:
    """
    Workflow for RSA challenges:

        key = RSA.generate(4096)
        decrypted, challenge = handshake.make_rsa_challenge(key.publickey())
        solved = handshake.solve_rsa_challenge(key, challenge)
        self.assertTrue(handshake.verify_rsa_challenge(decrypted, solved))
    """
    decrypted = get_random_bytes(CHALLENGE_SIZE)
    cipher_rsa = PKCS1_OAEP.new(challenged_pub_key)
    encrypted = cipher_rsa.encrypt(decrypted)

    return decrypted, RsaChallenge(encrypted=encrypted)


def solve_rsa_challenge(verified_priv_key: RsaKey,
                        rsa_challenge: RsaChallenge) -> RsaChallengeResponse:
    cipher_rsa = PKCS1_OAEP.new(verified_priv_key)
    decrypted = cipher_rsa.decrypt(rsa_challenge.encrypted)

    return RsaChallengeResponse(decrypted=decrypted)


def verify_rsa_challenge(decrypted: bytes, rsa_challenge_response: RsaChallengeResponse) -> bool:
    return decrypted == rsa_challenge_response.decrypted


def _int_to_bytes(n: int) -> bytes:
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big')


# TODO(mike): Move the following 3 methods to utils
def pubkey_to_proto(key: RsaKey) -> RsaPubKey:
    """
    Converts the given RSA Key into an RsaPubKey proto message.
    """
    message = RsaPubKey()
    message.modulus = _int_to_bytes(key.n)
    message.pub_exponent = _int_to_bytes(key.e)
    return message


def pubkey_to_deterministic_string(key: RsaKey) -> bytes:
    return pubkey_to_proto(key).SerializeToString()


def proto_to_pubkey(key: RsaPubKey) -> RsaKey:
    """
    Reads an RsaPubKey proto message back into an RsaKey
    """
    n = int.from_bytes(key.modulus, 'big')
    e = int.from_bytes(key.pub_exponent, 'big')
    return RsaKey(n=n, e=e)


def get_node_pub_key(n: NodeTableEntry) -> RsaKey:
    return proto_to_pubkey(n.node.public_key)


PEER_CONNECTION_KEY_SIZE = 256


class PeerHandshake:
    """
    Used for handling the handshake between BFCP peers.

    You should use handle_message() until PeerHandshake.complete is set to True. Once that's the
    case, you can access the following fields:
     * peer_pub_key - the public key of the peer. This is verified using an RSA Challenge
     * peer_serving_port - the port on which the peer serves the BFCP. If the peer does not keep a
       TCP server for BFCP, this will be set to None. Note, this value is not verified by trying to
       connect to the peer.
     * session key - the AES key established between the peers that can be used to encrypt traffic
       between them

    Handshake with a peer is performed as follows:
    * Node sends its public key
    * After getting peer's pub key, node sends an RSA challenge
    * After receiving peer's RSA challenge, node sends the solved challenge
    * After verifying the challenge, the node with the smaller pub key (lexicographic order of
      modulus, exponent) sends an encrypted AES key.
    * The AES key is used for all further communication.
    """

    def __init__(self, reader: StreamReader, writer: StreamWriter, own_rsa_key: RsaKey,
                 own_serving_port: Optional[int]):
        """
        :param own_rsa_key: The RSA key of this node
        :param own_serving_port: The serving port of this node. If this node is not serving, this
        should be set to None
        """
        self._writer = writer
        self._reader = reader
        self._own_serving_port = own_serving_port

        self.own_rsa_key = own_rsa_key
        self.peer_pub_key: Optional[RsaKey] = None
        self.peer_serving_port: Optional[int] = None
        self.session_key: Optional[bytes] = None

    def _make_hello(self) -> PeerHello:
        hello = PeerHello()
        hello.pub_key.CopyFrom(pubkey_to_proto(self.own_rsa_key))
        hello.serving_port = self._own_serving_port if self._own_serving_port is not None else 0
        return hello

    @staticmethod
    def _is_key_smaller_than(k1, k2) -> bool:
        return k1.n < k2.n or (k1.n == k2.n and k1.e < k2.e)

    async def execute(self):
        await send_proto_msg(self._writer, self._make_hello())

        peer_hello = PeerHello()
        await recv_proto_msg(self._reader, peer_hello)
        self.peer_pub_key = proto_to_pubkey(peer_hello.pub_key)
        self.peer_serving_port = \
            peer_hello.serving_port if peer_hello.serving_port > 0 else None

        decrypted_challenge, challenge = make_rsa_challenge(self.peer_pub_key)
        await send_proto_msg(self._writer, challenge)

        rsa_challenge = RsaChallenge()
        await recv_proto_msg(self._reader, rsa_challenge)
        await send_proto_msg(self._writer, solve_rsa_challenge(self.own_rsa_key, rsa_challenge))

        solved_challenge = RsaChallengeResponse()
        await recv_proto_msg(self._reader, solved_challenge)
        if not verify_rsa_challenge(decrypted_challenge, solved_challenge):
            raise ConnectionError('RSA challenge solved incorrectly')

        if self._is_key_smaller_than(self.own_rsa_key, self.peer_pub_key):
            self.session_key = generate_aes_key(PEER_CONNECTION_KEY_SIZE)

            cipher_rsa = PKCS1_OAEP.new(self.peer_pub_key)
            await send_proto_msg(self._writer, AESKey(key=cipher_rsa.encrypt(self.session_key)))
        else:
            key_message = AESKey()
            await recv_proto_msg(self._reader, key_message)

            cipher_rsa = PKCS1_OAEP.new(self.own_rsa_key)
            self.session_key = cipher_rsa.decrypt(key_message.key)
