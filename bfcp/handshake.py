from typing import Tuple

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes

from protos.bfcp_pb2 import RsaChallenge, RsaChallengeResponse, RsaPubKey

CHALLENGE_SIZE = 128


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


def pubkey_to_proto(key: RsaKey) -> RsaPubKey:
    """
    Converts the given RSA Key into an RsaPubKey proto message.
    """
    message = RsaPubKey()
    message.modulus = _int_to_bytes(key.n)
    message.pub_exponent = _int_to_bytes(key.e)
    return message


def proto_to_pubkey(key: RsaPubKey) -> RsaKey:
    """
    Reads an RsaPubKey proto message back into an RsaKey
    """
    n = int.from_bytes(key.modulus, 'big')
    e = int.from_bytes(key.pub_exponent, 'big')
    return RsaKey(n=n, e=e)
