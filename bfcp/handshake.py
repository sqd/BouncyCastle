from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes

from protos.bfcp_pb2 import RsaChallenge, RsaChallengeResponse


CHALLENGE_SIZE = 128


def make_rsa_challenge(challenged_pub_key: RsaKey):
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


def solve_rsa_challenge(verified_priv_key: RsaKey, rsa_challenge: RsaChallenge):
    cipher_rsa = PKCS1_OAEP.new(verified_priv_key)
    decrypted = cipher_rsa.decrypt(rsa_challenge.encrypted)

    return RsaChallengeResponse(decrypted=decrypted)


def verify_rsa_challenge(decrypted: bytes, rsa_challenge_response: RsaChallengeResponse):
    return decrypted == rsa_challenge_response.decrypted
