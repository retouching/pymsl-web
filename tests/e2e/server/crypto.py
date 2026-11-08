import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class ServerCrypto:
    def __init__(self) -> None:
        """Draw the RSA key of the server."""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @staticmethod
    def b64(data: bytes) -> str:
        """Write standard Base64."""
        return base64.b64encode(data).decode()

    def public_pem(self) -> bytes:
        """Give the PEM of the server's public key."""
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, data: bytes) -> bytes:
        """Sign `data` with RSASSA-PKCS1-v1_5 SHA-256, as the server's entity does."""
        return self.private_key.sign(data, rsa_padding.PKCS1v15(), hashes.SHA256())

    @staticmethod
    def wrap(public_key_der: bytes, secret: bytes) -> str:
        """Wrap `secret` in JWK JSON with RSA-OAEP SHA-1 for the client's public key."""
        key = serialization.load_der_public_key(public_key_der)
        if not isinstance(key, RSAPublicKey):
            raise TypeError("an RSA public key expected")
        jwk = {"kty": "oct", "k": base64.urlsafe_b64encode(secret).decode().rstrip("="), "extractable": True}
        sha1 = hashes.SHA1()  # noqa: S303
        oaep = rsa_padding.OAEP(mgf=rsa_padding.MGF1(sha1), algorithm=sha1, label=None)
        return ServerCrypto.b64(key.encrypt(json.dumps(jwk).encode(), oaep))

    @staticmethod
    def encrypt(key: bytes, key_id: str, clear: bytes) -> bytes:
        """Encrypt `clear` with AES-128-CBC and PKCS#7 into a V1 envelope."""
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padder.update(clear) + padder.finalize()) + encryptor.finalize()
        envelope = {"keyid": key_id, "iv": ServerCrypto.b64(iv), "ciphertext": ServerCrypto.b64(ciphertext)}
        envelope["sha256"] = "AA=="
        return json.dumps(envelope).encode()

    @staticmethod
    def decrypt(key: bytes, envelope: bytes) -> bytes:
        """Decrypt a V1 envelope."""
        document = json.loads(envelope)
        iv, ciphertext = base64.b64decode(document["iv"]), base64.b64decode(document["ciphertext"])
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()

    @staticmethod
    def mac(key: bytes, data: bytes) -> bytes:
        """Give the HMAC-SHA256 of `data`."""
        return hmac.new(key, data, hashlib.sha256).digest()
