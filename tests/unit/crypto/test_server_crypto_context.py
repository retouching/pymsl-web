import base64

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pymsl_web.crypto.server_crypto_context import ServerCryptoContext
from pymsl_web.exceptions import MSLCryptoError

SERVER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class TestServerCryptoContext:
    @staticmethod
    def pem(key: rsa.RSAPrivateKey) -> bytes:
        """Give the PEM of the public key of `key`."""
        return key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def der_base64(key: rsa.RSAPrivateKey) -> str:
        """Give the Base64 SPKI DER of the public key of `key`, as Netflix publishes it."""
        der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(der).decode()

    @staticmethod
    def signature(key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        """Sign `data` as the server does."""
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    def test_verifies_with_pem(self) -> None:
        """Accept an RSASSA-PKCS1-v1_5 SHA-256 signature of a PEM key and refuse another."""
        context = ServerCryptoContext.from_keys((self.pem(SERVER_KEY),))
        signature = self.signature(SERVER_KEY, b"header")
        assert context.verify(b"header", signature)
        assert not context.verify(b"headeR", signature)
        assert not context.verify(b"header", b"")

    def test_verifies_with_base64_der(self) -> None:
        """Accept a key given as Base64 SPKI DER, as text or as bytes."""
        signature = self.signature(SERVER_KEY, b"header")
        assert ServerCryptoContext.from_keys((self.der_base64(SERVER_KEY),)).verify(b"header", signature)
        assert ServerCryptoContext.from_keys((self.der_base64(SERVER_KEY).encode(),)).verify(b"header", signature)

    def test_verifies_with_any_key(self) -> None:
        """Accept a signature that one of several keys verifies."""
        context = ServerCryptoContext.from_keys((self.der_base64(OTHER_KEY), self.pem(SERVER_KEY)))
        assert context.verify(b"header", self.signature(SERVER_KEY, b"header"))
        assert context.verify(b"header", self.signature(OTHER_KEY, b"header"))

    def test_refuses_unknown_key(self) -> None:
        """Refuse a signature that none of the keys verifies."""
        context = ServerCryptoContext.from_keys((self.der_base64(OTHER_KEY),))
        assert not context.verify(b"header", self.signature(SERVER_KEY, b"header"))

    def test_accepts_without_key(self) -> None:
        """Accept any signature when no server key is configured."""
        assert ServerCryptoContext.from_keys(()).verify(b"header", b"anything")

    def test_reads_clear(self) -> None:
        """Give the data back as it is: the server's entity context does not encrypt."""
        assert ServerCryptoContext.from_keys(()).decrypt(b"clear") == b"clear"

    def test_refuses_to_sign(self) -> None:
        """Raise MSLCryptoError: the client never signs as the server."""
        with pytest.raises(MSLCryptoError):
            ServerCryptoContext.from_keys(()).sign(b"header")

    @pytest.mark.parametrize(
        "key",
        [b"not a key", "not a key", "AAEC", b"-----BEGIN PUBLIC KEY-----\nAAEC\n"],
        ids=["bytes", "text", "short der", "bad pem"],
    )
    def test_refuses_bad_key(self, key: str | bytes) -> None:
        """Raise MSLCryptoError for a key that is neither PEM nor Base64 DER of an RSA public key."""
        with pytest.raises(MSLCryptoError, match=r"^Server key: invalid"):
            ServerCryptoContext.from_keys((key,))
