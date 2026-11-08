import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pymsl_web.crypto.server_crypto_context import ServerCryptoContext
from pymsl_web.exceptions import MSLCryptoError

SERVER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = SERVER_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


class TestServerCryptoContext:
    def test_verifies_with_key(self) -> None:
        """Accept an RSASSA-PKCS1-v1_5 SHA-256 signature of the server key and refuse another."""
        context = ServerCryptoContext.from_pem(PEM)
        signature = SERVER_KEY.sign(b"header", padding.PKCS1v15(), hashes.SHA256())
        assert context.verify(b"header", signature)
        assert not context.verify(b"headeR", signature)
        assert not context.verify(b"header", b"")

    def test_accepts_without_key(self) -> None:
        """Accept any signature when no server key is configured."""
        assert ServerCryptoContext.from_pem(None).verify(b"header", b"anything")

    def test_reads_clear(self) -> None:
        """Give the data back as it is: the server's entity context does not encrypt."""
        assert ServerCryptoContext.from_pem(None).decrypt(b"clear") == b"clear"

    def test_refuses_to_sign(self) -> None:
        """Raise MSLCryptoError: the client never signs as the server."""
        with pytest.raises(MSLCryptoError):
            ServerCryptoContext.from_pem(None).sign(b"header")

    def test_refuses_bad_pem(self) -> None:
        """Raise MSLCryptoError for a key that is not a PEM RSA public key."""
        with pytest.raises(MSLCryptoError, match=r"^Server key: invalid"):
            ServerCryptoContext.from_pem(b"not a key")
