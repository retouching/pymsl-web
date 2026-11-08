from typing import Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pydantic import ConfigDict

from pymsl_web.crypto.crypto_context import CryptoContext
from pymsl_web.exceptions import MSLCryptoError
from pymsl_web.utils.messages import message


class ServerCryptoContext(CryptoContext):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    public_key: RSAPublicKey | None

    @classmethod
    def from_pem(cls, pem: bytes | None) -> Self:
        """Build the context of the server from its PEM RSA public key, or without one; raise MSLCryptoError for a
        key that is not a PEM RSA public key."""
        if pem is None:
            return cls(public_key=None)
        try:
            key = serialization.load_pem_public_key(pem)
        except ValueError as error:
            raise MSLCryptoError(message("Server key", "invalid", "a PEM RSA public key expected")) from error
        if not isinstance(key, RSAPublicKey):
            raise MSLCryptoError(message("Server key", "invalid", "a PEM RSA public key expected"))
        return cls(public_key=key)

    def encrypt(self, data: bytes) -> bytes:
        """Give `data` as it is: the server's entity context does not encrypt."""
        return data

    def decrypt(self, data: bytes) -> bytes:
        """Give `data` as it is."""
        return data

    def sign(self, data: bytes) -> bytes:
        """Refuse: the client never signs as the server."""
        raise MSLCryptoError(message("Server key", "unusable", "the client cannot sign as the server"))

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Check the RSASSA-PKCS1-v1_5 SHA-256 `signature` of `data` with the server key; accept any without a key."""
        if self.public_key is None:
            return True
        try:
            self.public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            return False
        return True
