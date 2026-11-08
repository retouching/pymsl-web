from collections.abc import Iterable
from typing import Final, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pydantic import ConfigDict

from pymsl_web.crypto.crypto_context import CryptoContext
from pymsl_web.exceptions import MSLCryptoError
from pymsl_web.utils.base64 import decode
from pymsl_web.utils.messages import message

SUBJECT: Final = "Server key"
PEM_PREFIX: Final = b"-----BEGIN"


class ServerCryptoContext(CryptoContext):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    public_keys: tuple[RSAPublicKey, ...]

    @classmethod
    def from_keys(cls, keys: Iterable[str | bytes]) -> Self:
        """Build the context of the server from its RSA public keys, each PEM or Base64 SPKI DER, or without any;
        raise MSLCryptoError for a key that is neither."""
        return cls(public_keys=tuple(cls.read_key(key) for key in keys))

    @staticmethod
    def read_key(key: str | bytes) -> RSAPublicKey:
        """Read one RSA public key, PEM or Base64 SPKI DER; raise MSLCryptoError for anything else."""
        text = key.encode() if isinstance(key, str) else key
        try:
            if text.lstrip().startswith(PEM_PREFIX):
                public_key = serialization.load_pem_public_key(text)
            else:
                public_key = serialization.load_der_public_key(decode(text.decode("ascii").strip(), context=SUBJECT))
        except (ValueError, UnicodeDecodeError) as error:
            raise MSLCryptoError(message(SUBJECT, "invalid", "a PEM or Base64 DER RSA public key expected")) from error
        if not isinstance(public_key, RSAPublicKey):
            raise MSLCryptoError(message(SUBJECT, "invalid", "a PEM or Base64 DER RSA public key expected"))
        return public_key

    def encrypt(self, data: bytes) -> bytes:
        """Give `data` as it is: the server's entity context does not encrypt."""
        return data

    def decrypt(self, data: bytes) -> bytes:
        """Give `data` as it is."""
        return data

    def sign(self, data: bytes) -> bytes:
        """Refuse: the client never signs as the server."""
        raise MSLCryptoError(message(SUBJECT, "unusable", "the client cannot sign as the server"))

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Tell whether one of the server keys verifies the RSASSA-PKCS1-v1_5 SHA-256 `signature` of `data`; accept
        any signature without a key."""
        return not self.public_keys or any(self.verifies(key, data, signature) for key in self.public_keys)

    @staticmethod
    def verifies(key: RSAPublicKey, data: bytes, signature: bytes) -> bool:
        """Tell whether `key` verifies `signature` of `data`."""
        try:
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            return False
        return True
