from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pydantic import ConfigDict, Field

from pymsl_web.keyexchange.key_request import KeyRequest
from pymsl_web.utils.base64 import encode
from pymsl_web.utils.json import JSONObject

MECHANISM: Final = "JWK_RSA"


class AsymmetricWrappedRequest(KeyRequest):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    keypair_id: str
    private_key: RSAPrivateKey = Field(repr=False)

    def to_wire(self) -> JSONObject:
        """Write the key pair ID, the JWK_RSA mechanism and the SPKI DER of the public key, as the web player does."""
        public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {
            "scheme": "ASYMMETRIC_WRAPPED",
            "keydata": {"keypairid": self.keypair_id, "mechanism": MECHANISM, "publickey": encode(public_key)},
        }
