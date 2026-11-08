from typing import ClassVar, Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import Field, ValidationError

from pymsl_web.crypto.jwk import JWK
from pymsl_web.crypto.session_keys import SessionKeys
from pymsl_web.exceptions import MSLMessageError
from pymsl_web.keyexchange.asymmetric_wrapped.asymmetric_wrapped_request import AsymmetricWrappedRequest
from pymsl_web.keyexchange.key_exchange import KeyExchange
from pymsl_web.keyexchange.key_request import KeyRequest
from pymsl_web.utils.base64 import decode
from pymsl_web.utils.json import JSONObject
from pymsl_web.utils.messages import message

SUBJECT: Final = "Key exchange"
PUBLIC_EXPONENT: Final = 65537
MINIMUM_KEY_SIZE: Final = 2048


class AsymmetricWrappedKeyExchange(KeyExchange):
    scheme: ClassVar[str] = "ASYMMETRIC_WRAPPED"

    keypair_id: str = Field(default="superKeyPair", min_length=1)
    key_size: int = Field(default=MINIMUM_KEY_SIZE, ge=MINIMUM_KEY_SIZE)

    def start(self) -> AsymmetricWrappedRequest:
        """Draw a fresh RSA key pair and give the request that sends its public key."""
        private_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=self.key_size)
        return AsymmetricWrappedRequest(keypair_id=self.keypair_id, private_key=private_key)

    def finish(self, request: KeyRequest, keydata: JSONObject) -> SessionKeys:
        """Unwrap the encryption key and the HMAC key the server wrapped with RSA-OAEP SHA-1 in JWK JSON; raise
        MSLMessageError for another key pair, another wrapping or keys of the wrong size."""
        if not isinstance(request, AsymmetricWrappedRequest):
            raise MSLMessageError(message(SUBJECT, "invalid", "an ASYMMETRIC_WRAPPED request expected"))
        if keydata.get("keypairid") != request.keypair_id:
            raise MSLMessageError(message(SUBJECT, "invalid", f"keypairid {request.keypair_id} expected"))
        try:
            return SessionKeys(
                encryption=self.unwrap(request, keydata, "encryptionkey"),
                hmac=self.unwrap(request, keydata, "hmackey"),
            )
        except ValidationError as error:
            raise MSLMessageError(message(SUBJECT, "invalid", "key size")) from error

    @staticmethod
    def unwrap(request: AsymmetricWrappedRequest, keydata: JSONObject, key: str) -> bytes:
        """Decrypt the JWK of the field `key` with the private key of `request` and give its bytes."""
        wrapped = keydata.get(key)
        if not isinstance(wrapped, str):
            raise MSLMessageError(message(SUBJECT, "invalid", f"{key} expected"))
        oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)  # noqa: S303
        try:
            clear = request.private_key.decrypt(decode(wrapped, context=SUBJECT), oaep)
        except ValueError as error:
            raise MSLMessageError(message(SUBJECT, "invalid", f"{key} cannot be unwrapped")) from error
        return JWK.parse(clear).key()
