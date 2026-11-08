from typing import Final

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.keyexchange.asymmetric_wrapped.asymmetric_wrapped import AsymmetricWrappedKeyExchange
from pymsl_web.keyexchange.asymmetric_wrapped.asymmetric_wrapped_request import AsymmetricWrappedRequest
from pymsl_web.utils.base64 import decode, encode, encode_url
from pymsl_web.utils.json import JSONObject, dump

ENCRYPTION_JWK: Final[JSONObject] = {
    "kty": "oct",
    "k": encode_url(bytes(range(16))),
    "alg": "A128CBC",
    "extractable": True,
}
HMAC_JWK: Final[JSONObject] = {"kty": "oct", "k": encode_url(b"\x02" * 32), "alg": "HS256", "extractable": True}
SHA1: Final = hashes.SHA1()  # noqa: S303


class TestAsymmetricWrappedKeyExchange:
    @staticmethod
    def public_key(request: AsymmetricWrappedRequest) -> RSAPublicKey:
        """Read the RSA public key a request sends."""
        keydata = request.to_wire()["keydata"]
        assert isinstance(keydata, dict)
        key = load_der_public_key(decode(str(keydata["publickey"]), context="test"))
        assert isinstance(key, RSAPublicKey)
        return key

    @staticmethod
    def wrap(key: RSAPublicKey, jwk: JSONObject, *, algorithm: hashes.HashAlgorithm) -> str:
        """Wrap a JWK as the server does, with RSA-OAEP of `algorithm`."""
        oaep = padding.OAEP(mgf=padding.MGF1(algorithm), algorithm=algorithm, label=None)
        return encode(key.encrypt(dump(jwk), oaep))

    def test_writes_request(self) -> None:
        """Write the key pair ID, JWK_RSA and the SPKI DER of a fresh 2048-bit key."""
        request = AsymmetricWrappedKeyExchange().start()
        wire = request.to_wire()
        assert wire["scheme"] == "ASYMMETRIC_WRAPPED"
        assert isinstance(wire["keydata"], dict)
        assert wire["keydata"]["keypairid"] == "superKeyPair"
        assert wire["keydata"]["mechanism"] == "JWK_RSA"
        assert self.public_key(request).key_size == 2048

    def test_draws_fresh_keys(self) -> None:
        """Draw a new key pair for each handshake."""
        exchange = AsymmetricWrappedKeyExchange()
        assert exchange.start().to_wire() != exchange.start().to_wire()

    def test_unwraps_keys(self) -> None:
        """Give the two keys the server wrapped with RSA-OAEP SHA-1 in JWK JSON."""
        exchange = AsymmetricWrappedKeyExchange()
        request = exchange.start()
        key = self.public_key(request)
        keys = exchange.finish(
            request,
            {
                "keypairid": "superKeyPair",
                "encryptionkey": self.wrap(key, ENCRYPTION_JWK, algorithm=SHA1),
                "hmackey": self.wrap(key, HMAC_JWK, algorithm=SHA1),
            },
        )
        assert keys.encryption == bytes(range(16))
        assert keys.hmac == b"\x02" * 32

    def test_refuses_other_key_pair(self) -> None:
        """Raise MSLMessageError when the answer names another key pair."""
        exchange = AsymmetricWrappedKeyExchange()
        request = exchange.start()
        key = self.public_key(request)
        keydata: JSONObject = {
            "keypairid": "other",
            "encryptionkey": self.wrap(key, ENCRYPTION_JWK, algorithm=SHA1),
            "hmackey": self.wrap(key, HMAC_JWK, algorithm=SHA1),
        }
        with pytest.raises(MSLMessageError, match=r"^Key exchange: invalid"):
            exchange.finish(request, keydata)

    def test_refuses_sha256_wrapping(self) -> None:
        """Raise MSLMessageError for keys wrapped with RSA-OAEP SHA-256, which the server never uses."""
        exchange = AsymmetricWrappedKeyExchange()
        request = exchange.start()
        key = self.public_key(request)
        keydata: JSONObject = {
            "keypairid": "superKeyPair",
            "encryptionkey": self.wrap(key, ENCRYPTION_JWK, algorithm=hashes.SHA256()),
            "hmackey": self.wrap(key, HMAC_JWK, algorithm=hashes.SHA256()),
        }
        with pytest.raises(MSLMessageError, match=r"^Key exchange: invalid"):
            exchange.finish(request, keydata)

    def test_refuses_missing_key(self) -> None:
        """Raise MSLMessageError when the answer lacks the HMAC key."""
        exchange = AsymmetricWrappedKeyExchange()
        request = exchange.start()
        keydata: JSONObject = {
            "keypairid": "superKeyPair",
            "encryptionkey": self.wrap(self.public_key(request), ENCRYPTION_JWK, algorithm=SHA1),
        }
        with pytest.raises(MSLMessageError, match=r"^Key exchange: invalid"):
            exchange.finish(request, keydata)

    def test_refuses_short_key(self) -> None:
        """Raise MSLMessageError when the encryption key is not 16 bytes."""
        exchange = AsymmetricWrappedKeyExchange()
        request = exchange.start()
        key = self.public_key(request)
        short: JSONObject = {"kty": "oct", "k": encode_url(b"\x01" * 8)}
        keydata: JSONObject = {
            "keypairid": "superKeyPair",
            "encryptionkey": self.wrap(key, short, algorithm=SHA1),
            "hmackey": self.wrap(key, HMAC_JWK, algorithm=SHA1),
        }
        with pytest.raises(MSLMessageError, match=r"^Key exchange: invalid"):
            exchange.finish(request, keydata)

    def test_refuses_small_key_size(self) -> None:
        """Refuse an RSA key smaller than 2048 bits."""
        with pytest.raises(ValueError, match="key_size"):
            AsymmetricWrappedKeyExchange(key_size=1024)
