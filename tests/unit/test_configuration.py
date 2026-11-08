import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from pymsl_web.configuration import MSLConfiguration
from pymsl_web.entityauth.schemes.none import NoneEntityAuthentication
from pymsl_web.enums import CompressionAlgorithm
from pymsl_web.keyexchange.asymmetric_wrapped.asymmetric_wrapped import AsymmetricWrappedKeyExchange


class TestMSLConfiguration:
    @staticmethod
    def build(**changes: object) -> MSLConfiguration:
        """Build a configuration of the web player with `changes`."""
        fields: dict[str, object] = {
            "url": "https://example.com/msl",
            "entity_authentication": NoneEntityAuthentication(identity="ESN"),
            "key_exchange": AsymmetricWrappedKeyExchange(),
        }
        return MSLConfiguration.model_validate({**fields, **changes})

    def test_has_owner_defaults(self) -> None:
        """Default to the values of the owner's working code."""
        configuration = self.build()
        assert configuration.compression is CompressionAlgorithm.GZIP
        assert configuration.compression_algorithms == (CompressionAlgorithm.GZIP,)
        assert configuration.encoder_formats == ("JSON",)
        assert configuration.languages == ()
        assert configuration.renewable is True
        assert configuration.verify_signatures is True
        assert configuration.user_authentication is None

    def test_refuses_extra(self) -> None:
        """Refuse an unknown field."""
        with pytest.raises(ValidationError):
            self.build(sender="ESN")

    def test_refuses_wrong_type(self) -> None:
        """Refuse a value of the wrong type."""
        with pytest.raises(ValidationError):
            self.build(verify_signatures="yes")

    def test_reads_server_keys(self) -> None:
        """Accept server keys as PEM bytes and as Base64 DER text."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        keys = (pem, base64.b64encode(der).decode())
        assert self.build(server_public_keys=keys).server_public_keys == keys

    def test_has_no_server_key_by_default(self) -> None:
        """Default to no server key."""
        assert self.build().server_public_keys == ()

    def test_refuses_bad_key(self) -> None:
        """Refuse a server key that is neither PEM nor Base64 DER of an RSA public key."""
        with pytest.raises(ValidationError, match="Server key"):
            self.build(server_public_keys=(b"not a key",))
