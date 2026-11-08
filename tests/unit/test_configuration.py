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

    def test_reads_server_key(self) -> None:
        """Accept a PEM RSA public key of the server."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        assert self.build(server_public_key=pem).server_public_key == pem

    def test_refuses_bad_key(self) -> None:
        """Refuse a server key that is not a PEM RSA public key."""
        with pytest.raises(ValidationError, match="Server key"):
            self.build(server_public_key=b"not a key")
