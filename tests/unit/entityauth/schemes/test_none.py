import pytest
from pydantic import ValidationError

from pymsl_web.crypto.null_crypto_context import NullCryptoContext
from pymsl_web.entityauth.schemes.none import NoneEntityAuthentication


class TestNoneEntityAuthentication:
    def test_writes_identity(self) -> None:
        """Write the scheme and the identity as the web player does."""
        assert NoneEntityAuthentication(identity="ESN").to_wire() == {
            "scheme": "NONE",
            "authdata": {"identity": "ESN"},
        }

    def test_gives_identity(self) -> None:
        """Give the identity as the sender of the messages."""
        assert NoneEntityAuthentication(identity="ESN").identity() == "ESN"

    def test_does_not_encrypt(self) -> None:
        """Give the null crypto context: the handshake header goes out in clear."""
        assert isinstance(NoneEntityAuthentication(identity="ESN").crypto_context(), NullCryptoContext)

    def test_refuses_empty_identity(self) -> None:
        """Refuse an empty identity."""
        with pytest.raises(ValidationError):
            NoneEntityAuthentication(identity="")

    def test_refuses_extra(self) -> None:
        """Refuse a field the scheme does not have."""
        with pytest.raises(ValidationError):
            NoneEntityAuthentication(identity="ESN", suffix="x")  # type: ignore[call-arg]
