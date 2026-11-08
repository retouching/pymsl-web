import pytest
from pydantic import ValidationError

from pymsl_web.crypto.session_keys import SessionKeys


class TestSessionKeys:
    def test_keeps_keys(self) -> None:
        """Keep a 16-byte encryption key and a 32-byte HMAC key."""
        keys = SessionKeys(encryption=b"\x01" * 16, hmac=b"\x02" * 32)
        assert keys.encryption == b"\x01" * 16

    def test_refuses_short_encryption_key(self) -> None:
        """Refuse an encryption key that is not 16 bytes."""
        with pytest.raises(ValidationError):
            SessionKeys(encryption=b"\x01" * 15, hmac=b"\x02" * 32)

    def test_refuses_short_hmac_key(self) -> None:
        """Refuse an HMAC key that is not 32 bytes."""
        with pytest.raises(ValidationError):
            SessionKeys(encryption=b"\x01" * 16, hmac=b"\x02" * 31)

    def test_hides_keys(self) -> None:
        """Keep the keys out of the representation."""
        assert "\\x01" not in repr(SessionKeys(encryption=b"\x01" * 16, hmac=b"\x01" * 32))
