import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pymsl_web.crypto.ciphertext_envelope import CiphertextEnvelope
from pymsl_web.exceptions import MSLMessageError


class TestCiphertextEnvelope:
    def test_writes_in_order(self) -> None:
        """Write the fields in the order of the owner's working code, with the dummy sha256."""
        envelope = CiphertextEnvelope(key_id="ESN_25", iv=b"\x00" * 16, ciphertext=b"\x01")
        assert envelope.to_json() == (
            b'{"ciphertext":"AQ==","keyid":"ESN_25","sha256":"AA==","iv":"AAAAAAAAAAAAAAAAAAAAAA=="}'
        )

    def test_reads_version_1(self) -> None:
        """Read the V1 envelope it wrote."""
        envelope = CiphertextEnvelope(key_id="ESN_25", iv=b"\x02" * 16, ciphertext=b"\x01\x02")
        assert CiphertextEnvelope.parse(envelope.to_json()) == envelope

    def test_reads_version_2(self) -> None:
        """Read a V2 envelope, which has no key ID."""
        data = b'{"version":2,"cipherspec":"AES/CBC/PKCS5Padding","iv":"AAAAAAAAAAAAAAAAAAAAAA==","ciphertext":"AQ=="}'
        envelope = CiphertextEnvelope.parse(data)
        assert envelope.ciphertext == b"\x01"
        assert envelope.key_id == ""

    def test_refuses_other_cipher(self) -> None:
        """Raise MSLMessageError for a V2 envelope of another cipher."""
        data = b'{"version":2,"cipherspec":"RSA/ECB/OAEP","iv":"AAAAAAAAAAAAAAAAAAAAAA==","ciphertext":"AQ=="}'
        with pytest.raises(MSLMessageError, match=r"^Ciphertext envelope: invalid"):
            CiphertextEnvelope.parse(data)

    def test_refuses_missing_iv(self) -> None:
        """Raise MSLMessageError for an envelope without its IV."""
        with pytest.raises(MSLMessageError, match=r"^Ciphertext envelope: invalid"):
            CiphertextEnvelope.parse(b'{"ciphertext":"AQ==","keyid":"x","sha256":"AA=="}')

    def test_tells_envelope(self) -> None:
        """Tell an envelope from clear header JSON."""
        assert CiphertextEnvelope.is_envelope(b'{"ciphertext":"AQ==","keyid":"x","iv":"AA=="}')
        assert not CiphertextEnvelope.is_envelope(b'{"messageid":1}')
        assert not CiphertextEnvelope.is_envelope(b"not json")

    @given(st.binary())
    def test_refuses_garbage(self, data: bytes) -> None:
        """Raise MSLMessageError, and nothing else, for any bytes that are not an envelope."""
        with contextlib.suppress(MSLMessageError):
            CiphertextEnvelope.parse(data)
