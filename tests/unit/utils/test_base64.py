import pytest
from hypothesis import given
from hypothesis import strategies as st

from pymsl_web.utils.base64 import decode, decode_url, encode, encode_url


class TestBase64:
    def test_encodes_with_padding(self) -> None:
        """Write standard Base64 with its padding."""
        assert encode(b"\x00\x01") == "AAE="

    def test_decodes_without_padding(self) -> None:
        """Decode standard Base64 whose padding is missing."""
        assert decode("AAE", context="Token") == b"\x00\x01"

    def test_decodes_url_without_padding(self) -> None:
        """Decode base64url without its padding, as the JWK `k` of the server."""
        assert decode_url("AAEC", context="JWK") == b"\x00\x01\x02"
        assert decode_url("_-8", context="JWK") == b"\xff\xef"

    def test_encodes_url_without_padding(self) -> None:
        """Write base64url without its padding."""
        assert encode_url(b"\xff\xef") == "_-8"

    def test_refuses_garbage(self) -> None:
        """Raise ValueError naming the context for a text that is not Base64."""
        with pytest.raises(ValueError, match=r"^JWK: invalid"):
            decode("@@@", context="JWK")

    def test_refuses_url_alphabet_in_standard(self) -> None:
        """Refuse the base64url alphabet where standard Base64 is expected."""
        with pytest.raises(ValueError, match=r"^Token: invalid"):
            decode("_-8", context="Token")

    @given(st.binary())
    def test_round_trips(self, data: bytes) -> None:
        """Give back the bytes it encoded."""
        assert decode(encode(data), context="test") == data
        assert decode_url(encode_url(data), context="test") == data
