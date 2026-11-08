import pytest

from pymsl_web.crypto.jwk import JWK
from pymsl_web.exceptions import MSLMessageError


class TestJWK:
    def test_gives_key(self) -> None:
        """Give the bytes of `k`, base64url without padding, as the server sends them."""
        jwk = JWK.parse(
            b'{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw","alg":"A128CBC","key_ops":["encrypt","decrypt"],'
            b'"extractable":true}'
        )
        assert jwk.key() == bytes(range(16))
        assert jwk.alg == "A128CBC"

    def test_ignores_unknown_fields(self) -> None:
        """Read a JWK that carries fields MSL does not name."""
        assert JWK.parse(b'{"kty":"oct","k":"AQ","kid":"x"}').key() == b"\x01"

    def test_refuses_other_type(self) -> None:
        """Raise MSLMessageError for a JWK that is not `oct`."""
        with pytest.raises(MSLMessageError, match=r"^JWK: invalid"):
            JWK.parse(b'{"kty":"RSA","k":"AQ"}')

    def test_refuses_missing_key(self) -> None:
        """Raise MSLMessageError for a JWK without `k`."""
        with pytest.raises(MSLMessageError, match=r"^JWK: invalid"):
            JWK.parse(b'{"kty":"oct"}')

    def test_refuses_bad_key(self) -> None:
        """Raise MSLMessageError for a `k` that is not base64url."""
        with pytest.raises(MSLMessageError, match=r"^JWK: invalid"):
            JWK.parse(b'{"kty":"oct","k":"@@"}').key()
