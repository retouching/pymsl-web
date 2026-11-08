import pytest
from pydantic import ValidationError

from pymsl_web.userauth.schemes.netflix_id import NetflixIDUserAuthentication


class TestNetflixIDUserAuthentication:
    def test_writes_cookies(self) -> None:
        """Write the two cookies under their wire names."""
        assert NetflixIDUserAuthentication(netflix_id="a", secure_netflix_id="b").to_wire() == {
            "scheme": "NETFLIXID",
            "authdata": {"netflixid": "a", "securenetflixid": "b"},
        }

    def test_hides_cookies(self) -> None:
        """Keep the cookies out of the representation."""
        assert "secret" not in repr(NetflixIDUserAuthentication(netflix_id="secret", secure_netflix_id="secret"))

    def test_refuses_empty_cookie(self) -> None:
        """Refuse an empty cookie."""
        with pytest.raises(ValidationError):
            NetflixIDUserAuthentication(netflix_id="", secure_netflix_id="b")
