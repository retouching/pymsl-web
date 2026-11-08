import pytest

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.tokens.master_token import MasterToken
from pymsl_web.tokens.user_id_token import UserIDToken
from tests.unit.support.tokens import Tokens


class TestUserIDToken:
    def test_reads_profile(self) -> None:
        """Read the `profileid` the web service adds."""
        assert UserIDToken.parse(Tokens.user_id_token(profile_id="SF2I")).profile_id == "SF2I"

    def test_reads_without_profile(self) -> None:
        """Read a token of the reference, without `profileid`."""
        assert UserIDToken.parse(Tokens.user_id_token(profile_id=None)).profile_id is None

    def test_tells_binding(self) -> None:
        """Tell whether the token belongs to a master token by its serial number."""
        token = UserIDToken.parse(Tokens.user_id_token(master_token_serial_number=3))
        assert token.is_bound_to(MasterToken.parse(Tokens.master_token(serial_number=3)))
        assert not token.is_bound_to(MasterToken.parse(Tokens.master_token(serial_number=4)))

    def test_keeps_wire(self) -> None:
        """Give back the token exactly as received."""
        wire = Tokens.user_id_token()
        assert UserIDToken.parse(wire).data.to_wire() == wire

    def test_refuses_missing_field(self) -> None:
        """Raise MSLMessageError for a token without its master token serial number."""
        with pytest.raises(MSLMessageError, match=r"^User ID token: invalid"):
            UserIDToken.parse(Tokens.wire({"renewalwindow": 1, "expiration": 2, "serialnumber": 3}))
