import pytest

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.tokens.service_token import ServiceToken
from tests.unit.support.tokens import Tokens


class TestServiceToken:
    def test_reads_unbound(self) -> None:
        """Read a token bound to nothing as serial numbers -1."""
        token = ServiceToken.parse(Tokens.service_token("cad"))
        assert token.name == "cad"
        assert (token.master_token_serial_number, token.user_id_token_serial_number) == (-1, -1)
        assert not token.is_deletion

    def test_reads_bindings(self) -> None:
        """Read the serial numbers a token is bound to."""
        token = ServiceToken.parse(
            Tokens.service_token("sf", master_token_serial_number=3, user_id_token_serial_number=7)
        )
        assert (token.master_token_serial_number, token.user_id_token_serial_number) == (3, 7)

    def test_tells_deletion(self) -> None:
        """Tell a token sent with empty data, which deletes the token of its name."""
        assert ServiceToken.parse(Tokens.service_token("sf", data="")).is_deletion

    def test_refuses_missing_name(self) -> None:
        """Raise MSLMessageError for a token without a name."""
        with pytest.raises(MSLMessageError, match=r"^Service token: invalid"):
            ServiceToken.parse(Tokens.wire({"servicedata": "AA=="}))
