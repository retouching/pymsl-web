import pytest
from hypothesis import given
from hypothesis import strategies as st

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.tokens.master_token import MasterToken
from tests.unit.support.tokens import Tokens


class TestMasterToken:
    def test_reads_fields(self) -> None:
        """Read the dates and numbers of the clear `tokendata`, in seconds."""
        token = MasterToken.parse(
            Tokens.master_token(sequence_number=25, serial_number=3, renewal_window=1000, expiration=2000)
        )
        assert (token.sequence_number, token.serial_number) == (25, 3)
        assert (token.renewal_window, token.expiration) == (1000, 2000)

    def test_keeps_wire(self) -> None:
        """Give back the token exactly as received."""
        wire = Tokens.master_token()
        assert MasterToken.parse(wire).data.to_wire() == wire

    def test_tells_renewable(self) -> None:
        """Tell renewable from `renewalwindow`."""
        token = MasterToken.parse(Tokens.master_token(renewal_window=1000, expiration=2000))
        assert not token.is_renewable(999)
        assert token.is_renewable(1000)

    def test_tells_expired(self) -> None:
        """Tell expired from `expiration`."""
        token = MasterToken.parse(Tokens.master_token(renewal_window=1000, expiration=2000))
        assert not token.is_expired(1999)
        assert token.is_expired(2000)

    def test_refuses_missing_field(self) -> None:
        """Raise MSLMessageError for a token without its sequence number."""
        wire = Tokens.wire({"renewalwindow": 1, "expiration": 2, "serialnumber": 3})
        with pytest.raises(MSLMessageError, match=r"^Master token: invalid"):
            MasterToken.parse(wire)

    def test_refuses_boolean_number(self) -> None:
        """Raise MSLMessageError for a number written as a boolean."""
        wire = Tokens.wire({"renewalwindow": 1, "expiration": 2, "serialnumber": 3, "sequencenumber": True})
        with pytest.raises(MSLMessageError, match=r"^Master token: invalid"):
            MasterToken.parse(wire)

    @given(st.one_of(st.dictionaries(st.text(), st.text()), st.text(), st.none(), st.integers()))
    def test_refuses_garbage(self, wire: object) -> None:
        """Raise MSLMessageError, and nothing else, for any malformed token."""
        with pytest.raises(MSLMessageError):
            MasterToken.parse(wire)  # type: ignore[arg-type]
