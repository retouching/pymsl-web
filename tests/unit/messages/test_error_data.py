import pytest

from pymsl_web.enums import MSLResponseCode
from pymsl_web.exceptions import MSLMessageError
from pymsl_web.messages.error_data import ErrorData


class TestErrorData:
    def test_gives_error(self) -> None:
        """Give the MSLError of the code, the internal code and the messages."""
        error = ErrorData.parse(
            {"messageid": 8, "errorcode": 7, "internalcode": 101, "errormsg": "No user", "usermsg": "Sign in"}
        ).to_error()
        assert error.code is MSLResponseCode.USERDATA_REAUTH
        assert error.internal_code == 101
        assert error.error_message == "No user"
        assert error.user_message == "Sign in"
        assert error.message_id == 8

    def test_refuses_missing_code(self) -> None:
        """Raise MSLMessageError for an error without its code."""
        with pytest.raises(MSLMessageError, match=r"^Error header: invalid"):
            ErrorData.parse({"messageid": 8})
