from pymsl_web.enums import MSLResponseCode
from pymsl_web.exceptions import MSLError, MSLMessageError, PyMSLError


class TestMSLError:
    def test_keeps_fields(self) -> None:
        """Keep the code as an MSLResponseCode and the details of the server."""
        error = MSLError(4, internal_code=101, error_message="Expired", user_message=None, message_id=9)
        assert error.code is MSLResponseCode.USER_REAUTH
        assert (error.internal_code, error.error_message, error.user_message, error.message_id) == (
            101,
            "Expired",
            None,
            9,
        )

    def test_writes_message(self) -> None:
        """Write the name of the code, the server's message and the internal code."""
        error = MSLError(4, internal_code=101, error_message="Expired", user_message=None, message_id=9)
        assert str(error) == "MSL: error USER_REAUTH (Expired, internal 101)"

    def test_keeps_unknown_code(self) -> None:
        """Keep a code MSL does not define as its number."""
        error = MSLError(42, internal_code=None, error_message=None, user_message=None, message_id=None)
        assert error.code == 42
        assert str(error) == "MSL: error 42"

    def test_derives_from_base(self) -> None:
        """Derive every error of pymsl from PyMSLError."""
        assert issubclass(MSLError, PyMSLError)
        assert issubclass(MSLMessageError, PyMSLError)
