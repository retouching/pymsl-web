from pymsl_web.enums import MSLResponseCode
from pymsl_web.utils.messages import message


class PyMSLError(Exception):
    pass


class MSLTransportError(PyMSLError):
    pass


class MSLMessageError(PyMSLError):
    pass


class MSLCryptoError(PyMSLError):
    pass


class MSLSessionError(PyMSLError):
    pass


class MSLError(PyMSLError):
    def __init__(
        self,
        code: MSLResponseCode | int,
        *,
        internal_code: int | None,
        error_message: str | None,
        user_message: str | None,
        message_id: int | None,
    ) -> None:
        """Keep the error the server answered: its response code, its internal code and its messages."""
        self.code: MSLResponseCode | int = (
            MSLResponseCode(code) if code in MSLResponseCode.__members__.values() else code
        )
        self.internal_code = internal_code
        self.error_message = error_message
        self.user_message = user_message
        self.message_id = message_id
        name = self.code.name if isinstance(self.code, MSLResponseCode) else str(self.code)
        internal = f"internal {internal_code}" if internal_code is not None else ""
        super().__init__(message("MSL", f"error {name}", error_message or "", internal))
