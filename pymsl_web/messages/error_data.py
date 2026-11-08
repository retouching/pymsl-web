from typing import Self

from pydantic import Field, StrictInt, StrictStr

from pymsl_web.exceptions import MSLError
from pymsl_web.messages.wire_model import WireModel
from pymsl_web.utils.json import JSONValue


class ErrorData(WireModel):
    message_id: StrictInt | None = Field(default=None, validation_alias="messageid")
    code: StrictInt = Field(validation_alias="errorcode")
    internal_code: StrictInt | None = Field(default=None, validation_alias="internalcode")
    error_message: StrictStr | None = Field(default=None, validation_alias="errormsg")
    user_message: StrictStr | None = Field(default=None, validation_alias="usermsg")
    timestamp: StrictInt | None = None

    @classmethod
    def parse(cls, wire: JSONValue) -> Self:
        """Read the clear fields of an error header; raise MSLMessageError for anything else."""
        return cls.from_wire(wire, subject="Error header")

    def to_error(self) -> MSLError:
        """Give the MSLError the server answered."""
        return MSLError(
            self.code,
            internal_code=self.internal_code,
            error_message=self.error_message,
            user_message=self.user_message,
            message_id=self.message_id,
        )
