from typing import Self

from pydantic import BaseModel, ConfigDict

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.utils.base64 import decode
from pymsl_web.utils.json import JSONObject, JSONValue, load_object
from pymsl_web.utils.messages import message


class TokenData(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    tokendata: str
    signature: str

    @classmethod
    def parse(cls, wire: JSONValue, *, subject: str) -> Self:
        """Keep a token as received, `{"tokendata", "signature"}`; raise MSLMessageError naming `subject` for
        anything else."""
        if not isinstance(wire, dict):
            raise MSLMessageError(message(subject, "invalid", "an object expected"))
        tokendata, signature = wire.get("tokendata"), wire.get("signature")
        if not isinstance(tokendata, str) or not isinstance(signature, str):
            raise MSLMessageError(message(subject, "invalid", "tokendata and signature expected"))
        return cls(tokendata=tokendata, signature=signature)

    def to_wire(self) -> JSONObject:
        """Give the token as the server sent it."""
        return {"tokendata": self.tokendata, "signature": self.signature}

    def fields(self, *, subject: str) -> JSONObject:
        """Read the clear JSON of `tokendata`; raise MSLMessageError naming `subject` when it is not."""
        try:
            return load_object(decode(self.tokendata, context=subject), context=subject)
        except ValueError as error:
            raise MSLMessageError(message(subject, "invalid", "tokendata")) from error

    @staticmethod
    def integer(fields: JSONObject, key: str, *, subject: str, default: int | None = None) -> int:
        """Read the integer `key` of `fields`, or `default` when it is absent; raise MSLMessageError naming `subject`
        for a missing key or a value that is not an integer."""
        value = fields.get(key)
        if value is None and default is not None:
            return default
        if not isinstance(value, int) or isinstance(value, bool):
            raise MSLMessageError(message(subject, "invalid", f"{key} expected"))
        return value
