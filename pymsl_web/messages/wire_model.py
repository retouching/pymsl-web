from typing import Self

from pydantic import BaseModel, ConfigDict, ValidationError

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.utils.json import JSONValue
from pymsl_web.utils.messages import message


class WireModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", validate_by_name=True, validate_by_alias=True)

    @classmethod
    def from_wire(cls, wire: JSONValue, *, subject: str) -> Self:
        """Read the fields of `wire` by their wire names; raise MSLMessageError naming `subject` and the first bad
        field for anything else."""
        if not isinstance(wire, dict):
            raise MSLMessageError(message(subject, "invalid", "an object expected"))
        try:
            return cls.model_validate(wire)
        except ValidationError as error:
            location = ".".join(str(part) for part in error.errors()[0]["loc"])
            raise MSLMessageError(message(subject, "invalid", location)) from error
