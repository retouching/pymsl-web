from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from pymsl_web.utils.json import JSONObject


class UserAuthentication(ABC, BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    scheme: ClassVar[str]

    @abstractmethod
    def authdata(self) -> JSONObject:
        """Give the `authdata` of the scheme."""

    def to_wire(self) -> JSONObject:
        """Write the user authentication data of a request."""
        return {"scheme": self.scheme, "authdata": self.authdata()}
