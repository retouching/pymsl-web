from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from pymsl_web.crypto.crypto_context import CryptoContext
from pymsl_web.utils.json import JSONObject


class EntityAuthentication(ABC, BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    scheme: ClassVar[str]

    @abstractmethod
    def identity(self) -> str:
        """Give the identity of the entity, the sender of the messages."""

    @abstractmethod
    def authdata(self) -> JSONObject:
        """Give the `authdata` of the scheme."""

    @abstractmethod
    def crypto_context(self) -> CryptoContext:
        """Give the context that protects a header sent before any master token."""

    def to_wire(self) -> JSONObject:
        """Write the entity authentication data of a handshake."""
        return {"scheme": self.scheme, "authdata": self.authdata()}
