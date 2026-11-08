from abc import ABC, abstractmethod

from pydantic import BaseModel

from pymsl_web.utils.json import JSONObject


class KeyRequest(ABC, BaseModel):
    @abstractmethod
    def to_wire(self) -> JSONObject:
        """Write the key request data of a handshake."""
