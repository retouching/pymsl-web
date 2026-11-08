from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from pymsl_web.crypto.session_keys import SessionKeys
from pymsl_web.keyexchange.key_request import KeyRequest
from pymsl_web.utils.json import JSONObject


class KeyExchange(ABC, BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    scheme: ClassVar[str]

    @abstractmethod
    def start(self) -> KeyRequest:
        """Begin an exchange: give the request to send, which keeps what the answer needs."""

    @abstractmethod
    def finish(self, request: KeyRequest, keydata: JSONObject) -> SessionKeys:
        """Give the session keys of the server's `keydata` answering `request`; raise MSLMessageError for an answer
        that does not match."""
