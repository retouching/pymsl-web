from typing import Self

from pydantic import Field, StrictBool, StrictInt, StrictStr

from pymsl_web.messages.capabilities import MessageCapabilities
from pymsl_web.messages.wire_model import WireModel
from pymsl_web.utils.json import JSONObject, JSONValue


class HeaderData(WireModel):
    message_id: StrictInt = Field(validation_alias="messageid")
    renewable: StrictBool = False
    handshake: StrictBool = False
    capabilities: MessageCapabilities = Field(default_factory=MessageCapabilities)
    timestamp: StrictInt | None = None
    sender: StrictStr | None = None
    non_replayable: StrictBool = Field(default=False, validation_alias="nonreplayable")
    user_authentication: JSONObject | None = Field(default=None, validation_alias="userauthdata")
    key_request: JSONObject | None = None
    user_id_token: JSONObject | None = Field(default=None, validation_alias="useridtoken")
    service_tokens: list[JSONValue] = Field(default_factory=list, validation_alias="servicetokens")
    key_response: JSONObject | None = Field(default=None, validation_alias="keyresponsedata")

    @classmethod
    def parse(cls, wire: JSONValue) -> Self:
        """Read the clear fields of a header; raise MSLMessageError for anything else."""
        return cls.from_wire(wire, subject="Header")

    def to_wire(self) -> JSONObject:
        """Write the fields in the order of the owner's working code, without the absent ones."""
        wire: JSONObject = {
            "messageid": self.message_id,
            "renewable": self.renewable,
            "handshake": self.handshake,
            "capabilities": self.capabilities.to_wire(),
        }
        if self.timestamp is not None:
            wire["timestamp"] = self.timestamp
        if self.sender is not None:
            wire["sender"] = self.sender
        wire["nonreplayable"] = self.non_replayable
        if self.user_authentication is not None:
            wire["userauthdata"] = self.user_authentication
        if self.key_request is not None:
            wire["keyrequestdata"] = [self.key_request]
        if self.user_id_token is not None:
            wire["useridtoken"] = self.user_id_token
        if self.service_tokens:
            wire["servicetokens"] = self.service_tokens
        return wire
