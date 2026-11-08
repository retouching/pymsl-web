from typing import Self

from pydantic import Field, StrictInt, StrictStr

from pymsl_web.messages.wire_model import WireModel
from pymsl_web.utils.json import JSONObject, JSONValue


class MessageCapabilities(WireModel):
    compression_algorithms: tuple[StrictStr, ...] = Field(default=(), validation_alias="compressionalgos")
    languages: tuple[StrictStr, ...] = ()
    encoder_formats: tuple[StrictStr, ...] = Field(default=(), validation_alias="encoderformats")
    max_payload_chunk_size: StrictInt | None = Field(default=None, validation_alias="maxpayloadchunksize")

    @classmethod
    def parse(cls, wire: JSONValue) -> Self:
        """Read the capabilities of a header; raise MSLMessageError for anything else."""
        return cls.from_wire(wire, subject="Capabilities")

    def to_wire(self) -> JSONObject:
        """Write the capabilities in the order of the owner's working code."""
        return {
            "compressionalgos": list(self.compression_algorithms),
            "languages": list(self.languages),
            "encoderformats": list(self.encoder_formats),
        }
