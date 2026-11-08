from typing import Final, Self

from pydantic import Field, StrictBool, StrictInt, StrictStr

from pymsl_web.compression.compressions import Compressions
from pymsl_web.crypto.crypto_context import CryptoContext
from pymsl_web.enums import CompressionAlgorithm
from pymsl_web.exceptions import MSLCryptoError, MSLMessageError
from pymsl_web.messages.wire_model import WireModel
from pymsl_web.utils.base64 import decode, encode
from pymsl_web.utils.json import JSONObject, JSONValue, dump, load_object
from pymsl_web.utils.messages import message

SUBJECT: Final = "Payload chunk"


class PayloadChunk(WireModel):
    message_id: StrictInt = Field(validation_alias="messageid")
    data: StrictStr
    compression: StrictStr | None = Field(default=None, validation_alias="compressionalgo")
    sequence_number: StrictInt = Field(validation_alias="sequencenumber")
    end_of_message: StrictBool = Field(default=False, validation_alias="endofmsg")

    @classmethod
    def build(cls, data: bytes, *, message_id: int, compression: CompressionAlgorithm | None) -> Self:
        """Build the one chunk of a request, its data compressed with `compression` unless it gives up."""
        compressed = None if compression is None else Compressions.get(compression).compress(data)
        return cls(
            message_id=message_id,
            data=encode(data if compressed is None else compressed),
            compression=None if compressed is None else str(compression),
            sequence_number=1,
            end_of_message=True,
        )

    @classmethod
    def parse(cls, wire: JSONValue, context: CryptoContext, *, verify: bool) -> Self:
        """Read a chunk of an answer: check its signature when `verify`, then decrypt it with `context`; raise
        MSLMessageError for anything else."""
        if not isinstance(wire, dict) or not isinstance(wire.get("payload"), str):
            raise MSLMessageError(message(SUBJECT, "invalid", "payload expected"))
        try:
            payload = decode(str(wire["payload"]), context=SUBJECT)
            signature = decode(str(wire.get("signature", "")), context=SUBJECT)
            if verify and not context.verify(payload, signature):
                raise MSLMessageError(message(SUBJECT, "invalid", "signature"))
            return cls.from_wire(load_object(context.decrypt(payload), context=SUBJECT), subject=SUBJECT)
        except (ValueError, MSLCryptoError) as error:
            raise MSLMessageError(message(SUBJECT, "invalid", str(error))) from error

    def to_wire(self, context: CryptoContext) -> JSONObject:
        """Write the chunk encrypted and signed with `context`, its fields in the order of the owner's code."""
        inner: JSONObject = {"messageid": self.message_id, "data": self.data}
        if self.compression is not None:
            inner["compressionalgo"] = self.compression
        inner["sequencenumber"] = self.sequence_number
        inner["endofmsg"] = self.end_of_message
        payload = context.encrypt(dump(inner))
        return {"payload": encode(payload), "signature": encode(context.sign(payload))}

    def content(self) -> bytes:
        """Give the data of the chunk, decompressed; raise MSLMessageError for data that cannot be read."""
        try:
            data = decode(self.data, context=SUBJECT)
        except ValueError as error:
            raise MSLMessageError(str(error)) from error
        if self.compression is None or self.compression == "":
            return data
        return Compressions.get(self.compression).decompress(data)
