from typing import Final

from pydantic import BaseModel, ConfigDict

from pymsl_web.crypto.ciphertext_envelope import CiphertextEnvelope
from pymsl_web.crypto.server_crypto_context import ServerCryptoContext
from pymsl_web.crypto.session_crypto_context import SessionCryptoContext
from pymsl_web.exceptions import MSLCryptoError, MSLMessageError
from pymsl_web.messages.answer import Answer
from pymsl_web.messages.error_data import ErrorData
from pymsl_web.messages.header_data import HeaderData
from pymsl_web.messages.payload_chunk import PayloadChunk
from pymsl_web.tokens.master_token import MasterToken
from pymsl_web.utils.base64 import decode
from pymsl_web.utils.json import JSONObject, load_object, split_objects
from pymsl_web.utils.messages import message

SUBJECT: Final = "Answer"


class MessageReader(BaseModel):
    model_config = ConfigDict(frozen=True)

    server: ServerCryptoContext
    verify_signatures: bool

    def read(self, body: bytes, *, session: SessionCryptoContext | None, request_message_id: int) -> Answer:
        """Read the answer to the request of `request_message_id`: raise the MSLError of an error header, else check
        and decrypt the header and the chunks and give their joined data; raise MSLMessageError for an answer that is
        malformed, wrongly signed or out of sequence."""
        try:
            objects = split_objects(body, context=SUBJECT)
        except ValueError as error:
            raise MSLMessageError(str(error)) from error
        if not objects:
            raise MSLMessageError(message(SUBJECT, "empty"))
        outer, chunks = objects[0], objects[1:]
        try:
            if "errordata" in outer:
                raise ErrorData.parse(self.open(outer, "errordata", session)).to_error()
            if "headerdata" not in outer:
                raise MSLMessageError(message(SUBJECT, "invalid", "headerdata or errordata expected"))
            header = HeaderData.parse(self.open(outer, "headerdata", session))
            master_token = MasterToken.parse(outer["mastertoken"]) if "mastertoken" in outer else None
        except MSLCryptoError as error:
            raise MSLMessageError(message(SUBJECT, "invalid", str(error))) from error
        if header.message_id != request_message_id + 1:
            raise MSLMessageError(
                message(SUBJECT, "invalid", f"message ID {header.message_id}, {request_message_id + 1} expected")
            )
        return Answer(header=header, data=self.join(chunks, header, session), master_token=master_token)

    def open(self, outer: JSONObject, key: str, session: SessionCryptoContext | None) -> JSONObject:
        """Give the clear JSON of the field `key` of a header: an envelope is checked and decrypted with the
        session, clear JSON is checked with the server's key."""
        try:
            protected = decode(str(outer[key]), context=SUBJECT)
            signature = decode(str(outer.get("signature", "")), context=SUBJECT)
        except ValueError as error:
            raise MSLMessageError(str(error)) from error
        if CiphertextEnvelope.is_envelope(protected):
            if session is None:
                raise MSLMessageError(message(SUBJECT, "invalid", "an encrypted header without a session"))
            if self.verify_signatures and not session.verify(protected, signature):
                raise MSLMessageError(message(SUBJECT, "invalid", "header signature"))
            clear = session.decrypt(protected)
        else:
            if not self.server.verify(protected, signature):
                raise MSLMessageError(message(SUBJECT, "invalid", "server signature"))
            clear = protected
        try:
            return load_object(clear, context=SUBJECT)
        except ValueError as error:
            raise MSLMessageError(str(error)) from error

    def join(self, chunks: list[JSONObject], header: HeaderData, session: SessionCryptoContext | None) -> bytes:
        """Read the chunks in sequence and join their data; raise MSLMessageError for a chunk out of sequence or of
        another message."""
        if not chunks:
            return b""
        if session is None:
            raise MSLMessageError(message(SUBJECT, "invalid", "chunks without a session"))
        data = bytearray()
        for expected, wire in enumerate(chunks, start=1):
            chunk = PayloadChunk.parse(wire, session, verify=self.verify_signatures)
            if chunk.message_id != header.message_id:
                raise MSLMessageError(message(SUBJECT, "invalid", f"chunk message ID {chunk.message_id}"))
            if chunk.sequence_number != expected:
                raise MSLMessageError(message(SUBJECT, "invalid", f"chunk sequence {chunk.sequence_number}"))
            data += chunk.content()
        return bytes(data)
