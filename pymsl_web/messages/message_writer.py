from pydantic import BaseModel

from pymsl_web.crypto.crypto_context import CryptoContext
from pymsl_web.crypto.null_crypto_context import NullCryptoContext
from pymsl_web.enums import CompressionAlgorithm
from pymsl_web.messages.header_data import HeaderData
from pymsl_web.messages.payload_chunk import PayloadChunk
from pymsl_web.tokens.master_token import MasterToken
from pymsl_web.utils.base64 import encode
from pymsl_web.utils.json import JSONObject, dump


class MessageWriter(BaseModel):
    def handshake(self, *, entity_authentication: JSONObject, header: HeaderData) -> bytes:
        """Write a handshake: the entity authentication, the header as Base64 of clear JSON, an empty signature and
        no chunk."""
        headerdata, signature = self.protect(header, NullCryptoContext())
        return dump({"entityauthdata": entity_authentication, "headerdata": headerdata, "signature": signature})

    def request(
        self,
        *,
        master_token: MasterToken,
        header: HeaderData,
        context: CryptoContext,
        data: bytes,
        compression: CompressionAlgorithm | None,
    ) -> bytes:
        """Write a request: the header encrypted and signed with `context` under `master_token`, then one chunk that
        holds `data` and ends the message."""
        headerdata, signature = self.protect(header, context)
        outer: JSONObject = {
            "headerdata": headerdata,
            "signature": signature,
            "mastertoken": master_token.data.to_wire(),
        }
        chunk = PayloadChunk.build(data, message_id=header.message_id, compression=compression)
        return dump(outer) + dump(chunk.to_wire(context))

    @staticmethod
    def protect(header: HeaderData, context: CryptoContext) -> tuple[str, str]:
        """Give the `headerdata` and the `signature` of `header`: its JSON encrypted, then signed, in Base64."""
        protected = context.encrypt(dump(header.to_wire()))
        return encode(protected), encode(context.sign(protected))
