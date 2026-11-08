from pymsl_web.crypto.session_crypto_context import SessionCryptoContext
from pymsl_web.crypto.session_keys import SessionKeys
from pymsl_web.enums import CompressionAlgorithm
from pymsl_web.messages.capabilities import MessageCapabilities
from pymsl_web.messages.header_data import HeaderData
from pymsl_web.messages.message_writer import MessageWriter
from pymsl_web.tokens.master_token import MasterToken
from pymsl_web.utils.base64 import decode
from pymsl_web.utils.json import load_object, split_objects
from tests.unit.support.tokens import Tokens

CONTEXT = SessionCryptoContext(keys=SessionKeys(encryption=bytes(range(16)), hmac=b"\x02" * 32), key_id="ESN_25")


class TestMessageWriter:
    @staticmethod
    def header(*, handshake: bool) -> HeaderData:
        """Build a header of message ID 7."""
        return HeaderData(
            message_id=7,
            renewable=True,
            handshake=handshake,
            capabilities=MessageCapabilities(compression_algorithms=("GZIP",), languages=(), encoder_formats=("JSON",)),
            timestamp=100,
            sender="ESN",
        )

    def test_writes_handshake_in_clear(self) -> None:
        """Write the handshake header as Base64 of clear JSON with an empty signature, and no chunk."""
        body = MessageWriter().handshake(
            entity_authentication={"scheme": "NONE", "authdata": {"identity": "ESN"}},
            header=self.header(handshake=True),
        )
        objects = split_objects(body, context="test")
        assert len(objects) == 1
        assert list(objects[0]) == ["entityauthdata", "headerdata", "signature"]
        assert objects[0]["signature"] == ""
        assert load_object(decode(str(objects[0]["headerdata"]), context="t"), context="t")["handshake"] is True

    def test_writes_request(self) -> None:
        """Write a header signed with the HMAC of its envelope JSON and one chunk of sequence 1 ending the message."""
        master_token = MasterToken.parse(Tokens.master_token())
        body = MessageWriter().request(
            master_token=master_token,
            header=self.header(handshake=False),
            context=CONTEXT,
            data=b"hello",
            compression=CompressionAlgorithm.GZIP,
        )
        header, chunk = split_objects(body, context="test")
        assert list(header) == ["headerdata", "signature", "mastertoken"]
        assert header["mastertoken"] == master_token.data.to_wire()
        envelope = decode(str(header["headerdata"]), context="t")
        assert CONTEXT.verify(envelope, decode(str(header["signature"]), context="t"))
        assert load_object(CONTEXT.decrypt(envelope), context="t")["messageid"] == 7
        inner = load_object(CONTEXT.decrypt(decode(str(chunk["payload"]), context="t")), context="t")
        assert (inner["messageid"], inner["sequencenumber"], inner["endofmsg"]) == (7, 1, True)
