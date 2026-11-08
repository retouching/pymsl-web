import pytest

from pymsl_web.crypto.session_crypto_context import SessionCryptoContext
from pymsl_web.crypto.session_keys import SessionKeys
from pymsl_web.enums import CompressionAlgorithm
from pymsl_web.exceptions import MSLMessageError
from pymsl_web.messages.payload_chunk import PayloadChunk
from pymsl_web.utils.base64 import decode
from pymsl_web.utils.json import load_object
from tests.unit.support.answers import Answers

ANSWERS = Answers()
CONTEXT = SessionCryptoContext(
    keys=SessionKeys(encryption=ANSWERS.encryption_key, hmac=ANSWERS.hmac_key), key_id=ANSWERS.key_id
)


class TestPayloadChunk:
    def test_writes_owner_fields(self) -> None:
        """Write the inner fields in the order of the owner's code, the data compressed then Base64."""
        chunk = PayloadChunk.build(b"x" * 100, message_id=7, compression=CompressionAlgorithm.GZIP)
        wire = chunk.to_wire(CONTEXT)
        payload = decode(str(wire["payload"]), context="test")
        assert CONTEXT.verify(payload, decode(str(wire["signature"]), context="test"))
        inner = load_object(CONTEXT.decrypt(payload), context="test")
        assert list(inner) == ["messageid", "data", "compressionalgo", "sequencenumber", "endofmsg"]
        assert inner["sequencenumber"] == 1
        assert inner["endofmsg"] is True

    def test_leaves_compression_out_when_longer(self) -> None:
        """Leave `compressionalgo` out when LZW would not shrink the data."""
        chunk = PayloadChunk.build(b"aa", message_id=7, compression=CompressionAlgorithm.LZW)
        assert chunk.compression is None
        assert chunk.content() == b"aa"

    def test_writes_without_compression(self) -> None:
        """Write the data as it is when no compression is configured."""
        chunk = PayloadChunk.build(b"data", message_id=7, compression=None)
        inner = load_object(CONTEXT.decrypt(decode(str(chunk.to_wire(CONTEXT)["payload"]), context="t")), context="t")
        assert "compressionalgo" not in inner

    @pytest.mark.parametrize(
        ("data", "compression"), [(b"x" * 50, "GZIP"), (bytes.fromhex("61804060503824160d02"), "LZW"), (b"x", None)]
    )
    def test_reads_server_chunk(self, data: bytes, compression: str | None) -> None:
        """Read a chunk of the server in each compression."""
        chunk = PayloadChunk.parse(ANSWERS.chunk(data, message_id=8, compression=compression), CONTEXT, verify=True)
        assert chunk.message_id == 8
        expected = b"x" * 50 if compression == "GZIP" else (b"a" * 40 if compression == "LZW" else b"x")
        assert chunk.content() == expected

    def test_refuses_bad_hmac(self) -> None:
        """Raise MSLMessageError for a chunk whose HMAC does not match."""
        with pytest.raises(MSLMessageError, match=r"^Payload chunk: invalid"):
            PayloadChunk.parse(ANSWERS.chunk(b"x", message_id=8, signature=b"\x00" * 32), CONTEXT, verify=True)

    def test_skips_hmac_when_off(self) -> None:
        """Read a chunk whose HMAC does not match when the check is off."""
        chunk = PayloadChunk.parse(ANSWERS.chunk(b"x", message_id=8, signature=b"\x00" * 32), CONTEXT, verify=False)
        assert chunk.content() == b"x"
