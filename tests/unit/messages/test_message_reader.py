import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import given
from hypothesis import strategies as st

from pymsl_web.crypto.server_crypto_context import ServerCryptoContext
from pymsl_web.crypto.session_crypto_context import SessionCryptoContext
from pymsl_web.crypto.session_keys import SessionKeys
from pymsl_web.enums import MSLResponseCode
from pymsl_web.exceptions import MSLError, MSLMessageError, PyMSLError
from pymsl_web.messages.message_reader import MessageReader
from pymsl_web.utils.json import JSONObject
from tests.unit.support.answers import Answers
from tests.unit.support.tokens import Tokens

SERVER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ANSWERS = Answers(server_key=SERVER_KEY)
CONTEXT = SessionCryptoContext(
    keys=SessionKeys(encryption=ANSWERS.encryption_key, hmac=ANSWERS.hmac_key), key_id=ANSWERS.key_id
)


class TestMessageReader:
    @staticmethod
    def reader(*, verify: bool = True, key: rsa.RSAPrivateKey | None = None) -> MessageReader:
        """Build a reader, with the public key of `key` as the server's when given."""
        pem = (
            None
            if key is None
            else key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        return MessageReader(server=ServerCryptoContext.from_pem(pem), verify_signatures=verify)

    @staticmethod
    def message(*chunks: bytes, message_id: int = 8, signature: bytes | None = None) -> bytes:
        """Write an answer under a master token with one chunk per data."""
        header = ANSWERS.header(
            {"messageid": message_id, "timestamp": 100, "sender": "Netflix"},
            master_token=Tokens.master_token(),
            signature=signature,
        )
        objects = [
            ANSWERS.chunk(data, message_id=message_id, sequence_number=index, end=index == len(chunks))
            for index, data in enumerate(chunks, start=1)
        ]
        return Answers.body(header, *objects)

    def test_reads_handshake_answer(self) -> None:
        """Read a clear handshake answer signed by the server and give its key response."""
        response: JSONObject = {"scheme": "ASYMMETRIC_WRAPPED", "mastertoken": Tokens.master_token(), "keydata": {}}
        body = Answers.body(ANSWERS.header({"messageid": 8, "keyresponsedata": response}))
        answer = self.reader(key=SERVER_KEY).read(body, session=None, request_message_id=7)
        assert answer.header.key_response == response
        assert answer.data == b""

    def test_refuses_server_signature(self) -> None:
        """Raise MSLMessageError for a clear header whose RSA signature fails against the configured server key."""
        body = Answers.body(ANSWERS.header({"messageid": 8}))
        with pytest.raises(MSLMessageError, match=r"^Answer: invalid"):
            self.reader(key=OTHER_KEY).read(body, session=None, request_message_id=7)

    def test_reads_message(self) -> None:
        """Verify, decrypt and join the chunks of an answer, and keep its master token."""
        answer = self.reader().read(self.message(b"hel", b"lo"), session=CONTEXT, request_message_id=7)
        assert answer.data == b"hello"
        assert answer.header.sender == "Netflix"
        assert answer.master_token is not None

    def test_raises_server_error(self) -> None:
        """Raise MSLError with the code, the internal code and the messages of an error header."""
        body = Answers.body(ANSWERS.error(4, message_id=8, error_message="Expired"))
        with pytest.raises(MSLError) as raised:
            self.reader(key=SERVER_KEY).read(body, session=CONTEXT, request_message_id=7)
        assert raised.value.code is MSLResponseCode.USER_REAUTH
        assert raised.value.error_message == "Expired"

    def test_refuses_forged_error(self) -> None:
        """Raise MSLMessageError for an error header the configured server did not sign."""
        body = Answers.body(Answers(server_key=OTHER_KEY).error(4, message_id=8))
        with pytest.raises(MSLMessageError):
            self.reader(key=SERVER_KEY).read(body, session=CONTEXT, request_message_id=7)

    def test_refuses_wrong_message_id(self) -> None:
        """Raise MSLMessageError when the answer's message ID is not the request's + 1."""
        with pytest.raises(MSLMessageError, match=r"message ID"):
            self.reader().read(self.message(b"x", message_id=9), session=CONTEXT, request_message_id=7)

    def test_refuses_skipped_sequence(self) -> None:
        """Raise MSLMessageError when a chunk skips a sequence number."""
        header = ANSWERS.header({"messageid": 8}, master_token=Tokens.master_token())
        body = Answers.body(header, ANSWERS.chunk(b"x", message_id=8, sequence_number=2))
        with pytest.raises(MSLMessageError, match=r"sequence"):
            self.reader().read(body, session=CONTEXT, request_message_id=7)

    def test_refuses_chunk_of_other_message(self) -> None:
        """Raise MSLMessageError when a chunk carries another message ID."""
        header = ANSWERS.header({"messageid": 8}, master_token=Tokens.master_token())
        body = Answers.body(header, ANSWERS.chunk(b"x", message_id=9))
        with pytest.raises(MSLMessageError, match=r"message ID"):
            self.reader().read(body, session=CONTEXT, request_message_id=7)

    def test_refuses_bad_hmac(self) -> None:
        """Raise MSLMessageError for a header whose HMAC does not match."""
        with pytest.raises(MSLMessageError, match=r"^Answer: invalid"):
            self.reader().read(self.message(b"x", signature=b"\x00" * 32), session=CONTEXT, request_message_id=7)

    def test_skips_hmac_when_off(self) -> None:
        """Read the same tampered-signature answer when `verify_signatures` is off."""
        body = self.message(b"x", signature=b"\x00" * 32)
        assert self.reader(verify=False).read(body, session=CONTEXT, request_message_id=7).data == b"x"

    def test_refuses_encrypted_without_session(self) -> None:
        """Raise MSLMessageError for an encrypted answer when there is no session to read it."""
        with pytest.raises(MSLMessageError):
            self.reader().read(self.message(b"x"), session=None, request_message_id=7)

    def test_refuses_empty_body(self) -> None:
        """Raise MSLMessageError for an answer without any object."""
        with pytest.raises(MSLMessageError, match=r"^Answer: empty"):
            self.reader().read(b"", session=CONTEXT, request_message_id=7)

    @given(st.binary())
    def test_refuses_garbage(self, body: bytes) -> None:
        """Raise a PyMSLError, and nothing else, for any body."""
        with pytest.raises(PyMSLError):
            self.reader().read(body, session=CONTEXT, request_message_id=7)
