import base64
import gzip
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key
from pydantic import BaseModel, ConfigDict, Field

from pymsl_web.utils.json import JSONObject, JSONValue, split_objects
from tests.unit.support.answers import Answers
from tests.unit.support.tokens import Tokens


class FakeAnswer(BaseModel):
    status_code: int
    content: bytes


class Post(BaseModel):
    url: str
    params: dict[str, str] | None
    header: JSONObject
    data: bytes | None


class FakeServer(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    answers: Answers = Field(default_factory=Answers)
    posts: list[Post] = Field(default_factory=list)
    timestamp: int = 1500
    serial_number: int = 1
    status_code: int = 200
    failure: OSError | None = None
    error_code: int | None = None
    message_id_shift: int = 1
    hmac_tampered: bool = False
    key_response: bool = True
    user_id_token: JSONObject | None = None
    service_tokens: list[JSONValue] = Field(default_factory=list)

    @property
    def headers(self) -> list[JSONObject]:
        """Give the clear header of each message received."""
        return [post.header for post in self.posts]

    def post(self, url: str, *, params: dict[str, str] | None, data: bytes) -> FakeAnswer:
        """Answer a handshake with a key response and a request with the echo of its data, as told."""
        if self.failure is not None:
            raise self.failure
        objects = split_objects(data, context="Fake server")
        outer = objects[0]
        raw = base64.b64decode(str(outer["headerdata"]))
        handshake = "entityauthdata" in outer
        header = json.loads(raw if handshake else self.answers.decrypt(raw))
        content = None if handshake else self.content(objects[1])
        self.posts.append(Post(url=url, params=None if params is None else dict(params), header=header, data=content))
        if self.status_code != 200:
            return FakeAnswer(status_code=self.status_code, content=b"")
        message_id = header["messageid"] + self.message_id_shift
        if self.error_code is not None:
            body = Answers.body(self.answers.error(self.error_code, message_id=message_id))
        elif handshake:
            body = Answers.body(self.answers.header(self.handshake_fields(header, message_id)))
        else:
            body = self.echo(message_id, content or b"")
        return FakeAnswer(status_code=200, content=body)

    def content(self, chunk: JSONObject) -> bytes:
        """Read the data of the chunk of a request."""
        payload = json.loads(self.answers.decrypt(base64.b64decode(str(chunk["payload"]))))
        data = base64.b64decode(payload["data"])
        return gzip.decompress(data) if payload.get("compressionalgo") == "GZIP" else data

    def handshake_fields(self, header: JSONObject, message_id: int) -> JSONObject:
        """Build the clear header of a handshake answer, the session keys wrapped for the client's public key."""
        fields: JSONObject = {"messageid": message_id, "timestamp": self.timestamp, "sender": "Netflix"}
        if not self.key_response:
            return fields
        request = header["keyrequestdata"]
        assert isinstance(request, list)
        assert isinstance(request[0], dict)
        keydata = request[0]["keydata"]
        assert isinstance(keydata, dict)
        key = load_der_public_key(base64.b64decode(str(keydata["publickey"])))
        assert isinstance(key, RSAPublicKey)
        fields["keyresponsedata"] = {
            "mastertoken": Tokens.master_token(serial_number=self.serial_number),
            "scheme": "ASYMMETRIC_WRAPPED",
            "keydata": {
                "keypairid": keydata["keypairid"],
                "encryptionkey": self.wrap(key, self.answers.encryption_key),
                "hmackey": self.wrap(key, self.answers.hmac_key),
            },
        }
        return fields

    @staticmethod
    def wrap(key: RSAPublicKey, secret: bytes) -> str:
        """Wrap `secret` in JWK JSON with RSA-OAEP SHA-1, as the server does."""
        jwk = {"kty": "oct", "k": base64.urlsafe_b64encode(secret).decode().rstrip("="), "extractable": True}
        sha1 = hashes.SHA1()  # noqa: S303
        oaep = padding.OAEP(mgf=padding.MGF1(sha1), algorithm=sha1, label=None)
        return base64.b64encode(key.encrypt(json.dumps(jwk).encode(), oaep)).decode()

    def echo(self, message_id: int, data: bytes) -> bytes:
        """Build the answer of a request: its header under the master token and one chunk holding `echo:<data>`."""
        fields: JSONObject = {"messageid": message_id, "timestamp": self.timestamp, "sender": "Netflix"}
        if self.user_id_token is not None:
            fields["useridtoken"] = self.user_id_token
        if self.service_tokens:
            fields["servicetokens"] = self.service_tokens
        signature = b"\x00" * 32 if self.hmac_tampered else None
        header = self.answers.header(
            fields, master_token=Tokens.master_token(serial_number=self.serial_number), signature=signature
        )
        return Answers.body(header, self.answers.chunk(b"echo:" + data, message_id=message_id, compression="GZIP"))
