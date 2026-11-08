import base64
import gzip
import json
import os
import secrets
import time
from typing import Final

from tests.e2e.server.crypto import ServerCrypto
from tests.e2e.server.lzw import LZW

NETFLIX_ID: Final = "e2e-id"
SECURE_NETFLIX_ID: Final = "e2e-secure"
RESPONSE_CODES: Final = {
    "FAIL": 1,
    "ENTITY_REAUTH": 3,
    "USER_REAUTH": 4,
    "KEYX_REQUIRED": 5,
    "USERDATA_REAUTH": 7,
    "EXPIRED": 8,
}
SERVER_ENTITY: Final = {"scheme": "RSA", "authdata": {"identity": "Netflix", "pubkeyid": "e2e"}}

type Document = dict[str, object]


class Session:
    def __init__(self, sender: str, encryption_key: bytes, hmac_key: bytes, sequence_number: int) -> None:
        """Keep the keys the server gave to `sender` at a handshake."""
        self.sender = sender
        self.encryption_key = encryption_key
        self.hmac_key = hmac_key
        self.sequence_number = sequence_number
        self.user_serial_numbers: set[int] = set()


class MSLServer:
    def __init__(self) -> None:
        """Start without any session, with a fresh RSA key."""
        self.crypto = ServerCrypto()
        self.sessions: dict[int, Session] = {}

    @staticmethod
    def split(body: bytes) -> list[Document]:
        """Read the run of JSON objects of a message."""
        decoder = json.JSONDecoder()
        text, index, objects = body.decode(), 0, []
        while index < len(text):
            value, index = decoder.raw_decode(text, index)
            objects.append(value)
        return objects

    @staticmethod
    def token(fields: Document) -> Document:
        """Write a token as Base64 of clear JSON with a random signature."""
        tokendata = base64.b64encode(json.dumps(fields).encode()).decode()
        return {"tokendata": tokendata, "signature": base64.b64encode(os.urandom(32)).decode()}

    @staticmethod
    def read_token(token: object) -> Document:
        """Read the clear fields of a token."""
        if not isinstance(token, dict):
            raise TypeError("a token expected")
        fields: Document = json.loads(base64.b64decode(str(token["tokendata"])))
        return fields

    def answer(self, body: bytes, *, json_echo: bool) -> bytes:
        """Answer a handshake or a request, the echo of a request as JSON when `json_echo`."""
        objects = self.split(body)
        if "entityauthdata" in objects[0]:
            return self.handshake(objects[0])
        return self.request(objects[0], objects[1:], json_echo=json_echo)

    def handshake(self, outer: Document) -> bytes:
        """Give a master token and the session keys wrapped for the client's public key."""
        header = json.loads(base64.b64decode(str(outer["headerdata"])))
        keydata = header["keyrequestdata"][0]["keydata"]
        serial_number, now = secrets.randbelow(2**40), int(time.time())
        session = Session(str(header["sender"]), os.urandom(16), os.urandom(32), 1)
        self.sessions[serial_number] = session
        master_token = self.token(
            {
                "sessiondata": "e2e",
                "renewalwindow": now + 600,
                "expiration": now + 3600,
                "sequencenumber": session.sequence_number,
                "serialnumber": serial_number,
            }
        )
        public_key = base64.b64decode(keydata["publickey"])
        fields = {
            "messageid": header["messageid"] + 1,
            "timestamp": now,
            "sender": "Netflix",
            "keyresponsedata": {
                "mastertoken": master_token,
                "scheme": "ASYMMETRIC_WRAPPED",
                "keydata": {
                    "keypairid": keydata["keypairid"],
                    "encryptionkey": self.crypto.wrap(public_key, session.encryption_key),
                    "hmackey": self.crypto.wrap(public_key, session.hmac_key),
                },
            },
        }
        clear = json.dumps(fields).encode()
        signature = self.crypto.b64(self.crypto.sign(clear))
        document = {"entityauthdata": SERVER_ENTITY, "headerdata": self.crypto.b64(clear), "signature": signature}
        return json.dumps(document).encode()

    def error(self, code: int, message_id: int) -> bytes:
        """Give a clear error header signed by the server."""
        clear = json.dumps({"messageid": message_id, "errorcode": code, "internalcode": 1, "errormsg": "e2e"}).encode()
        signature = self.crypto.b64(self.crypto.sign(clear))
        return json.dumps(
            {"entityauthdata": SERVER_ENTITY, "errordata": self.crypto.b64(clear), "signature": signature}
        ).encode()

    def request(self, outer: Document, chunks: list[Document], *, json_echo: bool) -> bytes:
        """Check a request under its master token and echo its data with the way the user authenticated: in front
        of the data, or as `{"auth", "echo"}` JSON when `json_echo`."""
        master_fields = self.read_token(outer["mastertoken"])
        serial_number = int(str(master_fields["serialnumber"]))
        session = self.sessions[serial_number]
        envelope = base64.b64decode(str(outer["headerdata"]))
        if self.crypto.mac(session.hmac_key, envelope) != base64.b64decode(str(outer["signature"])):
            raise ValueError("header signature")
        header = json.loads(self.crypto.decrypt(session.encryption_key, envelope))
        reply_id = header["messageid"] + 1
        method = self.authenticate(session, header)
        if method is None:
            return self.error(RESPONSE_CODES["USERDATA_REAUTH"], reply_id)
        data, compression = self.content(session, chunks[0])
        if data.startswith(b"error:"):
            name = data.removeprefix(b"error:").decode()
            if name == "USER_REAUTH":
                session.user_serial_numbers.clear()
            return self.error(RESPONSE_CODES[name], reply_id)
        user_serial_number = secrets.randbelow(2**40)
        session.user_serial_numbers.add(user_serial_number)
        now = int(time.time())
        user_id_token = self.token(
            {
                "userdata": "e2e",
                "mtserialnumber": serial_number,
                "renewalwindow": now + 600,
                "serialnumber": user_serial_number,
                "profileid": "E2E",
                "expiration": now + 3600,
            }
        )
        service_token = self.token(
            {"name": "cad", "mtserialnumber": serial_number, "encrypted": True, "servicedata": "e2e"}
        )
        fields = {
            "messageid": reply_id,
            "timestamp": now,
            "sender": "Netflix",
            "useridtoken": user_id_token,
            "servicetokens": [service_token],
        }
        key_id = f"{session.sender}_{session.sequence_number}"
        envelope = self.crypto.encrypt(session.encryption_key, key_id, json.dumps(fields).encode())
        answer = {
            "mastertoken": outer["mastertoken"],
            "headerdata": self.crypto.b64(envelope),
            "signature": self.crypto.b64(self.crypto.mac(session.hmac_key, envelope)),
        }
        echo = (
            json.dumps({"auth": method, "echo": json.loads(data)}).encode()
            if json_echo
            else f"echo:{method}:".encode() + data
        )
        return json.dumps(answer).encode() + self.chunk(session, reply_id, echo, compression)

    def authenticate(self, session: Session, header: Document) -> str | None:
        """Tell how the user of `header` authenticated: `token`, `cookies`, or None when refused."""
        if "useridtoken" in header:
            fields = self.read_token(header["useridtoken"])
            return "token" if fields["serialnumber"] in session.user_serial_numbers else None
        authentication = header.get("userauthdata")
        if not isinstance(authentication, dict) or authentication.get("scheme") != "NETFLIXID":
            return None
        authdata = authentication["authdata"]
        cookies = (authdata.get("netflixid"), authdata.get("securenetflixid"))
        return "cookies" if cookies == (NETFLIX_ID, SECURE_NETFLIX_ID) else None

    def content(self, session: Session, chunk: Document) -> tuple[bytes, str | None]:
        """Check and read the chunk of a request, and give its data and its compression."""
        payload = base64.b64decode(str(chunk["payload"]))
        if self.crypto.mac(session.hmac_key, payload) != base64.b64decode(str(chunk["signature"])):
            raise ValueError("chunk signature")
        fields = json.loads(self.crypto.decrypt(session.encryption_key, payload))
        data = base64.b64decode(fields["data"])
        compression = fields.get("compressionalgo")
        if compression == "GZIP":
            return gzip.decompress(data), compression
        if compression == "LZW":
            return LZW.decompress(data), compression
        return data, None

    def chunk(self, session: Session, message_id: int, data: bytes, compression: str | None) -> bytes:
        """Write the one chunk of an answer, compressed as the request was."""
        fields: Document = {"messageid": message_id, "sequencenumber": 1, "endofmsg": True}
        compressed = (
            gzip.compress(data) if compression == "GZIP" else LZW.compress(data) if compression == "LZW" else None
        )
        if compressed is not None:
            fields["compressionalgo"] = compression
        fields["data"] = self.crypto.b64(data if compressed is None else compressed)
        key_id = f"{session.sender}_{session.sequence_number}"
        payload = self.crypto.encrypt(session.encryption_key, key_id, json.dumps(fields).encode())
        signature = self.crypto.b64(self.crypto.mac(session.hmac_key, payload))
        return json.dumps({"payload": self.crypto.b64(payload), "signature": signature}).encode()
