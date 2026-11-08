import base64
import gzip
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pydantic import BaseModel, ConfigDict

from pymsl_web.utils.json import JSONObject, JSONValue


class Answers(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    encryption_key: bytes = bytes(range(16))
    hmac_key: bytes = b"\x02" * 32
    key_id: str = "ESN_25"
    server_key: rsa.RSAPrivateKey | None = None

    @staticmethod
    def b64(data: bytes) -> str:
        """Write standard Base64."""
        return base64.b64encode(data).decode()

    def encrypt(self, clear: bytes) -> bytes:
        """Encrypt `clear` as the server does: AES-128-CBC, PKCS#7, a JSON V1 envelope."""
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        encryptor = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padder.update(clear) + padder.finalize()) + encryptor.finalize()
        envelope = {"keyid": self.key_id, "iv": self.b64(iv), "ciphertext": self.b64(ciphertext), "sha256": "AA=="}
        return json.dumps(envelope).encode()

    def decrypt(self, envelope: bytes) -> bytes:
        """Decrypt a V1 envelope as the server does."""
        document = json.loads(envelope)
        iv, ciphertext = base64.b64decode(document["iv"]), base64.b64decode(document["ciphertext"])
        decryptor = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv)).decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()

    def mac(self, data: bytes) -> bytes:
        """Sign `data` with the HMAC-SHA256 of the session."""
        return hmac.new(self.hmac_key, data, hashlib.sha256).digest()

    def server_signature(self, data: bytes) -> bytes:
        """Sign `data` with the RSA key of the server, or give no signature without one."""
        if self.server_key is None:
            return b""
        return self.server_key.sign(data, rsa_padding.PKCS1v15(), hashes.SHA256())

    def header(
        self, fields: JSONObject, *, master_token: JSONObject | None = None, signature: bytes | None = None
    ) -> JSONObject:
        """Write a message header: encrypted and signed with the session under a master token, else clear and signed
        by the server."""
        clear = json.dumps(fields).encode()
        if master_token is not None:
            data = self.encrypt(clear)
            outer: JSONObject = {"mastertoken": master_token}
            sign = self.mac(data) if signature is None else signature
        else:
            data = clear
            outer = {"entityauthdata": {"scheme": "RSA", "authdata": {"identity": "Netflix"}}}
            sign = self.server_signature(data) if signature is None else signature
        outer["headerdata"] = self.b64(data)
        outer["signature"] = self.b64(sign)
        return outer

    def error(self, code: int, *, message_id: int, error_message: str = "refused") -> JSONObject:
        """Write a clear error header signed by the server."""
        fields = {"messageid": message_id, "errorcode": code, "internalcode": 101, "errormsg": error_message}
        data = json.dumps(fields).encode()
        return {
            "entityauthdata": {"scheme": "RSA", "authdata": {"identity": "Netflix"}},
            "errordata": self.b64(data),
            "signature": self.b64(self.server_signature(data)),
        }

    def chunk(
        self,
        data: bytes,
        *,
        message_id: int,
        sequence_number: int = 1,
        compression: str | None = None,
        end: bool = True,
        signature: bytes | None = None,
    ) -> JSONObject:
        """Write a payload chunk encrypted and signed with the session, its data compressed as asked."""
        payload: dict[str, JSONValue] = {"sequencenumber": sequence_number, "messageid": message_id}
        if end:
            payload["endofmsg"] = True
        if compression == "GZIP":
            data = gzip.compress(data)
        if compression is not None:
            payload["compressionalgo"] = compression
        payload["data"] = self.b64(data)
        encrypted = self.encrypt(json.dumps(payload).encode())
        return {
            "payload": self.b64(encrypted),
            "signature": self.b64(self.mac(encrypted) if signature is None else signature),
        }

    @staticmethod
    def body(*objects: JSONObject) -> bytes:
        """Glue the objects of an answer as the server does."""
        return b"".join(json.dumps(item).encode() for item in objects)
