from typing import Final, Self

from pydantic import BaseModel, ConfigDict

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.utils.base64 import decode, encode
from pymsl_web.utils.json import JSONObject, dump, load_object
from pymsl_web.utils.messages import message

SUBJECT: Final = "Ciphertext envelope"
CIPHER_SPEC: Final = "AES/CBC/PKCS5Padding"
DUMMY_SHA256: Final = "AA=="


class CiphertextEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True)

    key_id: str
    iv: bytes
    ciphertext: bytes

    def to_json(self) -> bytes:
        """Write the V1 envelope in the order of the owner's working code, with the dummy `sha256` of the reference."""
        return dump(
            {
                "ciphertext": encode(self.ciphertext),
                "keyid": self.key_id,
                "sha256": DUMMY_SHA256,
                "iv": encode(self.iv),
            }
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Read a V1 or V2 envelope; raise MSLMessageError for anything else."""
        try:
            document = load_object(data, context=SUBJECT)
            if "version" in document:
                return cls.parse_version_2(document)
            key_id = document["keyid"]
            if not isinstance(key_id, str):
                raise MSLMessageError(message(SUBJECT, "invalid", "keyid"))
            return cls(
                key_id=key_id, iv=cls.read_bytes(document, "iv"), ciphertext=cls.read_bytes(document, "ciphertext")
            )
        except (KeyError, ValueError) as error:
            raise MSLMessageError(message(SUBJECT, "invalid", str(error))) from error

    @classmethod
    def parse_version_2(cls, document: JSONObject) -> Self:
        """Read a V2 envelope, which names its cipher and no key."""
        if document["version"] != 2 or document.get("cipherspec") != CIPHER_SPEC:
            raise MSLMessageError(message(SUBJECT, "invalid", "an AES/CBC/PKCS5Padding V2 envelope expected"))
        return cls(key_id="", iv=cls.read_bytes(document, "iv"), ciphertext=cls.read_bytes(document, "ciphertext"))

    @staticmethod
    def read_bytes(document: JSONObject, key: str) -> bytes:
        """Read the Base64 field `key` of `document`."""
        value = document[key]
        if not isinstance(value, str):
            raise MSLMessageError(message(SUBJECT, "invalid", key))
        return decode(value, context=SUBJECT)

    @staticmethod
    def is_envelope(data: bytes) -> bool:
        """Tell whether `data` is a ciphertext envelope rather than clear JSON."""
        try:
            return "ciphertext" in load_object(data, context=SUBJECT)
        except ValueError:
            return False
