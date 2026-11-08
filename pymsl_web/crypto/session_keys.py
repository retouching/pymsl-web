from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

ENCRYPTION_KEY_SIZE: Final = 16
HMAC_KEY_SIZE: Final = 32


class SessionKeys(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True)

    encryption: bytes = Field(repr=False)
    hmac: bytes = Field(repr=False)

    @field_validator("encryption")
    @classmethod
    def check_encryption(cls, value: bytes) -> bytes:
        """Refuse an encryption key that is not an AES-128 key."""
        if len(value) != ENCRYPTION_KEY_SIZE:
            raise ValueError(f"an encryption key of {ENCRYPTION_KEY_SIZE} bytes expected")
        return value

    @field_validator("hmac")
    @classmethod
    def check_hmac(cls, value: bytes) -> bytes:
        """Refuse an HMAC key that is not an HMAC-SHA256 key."""
        if len(value) != HMAC_KEY_SIZE:
            raise ValueError(f"an HMAC key of {HMAC_KEY_SIZE} bytes expected")
        return value
