from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.utils.base64 import decode_url
from pymsl_web.utils.json import load_object
from pymsl_web.utils.messages import message

SYMMETRIC_KEY_TYPE: Final = "oct"


class JWK(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", strict=True)

    kty: str
    k: str = Field(repr=False)
    alg: str | None = None
    key_ops: list[str] | None = None
    extractable: bool | None = None
    use: str | None = None

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Read the JSON of a symmetric JWK; raise MSLMessageError for anything else."""
        try:
            jwk = cls.model_validate(load_object(data, context="JWK"))
        except (ValueError, ValidationError) as error:
            raise MSLMessageError(message("JWK", "invalid", "a JSON JWK expected")) from error
        if jwk.kty != SYMMETRIC_KEY_TYPE:
            raise MSLMessageError(message("JWK", "invalid", f"kty {SYMMETRIC_KEY_TYPE} expected"))
        return jwk

    def key(self) -> bytes:
        """Give the bytes of `k`; raise MSLMessageError when it is not base64url."""
        try:
            return decode_url(self.k, context="JWK")
        except ValueError as error:
            raise MSLMessageError(str(error)) from error
