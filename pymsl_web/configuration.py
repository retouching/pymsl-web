from pydantic import BaseModel, ConfigDict, field_validator

from pymsl_web.crypto.server_crypto_context import ServerCryptoContext
from pymsl_web.entityauth.entity_authentication import EntityAuthentication
from pymsl_web.enums import CompressionAlgorithm
from pymsl_web.exceptions import MSLCryptoError
from pymsl_web.keyexchange.key_exchange import KeyExchange
from pymsl_web.userauth.user_authentication import UserAuthentication


class MSLConfiguration(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    url: str
    entity_authentication: EntityAuthentication
    key_exchange: KeyExchange
    user_authentication: UserAuthentication | None = None
    languages: tuple[str, ...] = ()
    compression: CompressionAlgorithm | None = CompressionAlgorithm.GZIP
    compression_algorithms: tuple[CompressionAlgorithm, ...] = (CompressionAlgorithm.GZIP,)
    encoder_formats: tuple[str, ...] = ("JSON",)
    renewable: bool = True
    verify_signatures: bool = True
    server_public_key: bytes | None = None

    @field_validator("server_public_key")
    @classmethod
    def check_server_public_key(cls, value: bytes | None) -> bytes | None:
        """Refuse a server key that is not a PEM RSA public key."""
        try:
            ServerCryptoContext.from_pem(value)
        except MSLCryptoError as error:
            raise ValueError(str(error)) from error
        return value
