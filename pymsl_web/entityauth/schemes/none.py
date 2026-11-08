from typing import ClassVar

from pydantic import Field

from pymsl_web.crypto.crypto_context import CryptoContext
from pymsl_web.crypto.null_crypto_context import NullCryptoContext
from pymsl_web.entityauth.entity_authentication import EntityAuthentication
from pymsl_web.utils.json import JSONObject


class NoneEntityAuthentication(EntityAuthentication):
    scheme: ClassVar[str] = "NONE"

    identity_value: str = Field(alias="identity", min_length=1)

    def identity(self) -> str:
        """Give the identity, the ESN of the web player."""
        return self.identity_value

    def authdata(self) -> JSONObject:
        """Give the identity alone, as the web player sends it."""
        return {"identity": self.identity_value}

    def crypto_context(self) -> CryptoContext:
        """Give the null context: `NONE` neither encrypts nor signs."""
        return NullCryptoContext()
