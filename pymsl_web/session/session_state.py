from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from pymsl_web.tokens.token_data import TokenData


class MSLSessionState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    version: Literal[1] = 1
    sender: str
    master_token: TokenData | None
    encryption_key: str | None = Field(repr=False)
    hmac_key: str | None = Field(repr=False)
    user_id_token: TokenData | None
    service_tokens: list[TokenData]
    message_id: int
    clock_offset: int | None
