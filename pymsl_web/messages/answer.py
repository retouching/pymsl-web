from pydantic import BaseModel, ConfigDict

from pymsl_web.messages.header_data import HeaderData
from pymsl_web.tokens.master_token import MasterToken


class Answer(BaseModel):
    model_config = ConfigDict(frozen=True)

    header: HeaderData
    data: bytes
    master_token: MasterToken | None
