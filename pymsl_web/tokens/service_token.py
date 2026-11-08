from typing import Final, Self

from pydantic import BaseModel, ConfigDict

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.tokens.token_data import TokenData
from pymsl_web.utils.json import JSONValue
from pymsl_web.utils.messages import message

SUBJECT: Final = "Service token"
UNBOUND: Final = -1


class ServiceToken(BaseModel):
    model_config = ConfigDict(frozen=True)

    data: TokenData
    name: str
    master_token_serial_number: int
    user_id_token_serial_number: int
    is_deletion: bool

    @classmethod
    def parse(cls, wire: JSONValue) -> Self:
        """Read a service token as the server sends it, keeping its wire form; raise MSLMessageError for anything
        else."""
        data = TokenData.parse(wire, subject=SUBJECT)
        fields = data.fields(subject=SUBJECT)
        name, service_data = fields.get("name"), fields.get("servicedata", "")
        if not isinstance(name, str) or not name:
            raise MSLMessageError(message(SUBJECT, "invalid", "name expected"))
        if not isinstance(service_data, str):
            raise MSLMessageError(message(SUBJECT, "invalid", "servicedata expected as text"))
        return cls(
            data=data,
            name=name,
            master_token_serial_number=TokenData.integer(fields, "mtserialnumber", subject=SUBJECT, default=UNBOUND),
            user_id_token_serial_number=TokenData.integer(fields, "uitserialnumber", subject=SUBJECT, default=UNBOUND),
            is_deletion=not service_data,
        )
