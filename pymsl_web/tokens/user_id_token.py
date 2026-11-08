from typing import Final, Self

from pydantic import BaseModel, ConfigDict

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.tokens.master_token import MasterToken
from pymsl_web.tokens.token_data import TokenData
from pymsl_web.utils.json import JSONValue
from pymsl_web.utils.messages import message

SUBJECT: Final = "User ID token"


class UserIDToken(BaseModel):
    model_config = ConfigDict(frozen=True)

    data: TokenData
    renewal_window: int
    expiration: int
    master_token_serial_number: int
    serial_number: int
    profile_id: str | None

    @classmethod
    def parse(cls, wire: JSONValue) -> Self:
        """Read a user ID token as the server sends it, keeping its wire form; raise MSLMessageError for anything
        else."""
        data = TokenData.parse(wire, subject=SUBJECT)
        fields = data.fields(subject=SUBJECT)
        profile_id = fields.get("profileid")
        if profile_id is not None and not isinstance(profile_id, str):
            raise MSLMessageError(message(SUBJECT, "invalid", "profileid expected as text"))
        return cls(
            data=data,
            renewal_window=TokenData.integer(fields, "renewalwindow", subject=SUBJECT),
            expiration=TokenData.integer(fields, "expiration", subject=SUBJECT),
            master_token_serial_number=TokenData.integer(fields, "mtserialnumber", subject=SUBJECT),
            serial_number=TokenData.integer(fields, "serialnumber", subject=SUBJECT),
            profile_id=profile_id,
        )

    def is_bound_to(self, master_token: MasterToken) -> bool:
        """Tell whether the token belongs to `master_token`."""
        return self.master_token_serial_number == master_token.serial_number
