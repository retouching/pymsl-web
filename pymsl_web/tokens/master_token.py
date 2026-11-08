from typing import Final, Self

from pydantic import BaseModel, ConfigDict

from pymsl_web.tokens.token_data import TokenData
from pymsl_web.utils.json import JSONValue

SUBJECT: Final = "Master token"


class MasterToken(BaseModel):
    model_config = ConfigDict(frozen=True)

    data: TokenData
    renewal_window: int
    expiration: int
    sequence_number: int
    serial_number: int

    @classmethod
    def parse(cls, wire: JSONValue) -> Self:
        """Read a master token as the server sends it, keeping its wire form; raise MSLMessageError for anything
        else."""
        data = TokenData.parse(wire, subject=SUBJECT)
        fields = data.fields(subject=SUBJECT)
        return cls(
            data=data,
            renewal_window=TokenData.integer(fields, "renewalwindow", subject=SUBJECT),
            expiration=TokenData.integer(fields, "expiration", subject=SUBJECT),
            sequence_number=TokenData.integer(fields, "sequencenumber", subject=SUBJECT),
            serial_number=TokenData.integer(fields, "serialnumber", subject=SUBJECT),
        )

    def is_expired(self, now: int) -> bool:
        """Tell whether the token expired at `now`, in seconds of the server."""
        return self.expiration <= now

    def is_renewable(self, now: int) -> bool:
        """Tell whether the token entered its renewal window at `now`, in seconds of the server."""
        return self.renewal_window <= now
