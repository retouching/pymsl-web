from collections.abc import Iterable

from pydantic import BaseModel, Field

from pymsl_web.tokens.service_token import UNBOUND, ServiceToken
from pymsl_web.utils.json import JSONValue


class ServiceTokens(BaseModel):
    tokens: dict[str, ServiceToken] = Field(default_factory=dict)

    def __len__(self) -> int:
        """Count the tokens kept."""
        return len(self.tokens)

    def store(self, tokens: Iterable[ServiceToken]) -> None:
        """Keep each token in place of the one of its name, and delete the name of a token sent with empty data."""
        for token in tokens:
            if token.is_deletion:
                self.tokens.pop(token.name, None)
            else:
                self.tokens[token.name] = token

    def forget_bound_to(self, master_token_serial_number: int) -> None:
        """Drop the tokens bound to the master token of `master_token_serial_number`."""
        self.tokens = {
            name: token
            for name, token in self.tokens.items()
            if token.master_token_serial_number != master_token_serial_number
        }

    def forget_user_bound(self) -> None:
        """Drop the tokens bound to a user ID token."""
        self.tokens = {
            name: token for name, token in self.tokens.items() if token.user_id_token_serial_number == UNBOUND
        }

    def to_wire(self) -> list[JSONValue]:
        """Give the tokens as the server sent them, in the order they were kept."""
        return [token.data.to_wire() for token in self.tokens.values()]
