from pymsl_web.tokens.service_token import ServiceToken
from pymsl_web.tokens.service_tokens import ServiceTokens
from tests.unit.support.tokens import Tokens


class TestServiceTokens:
    def test_stores_and_replaces(self) -> None:
        """Keep one token per name, the last one received."""
        tokens = ServiceTokens()
        first = ServiceToken.parse(Tokens.service_token("sf", data="AAAA"))
        second = ServiceToken.parse(Tokens.service_token("sf", data="BBBB"))
        tokens.store([first, ServiceToken.parse(Tokens.service_token("cad"))])
        tokens.store([second])
        assert len(tokens) == 2
        assert tokens.tokens["sf"] == second

    def test_deletes_empty(self) -> None:
        """Remove a token when the server sends it with empty data."""
        tokens = ServiceTokens()
        tokens.store([ServiceToken.parse(Tokens.service_token("sf"))])
        tokens.store([ServiceToken.parse(Tokens.service_token("sf", data=""))])
        assert len(tokens) == 0

    def test_forgets_bound_to_master_token(self) -> None:
        """Drop the tokens bound to a master token and keep the unbound ones."""
        tokens = ServiceTokens()
        tokens.store(
            [
                ServiceToken.parse(Tokens.service_token("bound", master_token_serial_number=3)),
                ServiceToken.parse(Tokens.service_token("other", master_token_serial_number=4)),
                ServiceToken.parse(Tokens.service_token("free")),
            ]
        )
        tokens.forget_bound_to(3)
        assert sorted(tokens.tokens) == ["free", "other"]

    def test_forgets_user_bound(self) -> None:
        """Drop the tokens bound to a user ID token alone."""
        tokens = ServiceTokens()
        tokens.store(
            [
                ServiceToken.parse(
                    Tokens.service_token("user", master_token_serial_number=3, user_id_token_serial_number=7)
                ),
                ServiceToken.parse(Tokens.service_token("session", master_token_serial_number=3)),
            ]
        )
        tokens.forget_user_bound()
        assert list(tokens.tokens) == ["session"]

    def test_writes_wire(self) -> None:
        """Give the tokens as the server sent them, in the order received."""
        wire = [Tokens.service_token("sf"), Tokens.service_token("cad")]
        tokens = ServiceTokens()
        tokens.store([ServiceToken.parse(token) for token in wire])
        assert tokens.to_wire() == wire
