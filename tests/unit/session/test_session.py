from typing import Final

import pytest

from pymsl_web.crypto.session_keys import SessionKeys
from pymsl_web.exceptions import MSLSessionError
from pymsl_web.messages.header_data import HeaderData
from pymsl_web.session.clock import Clock
from pymsl_web.session.session import MSLSession
from pymsl_web.tokens.master_token import MasterToken
from tests.unit.support.tokens import Tokens

KEYS: Final = SessionKeys(encryption=bytes(range(16)), hmac=b"\x02" * 32)


class TestMSLSession:
    @staticmethod
    def started(*, now: float = 1500.0, serial_number: int = 1) -> MSLSession:
        """Give a session after a handshake whose answer gave a user ID token and two service tokens."""
        session = MSLSession.new("ESN", clock=Clock(source=lambda: now))
        header = HeaderData(
            message_id=1,
            timestamp=int(now),
            user_id_token=Tokens.user_id_token(master_token_serial_number=serial_number),
            service_tokens=[
                Tokens.service_token("session", master_token_serial_number=serial_number),
                Tokens.service_token("user", master_token_serial_number=serial_number, user_id_token_serial_number=7),
                Tokens.service_token("free"),
            ],
        )
        session.start(MasterToken.parse(Tokens.master_token(serial_number=serial_number)), KEYS, header)
        return session

    def test_starts_empty(self) -> None:
        """Start without master token: inactive, expired, not renewable, a message ID within 2^52."""
        session = MSLSession.new("ESN")
        assert not session.active
        assert session.expired
        assert not session.renewable
        assert 0 <= session.message_id <= 2**52

    def test_starts(self) -> None:
        """Keep the master token, the keys and the tokens of the handshake answer."""
        session = self.started()
        assert session.active
        assert session.user_id_token is not None
        assert len(session.service_tokens) == 3

    def test_draws_message_id_at_start(self) -> None:
        """Draw a new message ID at each handshake."""
        session = MSLSession.new("ESN")
        ids = set()
        for _ in range(3):
            session.start(MasterToken.parse(Tokens.master_token()), KEYS, HeaderData(message_id=1))
            ids.add(session.message_id)
        assert len(ids) > 1

    def test_tells_expired_in_server_time(self) -> None:
        """Tell expired by the server's time, not the local one."""
        session = self.started(now=1500.0)
        assert not session.expired
        session.clock.synchronize(2500)
        assert session.expired

    def test_tells_renewable(self) -> None:
        """Tell renewable once the server's time enters the renewal window."""
        assert not self.started(now=900.0).renewable
        assert self.started(now=1500.0).renewable

    def test_gives_crypto_context(self) -> None:
        """Give the session context of key ID sender_sequencenumber."""
        assert self.started().crypto_context().key_id == "ESN_25"

    def test_refuses_crypto_context_without_session(self) -> None:
        """Raise MSLSessionError for the context of a session without master token."""
        with pytest.raises(MSLSessionError):
            MSLSession.new("ESN").crypto_context()

    def test_starts_and_forgets_old_user(self) -> None:
        """Drop the user ID token and the service tokens of the old master token at a new handshake."""
        session = self.started(serial_number=1)
        session.start(MasterToken.parse(Tokens.master_token(serial_number=2)), KEYS, HeaderData(message_id=1))
        assert session.user_id_token is None
        assert list(session.service_tokens.tokens) == ["free"]

    def test_forgets_entity(self) -> None:
        """Drop the master token, the keys, the user ID token and the bound service tokens."""
        session = self.started()
        session.forget_entity()
        assert not session.active
        assert session.master_token is None
        assert session.user_id_token is None
        assert list(session.service_tokens.tokens) == ["free"]

    def test_forgets_user(self) -> None:
        """Drop the user ID token and the service tokens bound to it alone."""
        session = self.started()
        session.forget_user()
        assert session.active
        assert session.user_id_token is None
        assert sorted(session.service_tokens.tokens) == ["free", "session"]

    def test_stores_answer(self) -> None:
        """Keep the user ID token and the service tokens of an answer, and follow its timestamp."""
        session = self.started(now=1500.0)
        session.store(HeaderData(message_id=2, timestamp=1600, service_tokens=[Tokens.service_token("free", data="")]))
        assert session.clock.now() == 1600
        assert "free" not in session.service_tokens.tokens

    def test_advances(self) -> None:
        """Move the message ID on by one."""
        session = self.started()
        before = session.message_id
        session.advance()
        assert session.message_id == before + 1

    def test_wraps_message_id(self) -> None:
        """Go back to 0 after 2^53 - 1."""
        session = MSLSession.new("ESN")
        session.message_id = 2**53 - 1
        session.advance()
        assert session.message_id == 0

    def test_round_trips(self) -> None:
        """Restore what it exported, through JSON text."""
        session = self.started()
        session.clock.synchronize(1600)
        restored = MSLSession.restore_json(session.export().model_dump_json(), clock=Clock(source=lambda: 1500.0))
        assert restored.export() == session.export()
        assert restored.clock.now() == 1600
        assert restored.crypto_context().keys == KEYS

    def test_round_trips_empty(self) -> None:
        """Restore a session exported before any handshake."""
        session = MSLSession.new("ESN")
        assert MSLSession.restore(session.export()).export() == session.export()
