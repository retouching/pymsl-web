import secrets
from typing import Final, Self

from pydantic import BaseModel, Field, ValidationError

from pymsl_web.crypto.session_crypto_context import SessionCryptoContext
from pymsl_web.crypto.session_keys import SessionKeys
from pymsl_web.exceptions import MSLSessionError, PyMSLError
from pymsl_web.messages.header_data import HeaderData
from pymsl_web.session.clock import Clock
from pymsl_web.session.session_state import MSLSessionState
from pymsl_web.tokens.master_token import MasterToken
from pymsl_web.tokens.service_token import ServiceToken
from pymsl_web.tokens.service_tokens import ServiceTokens
from pymsl_web.tokens.user_id_token import UserIDToken
from pymsl_web.utils.base64 import decode, encode
from pymsl_web.utils.messages import message

FIRST_MESSAGE_ID_LIMIT: Final = 2**52
MAX_MESSAGE_ID: Final = 2**53 - 1
STATE_SUBJECT: Final = "Session state"


class MSLSession(BaseModel):
    sender: str
    master_token: MasterToken | None = None
    keys: SessionKeys | None = Field(default=None, repr=False)
    user_id_token: UserIDToken | None = None
    service_tokens: ServiceTokens = Field(default_factory=ServiceTokens)
    message_id: int
    clock: Clock = Field(default_factory=Clock)

    @classmethod
    def new(cls, sender: str, *, clock: Clock | None = None) -> Self:
        """Give an empty session of `sender`, its message ID drawn as the owner's working code does."""
        return cls(sender=sender, message_id=cls.draw_message_id(), clock=clock or Clock())

    @staticmethod
    def draw_message_id() -> int:
        """Draw a message ID in [0, 2^52]."""
        return secrets.randbelow(FIRST_MESSAGE_ID_LIMIT + 1)

    @property
    def active(self) -> bool:
        """Tell whether the session has a master token and its keys."""
        return self.master_token is not None and self.keys is not None

    @property
    def expired(self) -> bool:
        """Tell whether the master token expired in the server's time; a session without one counts as expired."""
        return self.master_token is None or self.master_token.is_expired(self.clock.now())

    @property
    def renewable(self) -> bool:
        """Tell whether the master token entered its renewal window in the server's time."""
        return self.master_token is not None and self.master_token.is_renewable(self.clock.now())

    def crypto_context(self) -> SessionCryptoContext:
        """Give the context of the session keys, of key ID `<sender>_<sequence number>`; raise MSLSessionError
        without a master token."""
        if self.master_token is None or self.keys is None:
            raise MSLSessionError(message("MSL session", "missing", "call handshake first"))
        return SessionCryptoContext(keys=self.keys, key_id=f"{self.sender}_{self.master_token.sequence_number}")

    def start(self, master_token: MasterToken, keys: SessionKeys, header: HeaderData) -> None:
        """Take the master token and the keys of a handshake answer, forget the user and the service tokens of the
        old master token, keep what the answer gives and draw a new message ID."""
        if self.master_token is not None:
            self.service_tokens.forget_bound_to(self.master_token.serial_number)
        self.service_tokens.forget_user_bound()
        self.user_id_token = None
        self.master_token = master_token
        self.keys = keys
        self.store(header)
        self.message_id = self.draw_message_id()

    def store(self, header: HeaderData) -> None:
        """Follow the timestamp of an answer and keep its user ID token and its service tokens."""
        if header.timestamp is not None:
            self.clock.synchronize(header.timestamp)
        if header.user_id_token is not None:
            self.user_id_token = UserIDToken.parse(header.user_id_token)
        self.service_tokens.store(ServiceToken.parse(token) for token in header.service_tokens)

    def advance(self) -> None:
        """Move the message ID on by one, back to 0 after 2^53 - 1."""
        self.message_id = 0 if self.message_id >= MAX_MESSAGE_ID else self.message_id + 1

    def forget_entity(self) -> None:
        """Drop the master token, its keys, the user ID token and the service tokens bound to them."""
        if self.master_token is not None:
            self.service_tokens.forget_bound_to(self.master_token.serial_number)
        self.forget_user()
        self.master_token = None
        self.keys = None

    def forget_user(self) -> None:
        """Drop the user ID token and the service tokens bound to it."""
        self.user_id_token = None
        self.service_tokens.forget_user_bound()

    def export(self) -> MSLSessionState:
        """Give the state of the session as data, the session keys in Base64."""
        return MSLSessionState(
            sender=self.sender,
            master_token=None if self.master_token is None else self.master_token.data,
            encryption_key=None if self.keys is None else encode(self.keys.encryption),
            hmac_key=None if self.keys is None else encode(self.keys.hmac),
            user_id_token=None if self.user_id_token is None else self.user_id_token.data,
            service_tokens=[token.data for token in self.service_tokens.tokens.values()],
            message_id=self.message_id,
            clock_offset=self.clock.offset,
        )

    @classmethod
    def restore(cls, state: MSLSessionState, *, clock: Clock | None = None) -> Self:
        """Rebuild the session of `state`; raise MSLSessionError for a state whose tokens or keys cannot be read."""
        try:
            master_token = None if state.master_token is None else MasterToken.parse(state.master_token.to_wire())
            if (state.encryption_key is None) != (state.hmac_key is None):
                raise MSLSessionError(message(STATE_SUBJECT, "invalid", "both keys or none expected"))
            keys = (
                None
                if state.encryption_key is None or state.hmac_key is None
                else SessionKeys(
                    encryption=decode(state.encryption_key, context=STATE_SUBJECT),
                    hmac=decode(state.hmac_key, context=STATE_SUBJECT),
                )
            )
            user_id_token = None if state.user_id_token is None else UserIDToken.parse(state.user_id_token.to_wire())
            service_tokens = ServiceTokens()
            service_tokens.store(ServiceToken.parse(token.to_wire()) for token in state.service_tokens)
        except MSLSessionError:
            raise
        except (PyMSLError, ValueError) as error:
            raise MSLSessionError(message(STATE_SUBJECT, "invalid", str(error))) from error
        restored_clock = clock or Clock()
        restored_clock.offset = state.clock_offset
        return cls(
            sender=state.sender,
            master_token=master_token,
            keys=keys,
            user_id_token=user_id_token,
            service_tokens=service_tokens,
            message_id=state.message_id,
            clock=restored_clock,
        )

    @classmethod
    def restore_json(cls, text: str | bytes, *, clock: Clock | None = None) -> Self:
        """Rebuild the session of the JSON `text` of a state; raise MSLSessionError for a malformed state."""
        try:
            state = MSLSessionState.model_validate_json(text)
        except ValidationError as error:
            raise MSLSessionError(message(STATE_SUBJECT, "invalid", str(error.errors()[0]["loc"]))) from error
        return cls.restore(state, clock=clock)
