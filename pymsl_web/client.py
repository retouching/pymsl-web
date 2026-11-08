from collections.abc import Mapping
from types import TracebackType
from typing import Final, Self

from pymsl_web.configuration import MSLConfiguration
from pymsl_web.crypto.server_crypto_context import ServerCryptoContext
from pymsl_web.enums import MSLResponseCode
from pymsl_web.exceptions import MSLError, MSLMessageError, MSLSessionError
from pymsl_web.messages.capabilities import MessageCapabilities
from pymsl_web.messages.header_data import HeaderData
from pymsl_web.messages.message_reader import MessageReader
from pymsl_web.messages.message_writer import MessageWriter
from pymsl_web.session.clock import Clock
from pymsl_web.session.session import MSLSession
from pymsl_web.tokens.master_token import MasterToken
from pymsl_web.transport.http_poster import HTTPPoster
from pymsl_web.transport.http_transport import HTTPTransport
from pymsl_web.utils.json import JSONValue, dump, load
from pymsl_web.utils.messages import message

ENTITY_REAUTH_CODES: Final = frozenset({MSLResponseCode.ENTITY_REAUTH, MSLResponseCode.ENTITYDATA_REAUTH})
USER_REAUTH_CODES: Final = frozenset(
    {MSLResponseCode.USER_REAUTH, MSLResponseCode.USERDATA_REAUTH, MSLResponseCode.SSOTOKEN_REJECTED}
)


class MSLClient:
    def __init__(
        self,
        configuration: MSLConfiguration,
        *,
        http: HTTPPoster | None = None,
        session: MSLSession | None = None,
        clock: Clock | None = None,
    ) -> None:
        """Keep the configuration, the HTTP session (given or built) and the MSL session (restored or new); raise
        MSLSessionError for a restored session of another sender."""
        sender = configuration.entity_authentication.identity()
        if session is not None and session.sender != sender:
            raise MSLSessionError(message("MSL session", "invalid", f"sender {session.sender}, {sender} expected"))
        self.configuration = configuration
        self.transport = HTTPTransport.create(http)
        self.session = session if session is not None else MSLSession.new(sender, clock=clock)
        self.writer = MessageWriter()
        self.reader = MessageReader(
            server=ServerCryptoContext.from_keys(configuration.server_public_keys),
            verify_signatures=configuration.verify_signatures,
        )

    def __enter__(self) -> Self:
        """Give the client to a with block."""
        return self

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None, traceback: TracebackType | None
    ) -> None:
        """Close the client at the end of a with block."""
        self.close()

    def close(self) -> None:
        """Close the HTTP session the client built; leave a session of the application open."""
        self.transport.close()

    def capabilities(self) -> MessageCapabilities:
        """Give the capabilities of the configuration."""
        return MessageCapabilities(
            compression_algorithms=tuple(str(algorithm) for algorithm in self.configuration.compression_algorithms),
            languages=self.configuration.languages,
            encoder_formats=self.configuration.encoder_formats,
        )

    def handshake(self, *, url: str | None = None, params: Mapping[str, str] | None = None) -> None:
        """Run a handshake: send the sender in clear with a key request, then take the master token and the session
        keys of the answer. The session changes only when the whole answer is read."""
        exchange = self.configuration.key_exchange
        request = exchange.start()
        message_id = self.session.message_id
        header = HeaderData(
            message_id=message_id,
            renewable=self.configuration.renewable,
            handshake=True,
            capabilities=self.capabilities(),
            timestamp=self.session.clock.local(),
            sender=self.session.sender,
            key_request=request.to_wire(),
        )
        body = self.writer.handshake(
            entity_authentication=self.configuration.entity_authentication.to_wire(), header=header
        )
        answer = self.reader.read(
            self.transport.post(url or self.configuration.url, params, body),
            session=None,
            request_message_id=message_id,
        )
        response = answer.header.key_response
        if response is None:
            raise MSLMessageError(message("Answer", "invalid", "no key response"))
        if response.get("scheme") != exchange.scheme:
            raise MSLMessageError(message("Answer", "invalid", f"key response {exchange.scheme} expected"))
        keydata = response.get("keydata")
        if not isinstance(keydata, dict):
            raise MSLMessageError(message("Answer", "invalid", "keydata expected"))
        keys = exchange.finish(request, keydata)
        master_token = MasterToken.parse(response.get("mastertoken"))
        self.session.start(master_token, keys, answer.header)

    def request(
        self, payload: JSONValue, *, url: str | None = None, params: Mapping[str, str] | None = None
    ) -> JSONValue:
        """Send `payload` as compact JSON under the session and give the JSON of the answer; raise MSLMessageError
        for an answer that is not JSON, and the errors of `raw_request`."""
        answer = self.raw_request(dump(payload), url=url, params=params)
        try:
            return load(answer, context="Answer")
        except ValueError as error:
            raise MSLMessageError(str(error)) from error

    def raw_request(self, data: bytes, *, url: str | None = None, params: Mapping[str, str] | None = None) -> bytes:
        """Send `data` under the session and give the data of the answer; raise MSLSessionError without a session,
        and the MSLError of the server after forgetting what it refused."""
        session = self.session
        if session.master_token is None or not session.active:
            raise MSLSessionError(message("MSL session", "missing", "call handshake first"))
        context = session.crypto_context()
        user_id_token = None if session.user_id_token is None else session.user_id_token.data.to_wire()
        user_authentication = self.configuration.user_authentication
        message_id = session.message_id
        header = HeaderData(
            message_id=message_id,
            renewable=self.configuration.renewable,
            handshake=False,
            capabilities=self.capabilities(),
            timestamp=session.clock.local(),
            sender=session.sender,
            user_authentication=(
                user_authentication.to_wire() if user_id_token is None and user_authentication is not None else None
            ),
            user_id_token=user_id_token,
            service_tokens=session.service_tokens.to_wire(),
        )
        body = self.writer.request(
            master_token=session.master_token,
            header=header,
            context=context,
            data=data,
            compression=self.configuration.compression,
        )
        answer_body = self.transport.post(url or self.configuration.url, params, body)
        session.advance()
        try:
            answer = self.reader.read(answer_body, session=context, request_message_id=message_id)
        except MSLError as error:
            if error.code in ENTITY_REAUTH_CODES:
                session.forget_entity()
            elif error.code in USER_REAUTH_CODES:
                session.forget_user()
            raise
        session.store(answer.header)
        return answer.data
