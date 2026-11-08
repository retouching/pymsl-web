from typing import Final

import pytest
from curl_cffi import requests
from curl_cffi.requests.exceptions import ConnectionError as CurlConnectionError

from pymsl_web.client import MSLClient
from pymsl_web.configuration import MSLConfiguration
from pymsl_web.entityauth.schemes.none import NoneEntityAuthentication
from pymsl_web.enums import MSLResponseCode
from pymsl_web.exceptions import MSLError, MSLMessageError, MSLSessionError, MSLTransportError
from pymsl_web.keyexchange.asymmetric_wrapped.asymmetric_wrapped import AsymmetricWrappedKeyExchange
from pymsl_web.session.clock import Clock
from pymsl_web.session.session import MSLSession
from pymsl_web.userauth.schemes.netflix_id import NetflixIDUserAuthentication
from tests.unit.support.server import FakeServer
from tests.unit.support.tokens import Tokens

CONFIGURATION: Final = MSLConfiguration(
    url="https://example.com/msl",
    entity_authentication=NoneEntityAuthentication(identity="ESN"),
    key_exchange=AsymmetricWrappedKeyExchange(),
    user_authentication=NetflixIDUserAuthentication(netflix_id="id", secure_netflix_id="secure"),
)
COOKIES: Final = {"scheme": "NETFLIXID", "authdata": {"netflixid": "id", "securenetflixid": "secure"}}


class TestMSLClient:
    @staticmethod
    def client(server: FakeServer, configuration: MSLConfiguration = CONFIGURATION) -> MSLClient:
        """Build a client posting to `server`, at the server's time."""
        return MSLClient(configuration, http=server, clock=Clock(source=lambda: 1500.0))

    @staticmethod
    def started(server: FakeServer) -> MSLClient:
        """Build a client that went through a handshake."""
        client = TestMSLClient.client(server)
        client.handshake()
        return client

    def test_handshakes(self) -> None:
        """Get a master token and keys, sending the sender in clear and no user authentication."""
        server = FakeServer()
        client = self.client(server)
        client.handshake(url="https://example.com/handshake", params={"reqName": "manifest"})
        sent = server.headers[-1]
        assert sent["handshake"] is True
        assert sent["sender"] == "ESN"
        assert "userauthdata" not in sent
        assert server.posts[-1].url == "https://example.com/handshake"
        assert server.posts[-1].params == {"reqName": "manifest"}
        assert client.session.active

    def test_posts_to_configured_url(self) -> None:
        """Post to the configured URL when a call names none."""
        server = FakeServer()
        self.started(server)
        assert server.posts[-1].url == "https://example.com/msl"

    def test_keeps_session_on_failed_handshake(self) -> None:
        """Keep the old session when a handshake answer has no key response."""
        server = FakeServer()
        client = self.started(server)
        before = client.session.export()
        server.key_response = False
        with pytest.raises(MSLMessageError, match=r"key response"):
            client.handshake()
        assert client.session.export() == before

    def test_returns_data(self) -> None:
        """Give back the joined, decompressed data of the answer."""
        server = FakeServer()
        assert self.started(server).raw_request(b"hello") == b"echo:hello"
        assert server.posts[-1].data == b"hello"

    def test_sends_cookies_then_token(self) -> None:
        """Send NETFLIXID until the server gives a user ID token, then the token alone."""
        server = FakeServer(user_id_token=Tokens.user_id_token())
        client = self.started(server)
        client.raw_request(b"one")
        client.raw_request(b"two")
        assert server.headers[-2]["userauthdata"] == COOKIES
        assert "useridtoken" not in server.headers[-2]
        assert server.headers[-1]["useridtoken"] == Tokens.user_id_token()
        assert "userauthdata" not in server.headers[-1]

    def test_echoes_service_tokens(self) -> None:
        """Send back the service tokens the server gave."""
        server = FakeServer(service_tokens=[Tokens.service_token("cad")])
        client = self.started(server)
        client.raw_request(b"one")
        assert "servicetokens" not in server.headers[-1]
        client.raw_request(b"two")
        assert server.headers[-1]["servicetokens"] == [Tokens.service_token("cad")]

    def test_moves_message_id(self) -> None:
        """Send each request with the message ID after the previous one's."""
        server = FakeServer()
        client = self.started(server)
        client.raw_request(b"one")
        client.raw_request(b"two")
        first, second = server.headers[-2]["messageid"], server.headers[-1]["messageid"]
        assert isinstance(first, int)
        assert second == first + 1

    def test_refuses_without_session(self) -> None:
        """Raise MSLSessionError for a request before any handshake, and post nothing."""
        server = FakeServer()
        with pytest.raises(MSLSessionError):
            self.client(server).raw_request(b"one")
        assert server.posts == []

    @pytest.mark.parametrize(
        ("code", "master_token_kept", "user_id_token_kept"),
        [
            (MSLResponseCode.ENTITY_REAUTH, False, False),
            (MSLResponseCode.ENTITYDATA_REAUTH, False, False),
            (MSLResponseCode.USER_REAUTH, True, False),
            (MSLResponseCode.USERDATA_REAUTH, True, False),
            (MSLResponseCode.SSOTOKEN_REJECTED, True, False),
            (MSLResponseCode.EXPIRED, True, True),
            (MSLResponseCode.FAIL, True, True),
        ],
    )
    def test_cleans_after_error(self, code: MSLResponseCode, master_token_kept: bool, user_id_token_kept: bool) -> None:
        """Raise MSLError, forget what the reference forgets for its code, and move the message ID on by 1."""
        server = FakeServer(user_id_token=Tokens.user_id_token())
        client = self.started(server)
        client.raw_request(b"one")
        before = client.session.message_id
        server.error_code = code
        with pytest.raises(MSLError) as raised:
            client.raw_request(b"two")
        assert raised.value.code is code
        assert (client.session.master_token is not None) is master_token_kept
        assert (client.session.user_id_token is not None) is user_id_token_kept
        assert client.session.message_id == before + 1

    def test_sends_cookies_after_user_reauth(self) -> None:
        """Send NETFLIXID again after the server refused the user ID token."""
        server = FakeServer(user_id_token=Tokens.user_id_token())
        client = self.started(server)
        client.raw_request(b"one")
        server.error_code = MSLResponseCode.USER_REAUTH
        with pytest.raises(MSLError):
            client.raw_request(b"two")
        server.error_code = None
        client.raw_request(b"three")
        assert server.headers[-1]["userauthdata"] == COOKIES

    def test_keeps_session_on_bad_answer(self) -> None:
        """Leave the tokens and keys as they were when the answer has a wrong message ID."""
        server = FakeServer()
        client = self.started(server)
        before = client.session.export()
        server.message_id_shift = 2
        server.user_id_token = Tokens.user_id_token()
        with pytest.raises(MSLMessageError, match=r"message ID"):
            client.raw_request(b"one")
        after = client.session.export()
        assert after.model_copy(update={"message_id": before.message_id}) == before

    def test_refuses_bad_hmac(self) -> None:
        """Raise MSLMessageError for an answer whose HMAC does not match."""
        server = FakeServer()
        client = self.started(server)
        server.hmac_tampered = True
        with pytest.raises(MSLMessageError):
            client.raw_request(b"one")

    def test_skips_hmac_when_off(self) -> None:
        """Read an answer whose HMAC does not match when `verify_signatures` is off."""
        server = FakeServer()
        configuration = CONFIGURATION.model_copy(update={"verify_signatures": False})
        client = self.client(server, configuration)
        client.handshake()
        server.hmac_tampered = True
        assert client.raw_request(b"one") == b"echo:one"

    def test_raises_transport_error(self) -> None:
        """Raise MSLTransportError and keep the message ID when the server cannot be reached."""
        server = FakeServer()
        client = self.started(server)
        before = client.session.message_id
        server.failure = CurlConnectionError("down")
        with pytest.raises(MSLTransportError):
            client.raw_request(b"one")
        assert client.session.message_id == before

    def test_refuses_other_sender(self) -> None:
        """Raise MSLSessionError for a restored session of another identity."""
        with pytest.raises(MSLSessionError, match=r"sender"):
            MSLClient(CONFIGURATION, http=FakeServer(), session=MSLSession.new("OTHER"))

    def test_restores_and_requests(self) -> None:
        """Send a request with a session exported by another client, without a new handshake."""
        server = FakeServer()
        text = self.started(server).session.export().model_dump_json()
        client = MSLClient(CONFIGURATION, http=server, session=MSLSession.restore_json(text))
        assert client.raw_request(b"again") == b"echo:again"
        assert len(server.posts) == 2

    def test_works_as_context_manager(self) -> None:
        """Close the client at the end of a with block."""
        with MSLClient(CONFIGURATION, http=FakeServer()) as client:
            assert not client.session.active

    def test_accepts_curl_session(self) -> None:
        """Take a curl_cffi session of the application, typed as such, and leave it open."""
        session = requests.Session()
        with MSLClient(CONFIGURATION, http=session) as client:
            assert not client.transport.owned
        session.close()

    def test_requests_json(self) -> None:
        """Send the payload as compact JSON and give the JSON of the answer."""
        server = FakeServer(echo_prefix=b"")
        answer = self.started(server).request({"version": 2, "params": ["a", "é"]})
        assert server.posts[-1].data == '{"version":2,"params":["a","é"]}'.encode()
        assert answer == {"version": 2, "params": ["a", "é"]}

    def test_refuses_non_json_answer(self) -> None:
        """Raise MSLMessageError when the answer of a JSON request is not JSON."""
        server = FakeServer()
        with pytest.raises(MSLMessageError, match=r"^Answer: invalid"):
            self.started(server).request({"version": 2})
