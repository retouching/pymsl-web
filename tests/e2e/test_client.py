import urllib.request
from typing import Final

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pymsl_web import (
    AsymmetricWrappedKeyExchange,
    CompressionAlgorithm,
    MSLClient,
    MSLConfiguration,
    MSLError,
    MSLMessageError,
    MSLResponseCode,
    MSLSession,
    NetflixIDUserAuthentication,
    NoneEntityAuthentication,
)
from tests.e2e.stack import Stack

ESN: Final = "NFCDCH-02-E2E"


@pytest.mark.e2e
class TestClient:
    @staticmethod
    def configuration(stack: Stack, **changes: object) -> MSLConfiguration:
        """Build the configuration of the web player against the fake server, with `changes`."""
        fields: dict[str, object] = {
            "url": f"{stack.url()}/msl",
            "entity_authentication": NoneEntityAuthentication(identity=ESN),
            "key_exchange": AsymmetricWrappedKeyExchange(),
            "user_authentication": NetflixIDUserAuthentication(netflix_id="e2e-id", secure_netflix_id="e2e-secure"),
        }
        return MSLConfiguration.model_validate({**fields, **changes})

    @staticmethod
    def server_key(stack: Stack) -> bytes:
        """Fetch the PEM public key of the fake server."""
        with urllib.request.urlopen(f"{stack.url()}/key", timeout=10) as answer:  # noqa: S310
            key: bytes = answer.read()
            return key

    def test_handshakes_and_requests(self, stack: Stack) -> None:
        """Handshake, then get the echo of two requests, the second one with the user ID token alone."""
        with MSLClient(self.configuration(stack)) as client:
            client.handshake(params={"reqName": "manifest"})
            assert client.session.active
            assert not client.session.expired
            assert client.raw_request(b"hello", params={"reqName": "manifest"}) == b"echo:cookies:hello"
            assert client.raw_request(b"again") == b"echo:token:again"

    @pytest.mark.parametrize("compression", [CompressionAlgorithm.GZIP, CompressionAlgorithm.LZW, None])
    def test_compresses(self, stack: Stack, compression: CompressionAlgorithm | None) -> None:
        """Get the echo of a request sent with each compression."""
        data = b'{"version":2,"url":"/manifest","params":{"a":1,"a":1,"a":1}}' * 20
        with MSLClient(self.configuration(stack, compression=compression)) as client:
            client.handshake()
            assert client.raw_request(data) == b"echo:cookies:" + data

    def test_verifies_server(self, stack: Stack) -> None:
        """Handshake with the server's public key configured, and fail with another key."""
        with MSLClient(self.configuration(stack, server_public_keys=(self.server_key(stack),))) as client:
            client.handshake()
            assert client.session.active
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        pem = other.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with MSLClient(self.configuration(stack, server_public_keys=(pem,))) as client, pytest.raises(MSLMessageError):
            client.handshake()

    def test_raises_user_reauth(self, stack: Stack) -> None:
        """Raise MSLError USER_REAUTH, then authenticate again with the cookies on the next request."""
        with MSLClient(self.configuration(stack)) as client:
            client.handshake()
            client.raw_request(b"one")
            with pytest.raises(MSLError) as raised:
                client.raw_request(b"error:USER_REAUTH")
            assert raised.value.code is MSLResponseCode.USER_REAUTH
            assert client.raw_request(b"two") == b"echo:cookies:two"

    def test_forgets_entity(self, stack: Stack) -> None:
        """Forget the master token after ENTITY_REAUTH, and work again after a new handshake."""
        with MSLClient(self.configuration(stack)) as client:
            client.handshake()
            with pytest.raises(MSLError):
                client.raw_request(b"error:ENTITY_REAUTH")
            assert not client.session.active
            client.handshake()
            assert client.raw_request(b"back") == b"echo:cookies:back"

    def test_restores(self, stack: Stack) -> None:
        """Request with a session exported as JSON text and restored in a new client."""
        configuration = self.configuration(stack)
        with MSLClient(configuration) as client:
            client.handshake()
            client.raw_request(b"one")
            text = client.session.export().model_dump_json()
        with MSLClient(configuration, session=MSLSession.restore_json(text)) as client:
            assert client.raw_request(b"two") == b"echo:token:two"
