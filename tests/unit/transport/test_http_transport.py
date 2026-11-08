from collections.abc import Mapping

import pytest
from curl_cffi.requests.exceptions import ConnectionError as CurlConnectionError
from pydantic import BaseModel, ConfigDict, Field

from pymsl_web.exceptions import MSLTransportError
from pymsl_web.transport.http_transport import HTTPTransport


class Response(BaseModel):
    status_code: int
    content: bytes


class Poster(BaseModel):
    status_code: int = 200
    failure: OSError | None = Field(default=None)
    calls: list[tuple[str, dict[str, str] | None, bytes]] = Field(default_factory=list)
    closed: bool = False

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def post(self, url: str, *, params: Mapping[str, str] | None, data: bytes) -> Response:
        """Record the call and answer with the configured status."""
        if self.failure is not None:
            raise self.failure
        self.calls.append((url, None if params is None else dict(params), data))
        return Response(status_code=self.status_code, content=b"answer")

    def close(self) -> None:
        """Remember that the session was closed."""
        self.closed = True


class TestHTTPTransport:
    def test_posts_body_and_params(self) -> None:
        """Post the body with the query parameters and give the answer's bytes."""
        poster = Poster()
        transport = HTTPTransport.create(poster)
        assert transport.post("https://example.com/msl", {"a": "1"}, b"body") == b"answer"
        assert poster.calls == [("https://example.com/msl", {"a": "1"}, b"body")]

    def test_refuses_status(self) -> None:
        """Raise MSLTransportError naming the host and the status for a 503."""
        transport = HTTPTransport.create(Poster(status_code=503))
        with pytest.raises(MSLTransportError, match=r"^MSL: refused \(example.com, HTTP 503\)$"):
            transport.post("https://example.com/msl", None, b"body")

    def test_wraps_failure(self) -> None:
        """Raise MSLTransportError when the poster raises a curl_cffi error."""
        transport = HTTPTransport.create(Poster(failure=CurlConnectionError("down")))
        with pytest.raises(MSLTransportError, match=r"^MSL: unreachable \(example.com\)$"):
            transport.post("https://example.com/msl", None, b"body")

    def test_leaves_given_session_open(self) -> None:
        """Leave open a session the application gave."""
        poster = Poster()
        HTTPTransport.create(poster).close()
        assert not poster.closed

    def test_builds_and_closes_own_session(self) -> None:
        """Build a curl_cffi session without one given, and close it."""
        transport = HTTPTransport.create(None)
        assert transport.owned
        transport.close()
