from collections.abc import Mapping
from typing import Self, cast
from urllib.parse import urlsplit

from curl_cffi import requests

from pymsl_web.exceptions import MSLTransportError
from pymsl_web.transport.http_poster import HTTPPoster
from pymsl_web.utils.messages import message


class HTTPTransport:
    def __init__(self, poster: HTTPPoster, *, owned: bool) -> None:
        """Keep the session that posts the messages, and whether this transport built it."""
        self.poster = poster
        self.owned = owned

    @classmethod
    def create(cls, poster: HTTPPoster | None) -> Self:
        """Use the session the application gives, or build a curl_cffi session of its own."""
        if poster is None:
            return cls(cast("HTTPPoster", requests.Session()), owned=True)
        return cls(poster, owned=False)

    def post(self, url: str, params: Mapping[str, str] | None, body: bytes) -> bytes:
        """Post `body` to `url` and give the body of the answer; raise MSLTransportError when the server cannot be
        reached or answers a status outside 200-299."""
        host = urlsplit(url).hostname or url
        try:
            answer = self.poster.post(url, params=None if params is None else dict(params), data=body)
            status, content = answer.status_code, answer.content
        except OSError as error:
            raise MSLTransportError(message("MSL", "unreachable", host)) from error
        if not 200 <= status < 300:
            raise MSLTransportError(message("MSL", "refused", host, f"HTTP {status}"))
        return content

    def close(self) -> None:
        """Close the session this transport built; leave a session of the application open."""
        if self.owned:
            closer = getattr(self.poster, "close", None)
            if callable(closer):
                closer()
