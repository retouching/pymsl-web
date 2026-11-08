from typing import Protocol


class HTTPAnswer(Protocol):
    @property
    def status_code(self) -> int:
        """Give the HTTP status of the answer."""
        ...

    @property
    def content(self) -> bytes:
        """Give the body of the answer."""
        ...


class HTTPPoster(Protocol):
    def post(self, url: str, *, params: dict[str, str] | None, data: bytes) -> HTTPAnswer:
        """Post `data` to `url` with the query parameters `params`."""
        ...
