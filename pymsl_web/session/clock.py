import time
from collections.abc import Callable

from pydantic import BaseModel, Field


class Clock(BaseModel):
    offset: int | None = None
    source: Callable[[], float] = Field(default=time.time, exclude=True, repr=False)

    def local(self) -> int:
        """Give the local time, in seconds."""
        return int(self.source())

    def now(self) -> int:
        """Give the server's time, in seconds: the local time moved by the offset of the last answer."""
        return self.local() + (self.offset or 0)

    def synchronize(self, server_timestamp: int) -> None:
        """Keep the gap between the server's `server_timestamp` and the local time."""
        self.offset = server_timestamp - self.local()
