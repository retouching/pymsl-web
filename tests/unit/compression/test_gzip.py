import gzip

import pytest

from pymsl_web.compression.gzip import GZIPCompression
from pymsl_web.exceptions import MSLMessageError


class TestGZIPCompression:
    def test_round_trips(self) -> None:
        """Give back what it compressed."""
        data = b'{"version":2}' * 10
        compressed = GZIPCompression().compress(data)
        assert compressed is not None
        assert GZIPCompression().decompress(compressed) == data

    def test_always_compresses(self) -> None:
        """Compress even when the result is longer, as the owner's working code does."""
        assert GZIPCompression().compress(b"a") is not None

    def test_reads_other_writer(self) -> None:
        """Read GZIP written by the standard library."""
        assert GZIPCompression().decompress(gzip.compress(b"hello")) == b"hello"

    def test_refuses_corrupt(self) -> None:
        """Raise MSLMessageError for bytes that are not GZIP."""
        with pytest.raises(MSLMessageError, match=r"^GZIP: invalid"):
            GZIPCompression().decompress(b"not gzip")

    def test_refuses_truncated(self) -> None:
        """Raise MSLMessageError for GZIP cut short."""
        with pytest.raises(MSLMessageError, match=r"^GZIP: invalid"):
            GZIPCompression().decompress(gzip.compress(b"hello" * 100)[:-10])

    def test_refuses_a_bomb(self) -> None:
        """Raise MSLMessageError when the data inflates beyond 200 times its size."""
        with pytest.raises(MSLMessageError, match=r"ratio"):
            GZIPCompression().decompress(gzip.compress(b"\x00" * 10_000_000))
