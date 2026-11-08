import pytest

from pymsl_web.compression.compressions import Compressions
from pymsl_web.compression.gzip import GZIPCompression
from pymsl_web.compression.lzw import LZWCompression
from pymsl_web.enums import CompressionAlgorithm
from pymsl_web.exceptions import MSLMessageError


class TestCompressions:
    def test_gets_by_name(self) -> None:
        """Give the compression of a wire name."""
        assert isinstance(Compressions.get("LZW"), LZWCompression)
        assert isinstance(Compressions.get(CompressionAlgorithm.GZIP), GZIPCompression)

    def test_refuses_unknown(self) -> None:
        """Raise MSLMessageError for a name MSL does not define."""
        with pytest.raises(MSLMessageError, match=r"^Compression: unsupported"):
            Compressions.get("BROTLI")
