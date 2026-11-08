from typing import ClassVar

from pydantic import BaseModel

from pymsl_web.compression.compression import Compression
from pymsl_web.compression.gzip import GZIPCompression
from pymsl_web.compression.lzw import LZWCompression
from pymsl_web.enums import CompressionAlgorithm
from pymsl_web.exceptions import MSLMessageError
from pymsl_web.utils.messages import message


class Compressions(BaseModel):
    known: ClassVar[dict[str, Compression]] = {
        CompressionAlgorithm.GZIP: GZIPCompression(),
        CompressionAlgorithm.LZW: LZWCompression(),
    }

    @classmethod
    def get(cls, algorithm: CompressionAlgorithm | str) -> Compression:
        """Give the compression of the wire name `algorithm`; raise MSLMessageError for a name MSL does not define."""
        compression = cls.known.get(str(algorithm))
        if compression is None:
            raise MSLMessageError(message("Compression", "unsupported", str(algorithm)))
        return compression
