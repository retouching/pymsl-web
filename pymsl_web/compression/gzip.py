import gzip
import zlib
from typing import ClassVar, Final

from pymsl_web.compression.compression import MAX_DEFLATE_RATIO, Compression
from pymsl_web.enums import CompressionAlgorithm
from pymsl_web.exceptions import MSLMessageError
from pymsl_web.utils.messages import message

GZIP_WINDOW_BITS: Final = 31
READ_SIZE: Final = 64 * 1024


class GZIPCompression(Compression):
    algorithm: ClassVar[CompressionAlgorithm] = CompressionAlgorithm.GZIP

    def compress(self, data: bytes) -> bytes:
        """Give `data` as GZIP, whatever its size, as the owner's working code does."""
        return gzip.compress(data)

    def decompress(self, data: bytes) -> bytes:
        """Give the bytes of the GZIP `data`, read by slices so that a bomb stops at `MAX_DEFLATE_RATIO` times its
        size; raise MSLMessageError for corrupt, truncated or inflating data."""
        limit = MAX_DEFLATE_RATIO * len(data)
        decompressor = zlib.decompressobj(wbits=GZIP_WINDOW_BITS)
        output = bytearray()
        pending = data
        try:
            while not decompressor.eof:
                chunk = decompressor.decompress(pending, READ_SIZE)
                output += chunk
                if len(output) > limit:
                    raise MSLMessageError(message("GZIP", "invalid", f"deflate ratio {MAX_DEFLATE_RATIO} exceeded"))
                pending = decompressor.unconsumed_tail
                if not chunk and not pending:
                    break
        except zlib.error as error:
            raise MSLMessageError(message("GZIP", "invalid", "corrupt data")) from error
        if not decompressor.eof:
            raise MSLMessageError(message("GZIP", "invalid", "truncated data"))
        return bytes(output)
