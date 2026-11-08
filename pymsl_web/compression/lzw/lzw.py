from typing import ClassVar, Final

from pymsl_web.compression.compression import MAX_DEFLATE_RATIO, Compression
from pymsl_web.compression.lzw.lzw_reader import LZWReader
from pymsl_web.compression.lzw.lzw_writer import LZWWriter
from pymsl_web.enums import CompressionAlgorithm
from pymsl_web.exceptions import MSLMessageError
from pymsl_web.utils.messages import message

BYTE_SIZE: Final = 8
BYTE_RANGE: Final = 256


class LZWCompression(Compression):
    algorithm: ClassVar[CompressionAlgorithm] = CompressionAlgorithm.LZW

    def compress(self, data: bytes) -> bytes | None:
        """Give `data` compressed as MSL's LZW does (`util/LzwCompression.js`), or None when the result would not be
        shorter than `data`."""
        dictionary = {bytes([value]): value for value in range(BYTE_RANGE)}
        writer = LZWWriter(capacity=len(data))
        bits = BYTE_SIZE
        symbols = b""
        for value in data:
            candidate = symbols + bytes([value])
            if candidate in dictionary:
                symbols = candidate
                continue
            if not writer.emit(dictionary[symbols], bits):
                return None
            if len(dictionary) >> bits != 0:
                bits += 1
            dictionary[candidate] = len(dictionary)
            symbols = bytes([value])
        if symbols and not writer.emit(dictionary[symbols], bits):
            return None
        return writer.result()

    def decompress(self, data: bytes) -> bytes:
        """Give the bytes of the LZW `data` as MSL's LZW reads them; raise MSLMessageError for an unknown code or data
        that inflates beyond `MAX_DEFLATE_RATIO` times its size."""
        dictionary = [bytes([value]) for value in range(BYTE_RANGE)]
        reader = LZWReader(data=data)
        limit = MAX_DEFLATE_RATIO * len(data)
        output = bytearray()
        bits = BYTE_SIZE
        previous = b""
        while (code := reader.read(bits)) is not None:
            value = dictionary[code] if code < len(dictionary) else None
            if not previous:
                if value is None:
                    raise MSLMessageError(message("LZW", "invalid", f"unknown code {code}"))
                bits += 1
            else:
                entry = previous + (previous[:1] if value is None else value[:1])
                dictionary.append(entry)
                if len(dictionary) == 1 << bits:
                    bits += 1
                if value is None:
                    if code >= len(dictionary):
                        raise MSLMessageError(message("LZW", "invalid", f"unknown code {code}"))
                    value = dictionary[code]
            if len(output) + len(value) > limit:
                raise MSLMessageError(message("LZW", "invalid", f"deflate ratio {MAX_DEFLATE_RATIO} exceeded"))
            output += value
            previous = value
        return bytes(output)
