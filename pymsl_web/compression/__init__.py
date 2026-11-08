from pymsl_web.compression.compression import MAX_DEFLATE_RATIO, Compression
from pymsl_web.compression.compressions import Compressions
from pymsl_web.compression.gzip import GZIPCompression
from pymsl_web.compression.lzw import LZWCompression

__all__ = ["MAX_DEFLATE_RATIO", "Compression", "Compressions", "GZIPCompression", "LZWCompression"]
