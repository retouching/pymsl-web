from abc import ABC, abstractmethod
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict

from pymsl_web.enums import CompressionAlgorithm

MAX_DEFLATE_RATIO: Final = 200


class Compression(ABC, BaseModel):
    model_config = ConfigDict(frozen=True)

    algorithm: ClassVar[CompressionAlgorithm]

    @abstractmethod
    def compress(self, data: bytes) -> bytes | None:
        """Give `data` compressed, or None when this compression gives up on it."""

    @abstractmethod
    def decompress(self, data: bytes) -> bytes:
        """Give `data` decompressed; raise MSLMessageError for corrupt data or data that inflates beyond
        `MAX_DEFLATE_RATIO` times its size."""
