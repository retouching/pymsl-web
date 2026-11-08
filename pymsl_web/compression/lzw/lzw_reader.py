from typing import Final

from pydantic import BaseModel

BYTE_SIZE: Final = 8
BYTE_MASK: Final = 0xFF


class LZWReader(BaseModel):
    data: bytes
    index: int = 0
    offset: int = 0

    def read(self, bits: int) -> int | None:
        """Read the next code of `bits` bits, most significant first; give None when fewer bits remain."""
        if (len(self.data) - self.index) * BYTE_SIZE - self.offset < bits:
            return None
        code = 0
        decoded = 0
        while decoded < bits:
            length = min(bits - decoded, BYTE_SIZE - self.offset)
            value = ((self.data[self.index] << self.offset) & BYTE_MASK) >> (BYTE_SIZE - length)
            decoded += length
            self.offset += length
            if self.offset == BYTE_SIZE:
                self.offset = 0
                self.index += 1
            code |= value << (bits - decoded)
        return code
