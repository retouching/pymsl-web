from typing import Final

from pydantic import BaseModel, ConfigDict, Field

BYTE_SIZE: Final = 8
BYTE_MASK: Final = 0xFF


class LZWWriter(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    capacity: int
    output: bytearray = Field(default_factory=bytearray)
    index: int = 0
    available: int = BYTE_SIZE

    def emit(self, code: int, bits: int) -> bool:
        """Write the `bits` low bits of `code`, most significant first; give False when they do not fit in the
        capacity."""
        while bits > 0:
            if self.index >= self.capacity:
                return False
            if self.index == len(self.output):
                self.output.append(0)
            if bits > self.available:
                self.output[self.index] |= (code >> (bits - self.available)) & BYTE_MASK
                bits -= self.available
                self.available = BYTE_SIZE
                self.index += 1
            else:
                shifted = (code << (self.available - bits)) & BYTE_MASK
                self.output[self.index] |= shifted >> (BYTE_SIZE - self.available)
                self.available -= bits
                bits = 0
                if self.available == 0:
                    self.available = BYTE_SIZE
                    self.index += 1
        return True

    def result(self) -> bytes:
        """Give the bytes written, the last one included when it is partly filled."""
        length = self.index + 1 if self.available < BYTE_SIZE else self.index
        return bytes(self.output[:length])
