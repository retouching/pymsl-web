from typing import Final

BYTE_SIZE: Final = 8
MAX_RATIO: Final = 200


class LZW:
    @staticmethod
    def compress(data: bytes) -> bytes | None:
        """Compress `data` as `util/LzwCompression.js` of Netflix/msl does, or give None when it would not shrink."""
        dictionary = {bytes([value]): value for value in range(256)}
        output = bytearray(len(data))
        index, available, bits = 0, BYTE_SIZE, BYTE_SIZE
        symbols = b""
        codes: list[tuple[int, int]] = []
        for value in data:
            candidate = symbols + bytes([value])
            if candidate in dictionary:
                symbols = candidate
                continue
            codes.append((dictionary[symbols], bits))
            if len(dictionary) >> bits != 0:
                bits += 1
            dictionary[candidate] = len(dictionary)
            symbols = bytes([value])
        if symbols:
            codes.append((dictionary[symbols], bits))
        for code, width in codes:
            remaining = width
            while remaining > 0:
                if index >= len(output):
                    return None
                if remaining > available:
                    output[index] |= (code >> (remaining - available)) & 0xFF
                    remaining -= available
                    available = BYTE_SIZE
                    index += 1
                else:
                    output[index] |= ((code << (available - remaining)) & 0xFF) >> (BYTE_SIZE - available)
                    available -= remaining
                    remaining = 0
                    if available == 0:
                        available = BYTE_SIZE
                        index += 1
        return bytes(output[: index + 1 if available < BYTE_SIZE else index])

    @staticmethod
    def decompress(data: bytes) -> bytes:
        """Decompress the LZW `data` as `util/LzwCompression.js` of Netflix/msl does."""
        dictionary = [bytes([value]) for value in range(256)]
        output = bytearray()
        position, bits = 0, BYTE_SIZE
        previous = b""
        total = len(data) * BYTE_SIZE
        while total - position >= bits:
            code = 0
            for offset in range(bits):
                bit = (data[(position + offset) // BYTE_SIZE] >> (7 - (position + offset) % BYTE_SIZE)) & 1
                code = (code << 1) | bit
            position += bits
            value = dictionary[code] if code < len(dictionary) else None
            if not previous:
                if value is None:
                    raise ValueError("unknown code")
                bits += 1
            else:
                dictionary.append(previous + (previous[:1] if value is None else value[:1]))
                if len(dictionary) == 1 << bits:
                    bits += 1
                if value is None:
                    value = dictionary[code]
            output += value
            if len(output) > MAX_RATIO * len(data):
                raise ValueError("deflate ratio exceeded")
            previous = value
        return bytes(output)
