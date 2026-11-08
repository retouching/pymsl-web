from typing import Final

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pymsl_web.compression.lzw import LZWCompression
from pymsl_web.exceptions import MSLMessageError

LZW_VECTORS: Final = (
    (b"", ""),
    (b"a", "61"),
    (b"a" * 40, "61804060503824160d02"),
    (b"TOBEORNOTTOBEORTOBEORNOT", "54279088a4f291389e548040a090981c160e"),
    (
        b'{"version":2,"url":"/manifest","params":{"a":1,"a":1,"a":1}}',
        "7b111d8ca72399a4de6e110e8642c111d4e46c848885e6d309b8d266329cce822861c0c272309b4e709801861231864987528114a"
        "8627d3e80",
    ),
)


class TestLZWCompression:
    @pytest.mark.parametrize(("data", "compressed"), LZW_VECTORS)
    def test_compresses_as_the_reference(self, data: bytes, compressed: str) -> None:
        """Write the same bytes as the JavaScript reference."""
        assert LZWCompression().compress(data) == bytes.fromhex(compressed)

    @pytest.mark.parametrize(("data", "compressed"), LZW_VECTORS)
    def test_decompresses_as_the_reference(self, data: bytes, compressed: str) -> None:
        """Read the bytes the JavaScript reference wrote."""
        assert LZWCompression().decompress(bytes.fromhex(compressed)) == data

    def test_decompresses_wider_code(self) -> None:
        """Decode two codes, the second one 9 bits wide."""
        assert LZWCompression().decompress(bytes.fromhex("613080")) == b"aa"

    def test_gives_up_when_longer(self) -> None:
        """Give None when the compressed data would not be shorter than the data, as the reference does."""
        assert LZWCompression().compress(b"aa") is None

    def test_compresses_repetition(self) -> None:
        """Shrink a long repetition and give it back."""
        data = b"TOBEORNOTTOBEORTOBEORNOT" * 20
        compressed = LZWCompression().compress(data)
        assert compressed is not None
        assert len(compressed) < len(data)
        assert LZWCompression().decompress(compressed) == data

    @given(st.binary(max_size=2048))
    def test_round_trips(self, data: bytes) -> None:
        """Give back what it compressed, whenever it compressed."""
        compressed = LZWCompression().compress(data)
        if compressed is not None:
            assert LZWCompression().decompress(compressed) == data

    def test_refuses_a_bomb(self) -> None:
        """Raise MSLMessageError when the data inflates beyond 200 times its size."""
        bomb = LZWCompression().compress(b"\x00" * 1_000_000)
        assert bomb is not None
        with pytest.raises(MSLMessageError, match=r"ratio"):
            LZWCompression().decompress(bomb)

    def test_refuses_unknown_code(self) -> None:
        """Raise MSLMessageError for a code beyond the next dictionary entry."""
        with pytest.raises(MSLMessageError, match=r"^LZW: invalid"):
            LZWCompression().decompress(bytes.fromhex("61ff80"))
