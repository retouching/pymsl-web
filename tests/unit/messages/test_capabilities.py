import pytest

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.messages.capabilities import MessageCapabilities


class TestMessageCapabilities:
    def test_writes_wire(self) -> None:
        """Write the capabilities in the order of the owner's working code."""
        capabilities = MessageCapabilities(compression_algorithms=("GZIP",), languages=(), encoder_formats=("JSON",))
        assert capabilities.to_wire() == {"compressionalgos": ["GZIP"], "languages": [], "encoderformats": ["JSON"]}

    def test_reads_browser_answer(self) -> None:
        """Read the capabilities of the web service's answer, `maxpayloadchunksize` included."""
        capabilities = MessageCapabilities.parse(
            {"languages": [], "compressionalgos": ["LZW"], "maxpayloadchunksize": -1, "encoderformats": []}
        )
        assert capabilities.compression_algorithms == ("LZW",)
        assert capabilities.max_payload_chunk_size == -1

    def test_refuses_non_text(self) -> None:
        """Raise MSLMessageError for an algorithm that is not text."""
        with pytest.raises(MSLMessageError, match=r"^Capabilities: invalid"):
            MessageCapabilities.parse({"compressionalgos": [1]})
