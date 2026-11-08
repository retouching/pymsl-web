from pymsl_web.crypto.null_crypto_context import NullCryptoContext


class TestNullCryptoContext:
    def test_keeps_data(self) -> None:
        """Give the data back as it is, encrypted or decrypted."""
        context = NullCryptoContext()
        assert context.encrypt(b"clear") == b"clear"
        assert context.decrypt(b"clear") == b"clear"

    def test_signs_empty(self) -> None:
        """Give an empty signature and accept any, as the `NONE` scheme does."""
        context = NullCryptoContext()
        assert context.sign(b"data") == b""
        assert context.verify(b"data", b"anything")
