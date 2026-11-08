from pymsl_web.crypto.crypto_context import CryptoContext


class NullCryptoContext(CryptoContext):
    def encrypt(self, data: bytes) -> bytes:
        """Give `data` as it is: the `NONE` scheme does not encrypt."""
        return data

    def decrypt(self, data: bytes) -> bytes:
        """Give `data` as it is."""
        return data

    def sign(self, data: bytes) -> bytes:
        """Give an empty signature, as the web player sends with `NONE`."""
        return b""

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Accept any signature."""
        return True
