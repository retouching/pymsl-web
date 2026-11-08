import hashlib
import hmac
import os
from typing import Final

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pymsl_web.crypto.ciphertext_envelope import CiphertextEnvelope
from pymsl_web.crypto.crypto_context import CryptoContext
from pymsl_web.crypto.session_keys import SessionKeys
from pymsl_web.exceptions import MSLCryptoError
from pymsl_web.utils.messages import message

IV_SIZE: Final = 16
AES_BLOCK_BITS: Final = 128


class SessionCryptoContext(CryptoContext):
    keys: SessionKeys
    key_id: str

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt `data` with AES-128-CBC, PKCS#7 and a fresh IV, and give its envelope JSON."""
        iv = os.urandom(IV_SIZE)
        padder = padding.PKCS7(AES_BLOCK_BITS).padder()
        clear = padder.update(data) + padder.finalize()
        encryptor = Cipher(algorithms.AES(self.keys.encryption), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(clear) + encryptor.finalize()
        return CiphertextEnvelope(key_id=self.key_id, iv=iv, ciphertext=ciphertext).to_json()

    def decrypt(self, data: bytes) -> bytes:
        """Give the clear bytes of the envelope JSON `data`; raise MSLCryptoError when they cannot be decrypted."""
        envelope = CiphertextEnvelope.parse(data)
        try:
            decryptor = Cipher(algorithms.AES(self.keys.encryption), modes.CBC(envelope.iv)).decryptor()
            clear = decryptor.update(envelope.ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(AES_BLOCK_BITS).unpadder()
            return unpadder.update(clear) + unpadder.finalize()
        except ValueError as error:
            raise MSLCryptoError(message("Session", "invalid", "ciphertext or padding")) from error

    def sign(self, data: bytes) -> bytes:
        """Give the HMAC-SHA256 of `data`."""
        return hmac.new(self.keys.hmac, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Tell whether `signature` is the HMAC-SHA256 of `data`, in constant time."""
        return hmac.compare_digest(self.sign(data), signature)
