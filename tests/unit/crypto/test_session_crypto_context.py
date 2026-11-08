import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pymsl_web.crypto.ciphertext_envelope import CiphertextEnvelope
from pymsl_web.crypto.session_crypto_context import SessionCryptoContext
from pymsl_web.crypto.session_keys import SessionKeys
from pymsl_web.exceptions import MSLCryptoError
from pymsl_web.utils.json import load_object

KEYS = SessionKeys(encryption=bytes(range(16)), hmac=b"\x02" * 32)


class TestSessionCryptoContext:
    def test_round_trips(self) -> None:
        """Decrypt what it encrypted, with a fresh IV each time."""
        context = SessionCryptoContext(keys=KEYS, key_id="ESN_1")
        first, second = context.encrypt(b"hello"), context.encrypt(b"hello")
        assert first != second
        assert context.decrypt(first) == b"hello"

    def test_writes_key_id(self) -> None:
        """Write its key ID in the envelope."""
        context = SessionCryptoContext(keys=KEYS, key_id="ESN_25")
        assert load_object(context.encrypt(b"x"), context="test")["keyid"] == "ESN_25"

    def test_decrypts_the_owner_format(self) -> None:
        """Decrypt an envelope built like the owner's `encrypt_payload`: AES-CBC, PKCS#7, a JSON envelope."""
        iv = b"\x07" * 16
        padder = padding.PKCS7(128).padder()
        clear = padder.update(b'{"messageid":1}') + padder.finalize()
        encryptor = Cipher(algorithms.AES(KEYS.encryption), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(clear) + encryptor.finalize()
        envelope = CiphertextEnvelope(key_id="ESN_1", iv=iv, ciphertext=ciphertext).to_json()
        assert SessionCryptoContext(keys=KEYS, key_id="ESN_1").decrypt(envelope) == b'{"messageid":1}'

    def test_signs_with_hmac(self) -> None:
        """Sign with HMAC-SHA256 of the HMAC key and verify the same bytes alone."""
        context = SessionCryptoContext(keys=KEYS, key_id="ESN_1")
        signature = context.sign(b"data")
        assert signature == hmac.new(KEYS.hmac, b"data", hashlib.sha256).digest()
        assert context.verify(b"data", signature)
        assert not context.verify(b"datA", signature)

    def test_refuses_bad_padding(self) -> None:
        """Raise MSLCryptoError when the clear bytes have no valid padding."""
        encryptor = Cipher(algorithms.AES(KEYS.encryption), modes.CBC(b"\x00" * 16)).encryptor()
        ciphertext = encryptor.update(b"\x00" * 16) + encryptor.finalize()
        envelope = CiphertextEnvelope(key_id="ESN_1", iv=b"\x00" * 16, ciphertext=ciphertext).to_json()
        with pytest.raises(MSLCryptoError, match=r"^Session: invalid"):
            SessionCryptoContext(keys=KEYS, key_id="ESN_1").decrypt(envelope)

    def test_refuses_partial_block(self) -> None:
        """Raise MSLCryptoError for a ciphertext that is not whole AES blocks."""
        envelope = CiphertextEnvelope(key_id="ESN_1", iv=b"\x00" * 16, ciphertext=b"\x01" * 5).to_json()
        with pytest.raises(MSLCryptoError, match=r"^Session: invalid"):
            SessionCryptoContext(keys=KEYS, key_id="ESN_1").decrypt(envelope)
