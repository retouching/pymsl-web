from abc import ABC, abstractmethod

from pydantic import BaseModel


class CryptoContext(ABC, BaseModel):
    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Give `data` encrypted, as the bytes that go in a message."""

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """Give the clear bytes of `data`."""

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Give the signature of `data`."""

    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        """Tell whether `signature` signs `data`."""
