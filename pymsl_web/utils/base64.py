import base64
import binascii
import re
from typing import Final

from pymsl_web.utils.messages import message

STANDARD_ALPHABET: Final = re.compile(r"[A-Za-z0-9+/]*={0,2}")
URL_ALPHABET: Final = re.compile(r"[A-Za-z0-9_-]*={0,2}")


def encode(data: bytes) -> str:
    """Write `data` as standard Base64 with its padding."""
    return base64.b64encode(data).decode("ascii")


def encode_url(data: bytes) -> str:
    """Write `data` as base64url without its padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode(text: str, *, context: str) -> bytes:
    """Read standard Base64, its padding optional; raise ValueError naming `context` for anything else."""
    try:
        return base64.b64decode(padded(text, STANDARD_ALPHABET, context=context))
    except binascii.Error as error:
        raise ValueError(message(context, "invalid", "Base64 expected")) from error


def decode_url(text: str, *, context: str) -> bytes:
    """Read base64url, its padding optional; raise ValueError naming `context` for anything else."""
    try:
        return base64.urlsafe_b64decode(padded(text, URL_ALPHABET, context=context))
    except binascii.Error as error:
        raise ValueError(message(context, "invalid", "Base64 expected")) from error


def padded(text: str, alphabet: re.Pattern[str], *, context: str) -> str:
    """Give `text` with its full padding once checked against `alphabet`; raise ValueError naming `context` for a
    text that is not Base64."""
    if not isinstance(text, str) or alphabet.fullmatch(text) is None:
        raise ValueError(message(context, "invalid", "Base64 expected"))
    stripped = text.rstrip("=")
    if len(stripped) % 4 == 1:
        raise ValueError(message(context, "invalid", "Base64 expected"))
    return stripped + "=" * (-len(stripped) % 4)
