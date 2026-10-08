"""Time-based one-time passwords (RFC 6238, HMAC-SHA1, 6 digits, 30-second steps)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6


def new_secret() -> str:
    """A random 160-bit secret, base32 without padding (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def code_at(secret: str, counter: int, *, digits: int = DIGITS) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def counter_at(when: float | None = None) -> int:
    return int((time.time() if when is None else when) // STEP_SECONDS)


def verify(secret: str, code: str, *, last_counter: int, when: float | None = None, window: int = 1) -> int | None:
    """Return the matching counter if ``code`` is valid and newer than ``last_counter``, else None.

    Accepts one step of clock drift either way. Refusing counters at or below
    ``last_counter`` stops a code from being used twice.
    """
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    now = counter_at(when)
    for counter in range(now - window, now + window + 1):
        if counter > last_counter and hmac.compare_digest(code_at(secret, counter), code):
            return counter
    return None


def provisioning_uri(secret: str, *, account: str = "owner", issuer: str = "ContextBridge") -> str:
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
