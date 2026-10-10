"""Wire protocol between the gateway and agents (JSON text frames over WebSocket/TLS).

Enrollment (one connection, then closed)::

    agent   → {"type": "enroll", "version", "code", "name", "public_key", "info"}
    gateway → {"type": "enrolled", "device_id", "name", "gateway_id"} | {"type": "error", ...}

Session::

    agent   → {"type": "hello", "version", "device_id"}
    gateway → {"type": "challenge", "nonce", "gateway_id"}
    agent   → {"type": "auth", "signature", "capabilities": {"tools", "policy", "info"}}
    gateway → {"type": "welcome", "heartbeat_seconds"}

    gateway → {"type": "call", "seq", "request_id", "tool", "args"}
    agent   → {"type": "started", "request_id", "fields"}
    agent   → {"type": "result", "request_id", "ok", "result" | "error": {"kind", "message"}, "started"}
    agent   → {"type": "heartbeat"}
    agent   → {"type": "event", "event": "exited", ...}
    gateway → {"type": "error", "code", "message"}   (then closes)

The signature is Ed25519 over :func:`auth_payload`, binding the device, this
gateway, and a fresh 32-byte nonce. ``seq`` increases strictly per connection
and ``request_id`` is never reused, so an agent refuses replayed calls.
"""

from __future__ import annotations

import base64
import json
from typing import Any

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 16 * 1024 * 1024
HANDSHAKE_TIMEOUT_SECONDS = 10.0
AUTH_CONTEXT = b"contextbridge-agent-auth-v1"

# Error codes after which an agent must stop reconnecting.
FATAL_ERRORS = frozenset({"revoked", "unknown_device", "bad_signature", "bad_code", "protocol", "version"})


class ProtocolError(ValueError):
    """Raised for malformed or unexpected messages."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: Any, *, field: str = "value") -> bytes:
    if not isinstance(text, str):
        raise ProtocolError(f"{field} must be base64 text")
    try:
        return base64.b64decode(text, validate=True)
    except ValueError:
        raise ProtocolError(f"{field} is not valid base64") from None


def auth_payload(gateway_id: str, device_id: str, nonce: bytes) -> bytes:
    return b"\n".join([AUTH_CONTEXT, gateway_id.encode(), device_id.encode(), nonce])


def encode(message: dict[str, Any]) -> str:
    return json.dumps(message, separators=(",", ":"), default=str)


def decode(raw: str | bytes, *, expect: str | tuple[str, ...] | None = None) -> dict[str, Any]:
    if isinstance(raw, bytes):
        raise ProtocolError("binary frames are not accepted")
    try:
        message = json.loads(raw)
    except json.JSONDecodeError:
        raise ProtocolError("frame is not JSON") from None
    if not isinstance(message, dict) or not isinstance(message.get("type"), str):
        raise ProtocolError("frame must be an object with a 'type'")
    if expect is not None:
        allowed = (expect,) if isinstance(expect, str) else expect
        if message["type"] not in allowed:
            if message["type"] == "error":
                return message
            raise ProtocolError(f"expected {'/'.join(allowed)}, got {message['type']!r}")
    return message


def error(code: str, message: str) -> dict[str, Any]:
    return {"type": "error", "code": code, "message": message}
