"""Address checks shared by the gateway and the agent, and the gateway's Host/Origin guard."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

# Tailscale and other carrier-grade NAT overlays use 100.64.0.0/10.
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_private_bind(host: str) -> bool:
    """True for a specific loopback, LAN, or overlay-network address (never a wildcard or public IP)."""
    if is_loopback(host):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False  # hostnames could resolve anywhere; require an address literal
    if address.is_unspecified or address.is_multicast:
        return False
    if address.version == 4 and address in _SHARED_ADDRESS_SPACE:
        return True
    return address.is_private and not address.is_global


def _host_name(value: str) -> str:
    """A Host header or URL authority as a bare lowercase host name: no port, no IPv6 brackets."""
    value = value.strip().lower()
    if value.startswith("["):
        return value[1 : value.find("]")] if "]" in value else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


class HostOriginGuard:
    """ASGI middleware that refuses requests not addressed to this server (DNS-rebinding protection).

    ``Host`` must be a loopback name or one of ``hosts`` (else 421). A browser's ``Origin``,
    when present, must be a loopback origin or one of ``origins`` (else 403). Our own,
    rather than FastMCP's, so the same rules hold on every supported FastMCP release.
    """

    def __init__(self, app: Any, *, hosts: Iterable[str] = (), origins: Iterable[str] = ()) -> None:
        self.app = app
        self.hosts = {_host_name(h) for h in hosts}
        self.origins = {o.strip().rstrip("/").lower() for o in origins}

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
            host = _host_name(headers.get("host", ""))
            if not (is_loopback(host) or host in self.hosts):
                await _reject(send, 421, b"Misdirected Request")
                return
            origin = headers.get("origin")
            if origin is not None and not self._origin_allowed(origin):
                await _reject(send, 403, b"Forbidden Origin")
                return
        await self.app(scope, receive, send)

    def _origin_allowed(self, origin: str) -> bool:
        origin = origin.strip().rstrip("/").lower()
        if origin in self.origins:
            return True
        parts = urlsplit(origin)
        return parts.scheme in ("http", "https") and is_loopback(parts.hostname or "")


async def _reject(send: Any, status: int, body: bytes) -> None:
    headers = [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
