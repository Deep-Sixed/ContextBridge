"""Address checks shared by the gateway and the agent."""

from __future__ import annotations

import ipaddress

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
