"""Tailnet identity validation for ContextBridge remote agent connections.

Tailscale provides private transport; this module provides a fail-closed way to
associate a connecting IP with a known node in the local tailscaled status.
Application authentication and per-operation authorization remain mandatory.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Mapping


class TailnetDenied(ValueError):
    """The connecting endpoint is not a trusted online tailnet peer."""


@dataclass(frozen=True)
class TailnetPeer:
    node_id: str
    dns_name: str
    ips: tuple[str, ...]


def _ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError as exc:
        raise TailnetDenied("invalid peer IP") from exc
    # Reject IPv4-mapped IPv6 to avoid two representations of one address.
    if getattr(address, "ipv4_mapped", None):
        raise TailnetDenied("IPv4-mapped address is not permitted")
    return str(address)


def identify_tailnet_peer(
    status: Mapping[str, Any],
    remote_ip: str,
    *,
    allowed_node_ids: frozenset[str],
) -> TailnetPeer:
    """Identify a remote Tailscale peer by exact IP and explicitly enrolled node ID.

    Input is the JSON from `tailscale status --json` obtained on the gateway.
    IP ownership is checked against online peers, never against CIDR membership
    alone. Caller must additionally authenticate the connection cryptographically.
    """
    if not allowed_node_ids:
        raise TailnetDenied("no enrolled tailnet nodes")
    if status.get("BackendState") != "Running":
        raise TailnetDenied("tailscaled is not running")
    address = _ip(remote_ip)
    peer_map = status.get("Peer")
    if not isinstance(peer_map, dict):
        raise TailnetDenied("peer status unavailable")
    matches: list[TailnetPeer] = []
    for peer in peer_map.values():
        if not isinstance(peer, dict) or peer.get("Online") is not True:
            continue
        node_id = peer.get("ID")
        if not isinstance(node_id, str) or node_id not in allowed_node_ids:
            continue
        raw_ips = peer.get("TailscaleIPs")
        if not isinstance(raw_ips, list):
            continue
        ips = tuple(_ip(i) for i in raw_ips if isinstance(i, str))
        if address in ips:
            matches.append(TailnetPeer(node_id, str(peer.get("DNSName", "")), ips))
    if len(matches) != 1:
        raise TailnetDenied("connecting address is not one uniquely enrolled online peer")
    return matches[0]


def decode_status(stdout: str) -> Mapping[str, Any]:
    try:
        value = json.loads(stdout)
    except (ValueError, TypeError) as exc:
        raise TailnetDenied("invalid tailscale status JSON") from exc
    if not isinstance(value, dict):
        raise TailnetDenied("tailscale status must be an object")
    return value
