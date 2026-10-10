"""Fail-closed admission of enrolled Tailscale peers on the gateway."""
from __future__ import annotations

import ipaddress
import json
import subprocess
from collections.abc import Mapping
from typing import Any


class TailnetAdmissionDenied(ValueError):
    pass


def peer_node_id(status: Mapping[str, Any], remote_ip: str, allowed_ids: frozenset[str]) -> str:
    if status.get("BackendState") != "Running" or not allowed_ids:
        raise TailnetAdmissionDenied("tailnet unavailable or not enrolled")
    try:
        ip = ipaddress.ip_address(remote_ip)
    except ValueError as exc:
        raise TailnetAdmissionDenied("invalid peer address") from exc
    if getattr(ip, "ipv4_mapped", None) is not None:
        raise TailnetAdmissionDenied("ambiguous peer address")
    peers = status.get("Peer")
    if not isinstance(peers, dict):
        raise TailnetAdmissionDenied("tailnet peer inventory missing")
    matches = []
    for peer in peers.values():
        if not isinstance(peer, dict) or peer.get("Online") is not True:
            continue
        node_id = peer.get("ID")
        if not isinstance(node_id, str) or node_id not in allowed_ids:
            continue
        addresses = peer.get("TailscaleIPs")
        if not isinstance(addresses, list):
            continue
        if any(isinstance(addr, str) and addr == str(ip) for addr in addresses):
            matches.append(node_id)
    if len(matches) != 1:
        raise TailnetAdmissionDenied("peer not uniquely enrolled and online")
    return matches[0]


def verify_local_tailnet_peer(remote_ip: str, allowed_ids: frozenset[str]) -> str:
    """Use *gateway-local* tailscaled state; caller data never supplies the inventory."""
    try:
        proc = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True, text=True, timeout=3, check=True,
        )
        status = json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise TailnetAdmissionDenied("cannot verify local tailscale state") from exc
    if not isinstance(status, dict):
        raise TailnetAdmissionDenied("invalid tailnet status")
    return peer_node_id(status, remote_ip, allowed_ids)
