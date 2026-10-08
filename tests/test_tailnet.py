from __future__ import annotations

import pytest

from uga.tailnet import TailnetDenied, decode_status, identify_tailnet_peer


def status(*, online=True, backend="Running"):
    return {
        "BackendState": backend,
        "Peer": {
            "nodekey:friday": {
                "ID": "node-friday",
                "Online": online,
                "DNSName": "friday.tailnet.ts.net.",
                "TailscaleIPs": ["100.101.10.1", "fd7a:115c:a1e0::1"],
            },
            "nodekey:unknown": {
                "ID": "node-unknown",
                "Online": True,
                "TailscaleIPs": ["100.101.10.2"],
            },
        },
    }


def identify(s, ip, ids=frozenset({"node-friday"})):
    return identify_tailnet_peer(s, ip, allowed_node_ids=ids)


def test_enrolled_online_peer_ipv4_and_ipv6():
    assert identify(status(), "100.101.10.1").node_id == "node-friday"
    assert identify(status(), "fd7a:115c:a1e0::1").node_id == "node-friday"


@pytest.mark.parametrize("ip", ["100.101.10.2", "100.101.10.3", "10.0.0.151", "invalid"])
def test_unknown_or_non_tailnet_address_denied(ip):
    with pytest.raises(TailnetDenied):
        identify(status(), ip)


def test_offline_peer_denied():
    with pytest.raises(TailnetDenied):
        identify(status(online=False), "100.101.10.1")


def test_tailscale_down_denied():
    with pytest.raises(TailnetDenied):
        identify(status(backend="Stopped"), "100.101.10.1")


def test_empty_allowlist_denied():
    with pytest.raises(TailnetDenied):
        identify(status(), "100.101.10.1", frozenset())


def test_duplicate_matching_ips_denied():
    s = status()
    s["Peer"]["duplicate"] = {
        "ID": "node-other", "Online": True, "TailscaleIPs": ["100.101.10.1"]
    }
    with pytest.raises(TailnetDenied):
        identify(s, "100.101.10.1", frozenset({"node-friday", "node-other"}))


def test_ipv4_mapped_ipv6_denied():
    with pytest.raises(TailnetDenied):
        identify(status(), "::ffff:100.101.10.1")


@pytest.mark.parametrize("raw", ["", "null", "[]", "{broken"])
def test_invalid_status_denied(raw):
    with pytest.raises(TailnetDenied):
        decode_status(raw)


def test_valid_status_decoding():
    assert decode_status('{"BackendState":"Running"}')["BackendState"] == "Running"
