from __future__ import annotations

import pytest

from contextbridge.remote.tailnet import TailnetAdmissionDenied, peer_node_id


def status(*, online: bool = True, state: str = "Running") -> dict:
    return {
        "BackendState": state,
        "Peer": {
            "a": {"ID": "node-friday", "Online": online, "TailscaleIPs": ["100.91.238.124", "fd7a:115c:a1e0::1"]},
            "b": {"ID": "node-untrusted", "Online": True, "TailscaleIPs": ["100.93.22.66"]},
        },
    }


def test_online_enrolled_ipv4_ipv6():
    allowed = frozenset({"node-friday"})
    assert peer_node_id(status(), "100.91.238.124", allowed) == "node-friday"
    assert peer_node_id(status(), "fd7a:115c:a1e0::1", allowed) == "node-friday"


@pytest.mark.parametrize("remote,ids", [
    ("100.93.22.66", frozenset({"node-friday"})),
    ("100.91.238.125", frozenset({"node-friday"})),
    ("10.0.0.151", frozenset({"node-friday"})),
    ("invalid", frozenset({"node-friday"})),
    ("100.91.238.124", frozenset()),
    ("::ffff:100.91.238.124", frozenset({"node-friday"})),
])
def test_untrusted_address_denied(remote, ids):
    with pytest.raises(TailnetAdmissionDenied):
        peer_node_id(status(), remote, ids)


def test_offline_and_disconnected_denied():
    for report in (status(online=False), status(state="Stopped"), {"BackendState": "Running"}):
        with pytest.raises(TailnetAdmissionDenied):
            peer_node_id(report, "100.91.238.124", frozenset({"node-friday"}))


def test_ambiguous_peer_denied():
    report = status()
    report["Peer"]["c"] = {
        "ID": "node-another", "Online": True, "TailscaleIPs": ["100.91.238.124"]
    }
    with pytest.raises(TailnetAdmissionDenied):
        peer_node_id(report, "100.91.238.124", frozenset({"node-friday", "node-another"}))
