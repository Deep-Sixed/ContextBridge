"""Agent admission modes and the failed-attempt limiter on the agent listener."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from contextbridge.computer.audit import ComputerAuditLog
from contextbridge.computer.server import (
    ADMISSION_DEVICE_KEY,
    ADMISSION_TAILNET,
    AgentListenerConfig,
)
from contextbridge.remote import hub as hub_module
from contextbridge.remote.admin import main as admin_main
from contextbridge.remote.hub import AgentHub, FailureLimiter
from contextbridge.remote.protocol import FATAL_ERRORS, PROTOCOL_VERSION, b64e
from contextbridge.remote.registry import DeviceRegistry


def listener(tmp_path: Path, **cfg) -> AgentListenerConfig:
    section = {"port": 8792, "registry": "devices.json", **cfg}
    return AgentListenerConfig(section, tmp_path, tmp_path / "gateway.yaml")


# ------------------------------------------------------------------ config


def test_loopback_defaults_to_device_key_and_off_loopback_to_tailnet(tmp_path):
    local = listener(tmp_path)
    assert local.admission == ADMISSION_DEVICE_KEY and local.tailnet_node_ids is None
    tailnet = listener(tmp_path, host="100.91.238.124", tls_cert="c", tls_key="k", tailnet_node_ids=["n1"])
    assert tailnet.admission == ADMISSION_TAILNET and tailnet.tailnet_node_ids == frozenset({"n1"})


def test_device_key_admission_allows_a_public_address_with_tls(tmp_path):
    public = listener(tmp_path, host="8.8.8.8", admission="device-key", tls_cert="c", tls_key="k")
    assert public.admission == ADMISSION_DEVICE_KEY and public.tailnet_node_ids is None
    with pytest.raises(SystemExit, match="required when agents.host is not loopback"):
        listener(tmp_path, host="8.8.8.8", admission="device-key")


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "friday.local", "224.0.0.1"])
def test_device_key_admission_still_refuses_wildcards_and_hostnames(tmp_path, host):
    with pytest.raises(SystemExit, match="one IP address"):
        listener(tmp_path, host=host, admission="device-key", tls_cert="c", tls_key="k")


def test_public_address_without_device_key_is_refused(tmp_path):
    with pytest.raises(SystemExit, match="set admission: device-key"):
        listener(tmp_path, host="8.8.8.8", tls_cert="c", tls_key="k", tailnet_node_ids=["n1"])


@pytest.mark.parametrize(
    ("cfg", "message"),
    [
        ({"admission": "open"}, "must be one of"),
        ({"admission": "tailnet"}, "on loopback every peer is 127.0.0.1"),
        ({"admission": "device-key", "tailnet_node_ids": ["n1"]}, "only enforced with admission: tailnet"),
        ({"client_ip_header": ""}, "client_ip_header"),
        ({"public_url": "https://agents.example.com"}, "wss://"),
        ({"public_url": "wss://agents.example.com/agents"}, "no path"),
        ({"max_failed_attempts": 0}, "max_failed_attempts"),
        ({"failure_window_seconds": "soon"}, "failure_window_seconds"),
    ],
)
def test_bad_admission_settings_are_refused(tmp_path, cfg, message):
    with pytest.raises(SystemExit, match=message):
        listener(tmp_path, **cfg)


def test_client_ip_header_is_only_trusted_on_loopback(tmp_path):
    assert listener(tmp_path, client_ip_header="CF-Connecting-IP").client_ip_header == "CF-Connecting-IP"
    with pytest.raises(SystemExit, match="only when agents.host is loopback"):
        listener(
            tmp_path, host="8.8.8.8", admission="device-key", tls_cert="c", tls_key="k",
            client_ip_header="CF-Connecting-IP",
        )


def test_pair_prints_the_public_agent_url(tmp_path, capsys):
    config = tmp_path / "gateway.yaml"
    config.write_text(
        yaml.safe_dump(
            {"agents": {"enabled": True, "port": 8792, "registry": "devices.json", "public_url": "wss://agents.example.com"}}
        ),
        encoding="utf-8",
    )
    admin_main(["--config", str(config), "pair", "laptop", "--scopes", "computer:read"])
    out = capsys.readouterr().out
    assert "url: wss://agents.example.com" in out and "fingerprint" not in out


def test_rate_limited_is_not_fatal_for_agents():
    assert "rate_limited" not in FATAL_ERRORS  # agents keep retrying with backoff


# ----------------------------------------------------------------- limiter


def test_limiter_blocks_after_max_failures_and_forgets_after_the_window():
    now = [0.0]
    limiter = FailureLimiter(3, 60, clock=lambda: now[0])
    assert [limiter.record("a") for _ in range(3)] == [False, False, True]
    assert limiter.blocked("a") and not limiter.blocked("b")
    now[0] = 30.0
    assert limiter.blocked("a")
    now[0] = 61.0
    assert not limiter.blocked("a")


def test_limiter_memory_is_bounded():
    limiter = FailureLimiter(1, 60, max_clients=3)
    for client in "abcde":
        limiter.record(client)
    assert not limiter.blocked("a") and not limiter.blocked("b")
    assert all(limiter.blocked(c) for c in "cde")


# -------------------------------------------------------------------- hub


def _public_key() -> str:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return b64e(raw)


async def _exchange(url: str, message: dict, headers: dict[str, str] | None = None) -> dict:
    """Send one handshake frame and return the reply. A rate-limited client is refused before its
    first frame is read, so the refusal may arrive only as the close reason."""
    async with connect(url, additional_headers=headers or {}) as ws:
        try:
            await ws.send(json.dumps(message))
            return json.loads(await ws.recv())
        except ConnectionClosed as exc:
            reason = exc.rcvd.reason if exc.rcvd else ""
            return {"type": "error", "code": "rate_limited" if "too many failed attempts" in reason else "closed"}


async def _enroll(url: str, code: str, name: str, headers: dict[str, str] | None = None) -> dict:
    message = {"type": "enroll", "version": PROTOCOL_VERSION, "code": code, "name": name,
               "public_key": _public_key(), "info": {}}
    return await _exchange(url, message, headers)


def test_failed_enrollments_are_rate_limited_per_client(tmp_path, monkeypatch):
    monkeypatch.setattr(hub_module, "FAILED_ENROLL_DELAY_SECONDS", 0.0)
    registry = DeviceRegistry(tmp_path / "devices.json")
    audit_path = tmp_path / "audit.jsonl"

    async def scenario():
        hub = AgentHub(
            registry,
            ComputerAuditLog(audit_path, echo=False),
            client_ip_header="CF-Connecting-IP",
            max_failed_attempts=3,
            failure_window_seconds=600,
        )
        port = await hub.start("127.0.0.1", 0)
        url = f"ws://127.0.0.1:{port}"
        attacker = {"CF-Connecting-IP": "203.0.113.9"}
        try:
            guesses = [(await _enroll(url, "AAAA-BBBB-CCCC-DDDD", "laptop", attacker))["code"] for _ in range(3)]
            code, _ = registry.create_enrollment("laptop", ["computer:read"])
            blocked = await _enroll(url, code, "laptop", attacker)       # even a valid code
            other = await _enroll(url, code, "laptop", {"CF-Connecting-IP": "198.51.100.4"})
        finally:
            await hub.close()
        return guesses, blocked, other

    guesses, blocked, other = asyncio.run(scenario())
    assert guesses == ["bad_code"] * 3
    assert blocked["type"] == "error" and blocked["code"] == "rate_limited"
    assert other["type"] == "enrolled"  # a different client is unaffected, and the code was not used up
    log = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    limited = [e for e in log if e["event"] == "agent_rate_limited"]
    assert len(limited) == 1 and limited[0]["peer"] == "203.0.113.9"
    rejected = [e for e in log if e["event"] == "device_enroll_rejected"]
    assert {e["peer"] for e in rejected} == {"203.0.113.9"}


def test_failed_sign_ins_count_and_a_bad_header_falls_back_to_the_socket_address(tmp_path):
    registry = DeviceRegistry(tmp_path / "devices.json")

    async def scenario():
        hub = AgentHub(
            registry,
            ComputerAuditLog(tmp_path / "audit.jsonl", echo=False),
            client_ip_header="CF-Connecting-IP",
            max_failed_attempts=2,
        )
        port = await hub.start("127.0.0.1", 0)
        url = f"ws://127.0.0.1:{port}"
        replies = []
        try:
            hello = {"type": "hello", "version": PROTOCOL_VERSION, "device_id": "dev_unknown"}
            for _ in range(3):
                reply = await _exchange(url, hello, {"CF-Connecting-IP": "not-an-ip"})
                replies.append(reply["code"])
        finally:
            await hub.close()
        return replies, hub.limiter.blocked("127.0.0.1")

    replies, blocked = asyncio.run(scenario())
    assert replies == ["unknown_device", "unknown_device", "rate_limited"]
    assert blocked
