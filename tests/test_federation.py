"""MCP federation: MCP servers a device's config runs, offered through the gateway with a device argument."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import anyio
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from test_computer_server import allow_scopes
from test_remote import DEVICE, connected_agent, gateway, mcp

from contextbridge.computer import federation as fed
from contextbridge.computer.audit import ComputerAuditLog
from contextbridge.computer.dispatch import (
    RESERVED_TOOL_NAMES,
    Engine,
    build_federation,
)
from contextbridge.computer.federation import (
    Federation,
    FederationError,
    load_mcp_servers,
    tools_from_wire,
)
from contextbridge.computer.policy import PolicyError
from contextbridge.computer.server import (
    ALL_SCOPES,
    SCOPE_DESKTOP_OBSERVE,
    SCOPE_EXECUTE,
    SCOPE_READ,
    build_router,
    create_computer_server,
)

FAKE = str(Path(__file__).with_name("fake_mcp_server.py"))
FAKE_TOOLS = {"fake_echo", "fake_snapshot", "fake_fail", "fake_slow", "fake_crash", "fake_env"}


def fake_section(**extra):
    return {"fake": {"command": sys.executable, "args": [FAKE], "startup_seconds": 60, **extra}}


def servers(**extra):
    return load_mcp_servers({"mcp_servers": fake_section(**extra)})


def audit_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def federation(policy):
    federation = build_federation(servers(), policy)
    federation.start()
    yield federation
    federation.close()


# ------------------------------------------------------------------ config


def test_config_defaults_and_validation(tmp_path):
    (server,) = load_mcp_servers(
        {"mcp_servers": {"desktop": {"command": "agent-desktop", "args": ["mcp"], "cwd": "work"}}}, base=tmp_path
    )
    assert server.scope == SCOPE_EXECUTE and server.tools is None and server.cwd == tmp_path / "work"
    assert load_mcp_servers({}) == ()
    assert load_mcp_servers({"mcp_servers": {"off": {"command": "x", "enabled": False}}}) == ()
    bad = [
        {"Desktop": {"command": "x"}},
        {"desktop": {"args": ["mcp"]}},
        {"desktop": {"command": "x", "scope": "root"}},
        {"desktop": {"command": "x", "args": "mcp"}},
        {"desktop": {"command": "x", "tool_scopes": {"snap": "everything"}}},
        {"desktop": {"command": "x", "timeout_seconds": 0}},
        {"desktop": {"command": "x", "env": {"A": 1}}},
        ["desktop"],
    ]
    for section in bad:
        with pytest.raises(PolicyError):
            load_mcp_servers({"mcp_servers": section})


def test_wire_tools_are_validated():
    good = {"name": "desktop_snapshot", "server": "desktop", "scope": SCOPE_READ, "input_schema": {"type": "object"}}
    raw = [
        good,
        {**good, "name": "read_file"},  # a built-in name
        {**good, "name": "bad.name"},
        {**good, "name": "desktop_other", "scope": "root"},
        {**good, "name": "desktop_aim", "input_schema": {"type": "object", "properties": {"device": {}}}},
        {**good, "name": "desktop_list", "input_schema": {"type": "array"}},
        "junk",
    ]
    tools = tools_from_wire(raw, reserved=RESERVED_TOOL_NAMES)
    assert list(tools) == ["desktop_snapshot"]
    assert tools_from_wire("junk", reserved=frozenset()) == {}


# ------------------------------------------------------------------ engine


def test_federation_lists_and_calls_tools(federation, policy):
    assert set(federation.tools) == FAKE_TOOLS  # fake_aim is dropped: it has its own 'device' argument
    assert all(t.scope == SCOPE_EXECUTE and t.server == "fake" for t in federation.tools.values())
    engine = Engine(policy, federation=federation)
    assert set(engine.federated) == FAKE_TOOLS and not FAKE_TOOLS & engine.tools

    echoed = engine.execute("fake_echo", {"text": "hi"})
    assert echoed["is_error"] is False and echoed["structured_content"]["echo"] == "hi"
    image = engine.execute("fake_snapshot", {})
    assert image["content"][0]["type"] == "image" and image["content"][0]["mimeType"] == "image/png"
    failed = engine.execute("fake_fail", {"reason": "x"})
    assert failed["is_error"] is True and "failed: x" in fed.result_text(failed)


def test_child_environment_has_credentials_removed(policy, monkeypatch):
    monkeypatch.setenv("CONTEXTBRIDGE_COMPUTER_TOKEN", "secret-token-value")
    monkeypatch.setenv("FEDERATION_VISIBLE", "yes")
    federation = build_federation(servers(env={"EXTRA": "set"}), policy)
    federation.start()
    try:
        values = {
            name: fed.result_text(federation.call("fake_env", {"name": name}))
            for name in ("CONTEXTBRIDGE_COMPUTER_TOKEN", "FEDERATION_VISIBLE", "EXTRA")
        }
    finally:
        federation.close()
    assert values == {"CONTEXTBRIDGE_COMPUTER_TOKEN": "<unset>", "FEDERATION_VISIBLE": "yes", "EXTRA": "set"}


def test_tool_allowlist_and_scope_overrides(policy):
    federation = build_federation(
        servers(tools=["echo", "fake_snapshot"], tool_scopes={"fake_snapshot": SCOPE_DESKTOP_OBSERVE}), policy
    )
    federation.start()
    try:
        tools = federation.tools
    finally:
        federation.close()
    assert set(tools) == {"fake_echo", "fake_snapshot"}
    assert tools["fake_snapshot"].scope == SCOPE_DESKTOP_OBSERVE and tools["fake_echo"].scope == SCOPE_EXECUTE


def test_server_that_fails_to_start_is_left_out(policy):
    section = {
        **fake_section(),
        "broken": {"command": sys.executable, "args": ["-c", "import sys; sys.exit(2)"], "startup_seconds": 20},
    }
    messages: list[str] = []
    federation = Federation(load_mcp_servers({"mcp_servers": section}), env=policy.child_env(), log=messages.append)
    federation.start()
    try:
        assert set(federation.tools) == FAKE_TOOLS
        rows = {row["server"]: row for row in federation.describe()}
    finally:
        federation.close()
    assert rows["fake"]["running"] is True and rows["broken"]["running"] is False and rows["broken"]["error"]
    assert any("'broken' did not start" in m for m in messages)


def test_crashed_server_is_started_again(policy, monkeypatch):
    monkeypatch.setattr(fed, "RESTART_INTERVAL_SECONDS", 0.0)
    federation = build_federation(servers(), policy)
    federation.start()
    try:
        first = federation.call("fake_echo", {"text": "a"})["structured_content"]["pid"]
        with pytest.raises(FederationError):
            federation.call("fake_crash", {})
        second = federation.call("fake_echo", {"text": "b"})["structured_content"]
    finally:
        federation.close()
    assert second["echo"] == "b" and second["pid"] != first


def test_slow_call_times_out(policy):
    federation = build_federation(servers(timeout_seconds=1), policy)
    federation.start()
    try:
        with pytest.raises(FederationError, match="did not answer|timed out|Timed out"):
            federation.call("fake_slow", {"seconds": 5})
    finally:
        federation.close()


# ----------------------------------------------------------------- gateway


def run_client(server, fn):
    async def inner():
        async with Client(server) as client:
            return await fn(client)

    return anyio.run(inner)


def local_server(policy, federation, audit, scopes=ALL_SCOPES):
    router = build_router(policy, audit=audit, federation=federation)
    return create_computer_server(None, audit=audit, router=router, authorize=allow_scopes(*scopes))


def test_gateway_lists_and_routes_local_federated_tools(policy, federation, tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    server = local_server(policy, federation, ComputerAuditLog(audit_path, echo=False))

    async def scenario(client):
        tools = {t.name: t for t in await client.list_tools()}
        echoed = await client.call_tool("fake_echo", {"text": "hello"})
        explicit = await client.call_tool("fake_echo", {"text": "again", "device": "local"})
        image = await client.call_tool("fake_snapshot", {})
        with pytest.raises(ToolError, match="failed: boom"):
            await client.call_tool("fake_fail", {"reason": "boom"})
        with pytest.raises(ToolError, match="not offered"):
            await client.call_tool("fake_echo", {"text": "x", "device": "elsewhere"})
        devices = (await client.call_tool("list_devices", {})).structured_content["devices"]
        return tools, echoed, explicit, image, devices

    tools, echoed, explicit, image, devices = run_client(server, scenario)
    assert FAKE_TOOLS <= set(tools) and "read_file" in tools
    schema = tools["fake_echo"].inputSchema
    assert schema["properties"]["device"]["default"] == "local" and schema["required"] == ["text"]
    assert "MCP server 'fake' on local" in tools["fake_echo"].description
    assert echoed.structured_content["echo"] == "hello" and explicit.structured_content["echo"] == "again"
    assert image.content[0].type == "image"
    assert devices[0]["mcp_tools"] == sorted(FAKE_TOOLS)

    log = audit_events(audit_path)
    calls = [e for e in log if e["event"] == "requested" and e["tool"] == "fake_echo"]
    lifecycle = [e["event"] for e in log if e.get("request_id") == calls[0]["request_id"]]
    assert lifecycle == ["requested", "started", "completed"]
    started = next(e for e in log if e.get("request_id") == calls[0]["request_id"] and e["event"] == "started")
    assert started["mcp_server"] == "fake" and started["args_bytes"] > 0 and "text" not in started
    failed = [e for e in log if e["event"] == "completed" and e["tool"] == "fake_fail"]
    assert failed[0]["success"] is False and "boom" in failed[0]["reason"]
    assert any(e["event"] == "denied" and e["tool"] == "fake_echo" for e in log)


def test_gateway_hides_and_refuses_tools_outside_the_callers_scopes(policy, tmp_path):
    federation = build_federation(servers(tool_scopes={"fake_snapshot": SCOPE_READ}), policy)
    federation.start()
    try:
        server = local_server(policy, federation, ComputerAuditLog(tmp_path / "a.jsonl", echo=False), (SCOPE_READ,))

        async def scenario(client):
            names = {t.name for t in await client.list_tools()}
            image = await client.call_tool("fake_snapshot", {})
            with pytest.raises(ToolError, match="not authorized"):
                await client.call_tool("fake_echo", {"text": "x"})
            with pytest.raises(ToolError):
                await client.call_tool("no.such.tool", {})
            return names, image

        names, image = run_client(server, scenario)
    finally:
        federation.close()
    assert "fake_snapshot" in names and "fake_echo" not in names
    assert image.content[0].type == "image"


# ------------------------------------------------------------------ remote


def test_remote_device_offers_its_mcp_servers(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(
            tmp_path, workspace, gw, mcp_servers=fake_section()
        ):
            async with mcp(gw) as client:
                tools = {t.name: t for t in await client.list_tools()}
                echoed = await client.call_tool("fake_echo", {"text": "remote"})
                with pytest.raises(ToolError, match="failed: far"):
                    await client.call_tool("fake_fail", {"reason": "far"})
                devices = (await client.call_tool("list_devices", {})).structured_content["devices"]
            async with mcp(gw, scopes=(SCOPE_READ,)) as limited:
                hidden = {t.name for t in await limited.list_tools()}
            return tools, echoed, devices, hidden

    tools, echoed, devices, hidden = asyncio.run(scenario())
    assert FAKE_TOOLS <= set(tools)
    assert tools["fake_echo"].inputSchema["properties"]["device"]["default"] == DEVICE
    assert echoed.structured_content["echo"] == "remote"
    assert devices[0]["mcp_tools"] == sorted(FAKE_TOOLS)
    assert not FAKE_TOOLS & hidden

    agent_log = audit_events(tmp_path / "agent-audit.jsonl")
    gateway_log = audit_events(tmp_path / "gateway-audit.jsonl")
    request_id = next(e["request_id"] for e in gateway_log if e["event"] == "requested" and e["tool"] == "fake_echo")
    assert [e["event"] for e in gateway_log if e.get("request_id") == request_id] == [
        "requested",
        "started",
        "completed",
    ]
    assert [e["event"] for e in agent_log if e.get("request_id") == request_id] == ["requested", "started", "completed"]
    assert any(e["event"] == "mcp_servers_started" for e in agent_log)


def test_device_grant_limits_federated_tools(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(
            tmp_path, workspace, gw, scopes=(SCOPE_READ,), mcp_servers=fake_section()
        ):
            async with mcp(gw) as client:
                names = {t.name for t in await client.list_tools()}
                with pytest.raises(ToolError, match="not authorized"):
                    await client.call_tool("fake_echo", {"text": "x", "device": DEVICE})
            return names

    names = asyncio.run(scenario())
    assert not FAKE_TOOLS & names


def test_two_servers_never_collide(policy):
    section = {**fake_section(), "fake-two": {"command": sys.executable, "args": [FAKE], "startup_seconds": 60}}
    federation = build_federation(load_mcp_servers({"mcp_servers": section}), policy)
    federation.start()
    try:
        tools = federation.tools
        first = federation.call("fake_echo", {"text": "one"})["structured_content"]
        second = federation.call("fake-two_echo", {"text": "two"})["structured_content"]
    finally:
        federation.close()
    # Server names cannot contain '_', so '<server>_' prefixes from different servers never overlap.
    assert FAKE_TOOLS <= set(tools) and "fake-two_echo" in tools and "fake-two_fake_snapshot" in tools
    assert tools["fake-two_echo"].server == "fake-two"
    assert first["echo"] == "one" and second["echo"] == "two" and first["pid"] != second["pid"]
