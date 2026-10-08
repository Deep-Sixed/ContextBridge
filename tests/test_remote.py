"""Gateway hub and agent together, in one event loop, over real WebSocket connections."""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastmcp import Client
from fastmcp.exceptions import ToolError
from helpers import PY, python_cmd

from contextbridge.computer.audit import ComputerAuditLog
from contextbridge.computer.policy import PolicyError
from contextbridge.computer.server import ALL_SCOPES, TOOL_SCOPES, AuthorizationError, create_computer_server
from contextbridge.computer.server import main as computer_main
from contextbridge.remote.agent import Agent, FatalAgentError, Identity, enroll, load_agent_config
from contextbridge.remote.hub import AgentHub, RemoteDenied, _Pending
from contextbridge.remote.protocol import encode
from contextbridge.remote.registry import DeviceRegistry
from contextbridge.remote.tls import PinMismatch, generate_self_signed, server_context

DEVICE = "thanatos"
HI = python_cmd("print('hi')")


def allow_scopes(*scopes: str):
    def authorize(tool: str) -> str:
        if TOOL_SCOPES.get(tool) not in scopes:
            raise AuthorizationError(f"Token is not authorized for '{tool}'.")
        return "test-client"

    return authorize


def events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def lifecycle(path: Path, request_id: str) -> list[str]:
    return [e["event"] for e in events(path) if e.get("request_id") == request_id]


async def wait_for(predicate, timeout: float = 5.0, interval: float = 0.05) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(interval)


def write_agent_config(tmp_path: Path, workspace: Path, url: str, **overrides) -> Path:
    cfg = {
        "name": DEVICE,
        "gateway": {"url": url},
        "identity": str(tmp_path / "agent-state" / "identity.json"),
        "audit_log": str(tmp_path / "agent-audit.jsonl"),
        "filesystem": {"roots": [str(workspace)], "writable_roots": [str(workspace / "work")]},
        "commands": {"mode": "allowlist", "allow": [PY]},
    }
    for key, value in overrides.items():
        cfg[key] = value
    path = tmp_path / "agent.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path


@asynccontextmanager
async def gateway(tmp_path: Path, *, heartbeat: float = 15.0, tls: bool = False):
    registry = DeviceRegistry(tmp_path / "state" / "devices.json")
    audit_path = tmp_path / "gateway-audit.jsonl"
    audit = ComputerAuditLog(audit_path, echo=False)
    hub = AgentHub(registry, audit, heartbeat_seconds=heartbeat, call_timeout_seconds=30)
    fingerprint = None
    ssl_context = None
    if tls:
        cert, key = tmp_path / "state" / "tls" / "gw.crt", tmp_path / "state" / "tls" / "gw.key"
        fingerprint = generate_self_signed(cert, key, hostnames=["localhost"], ips=["127.0.0.1"])
        ssl_context = server_context(cert, key)
    port = await hub.start("127.0.0.1", 0, ssl_context)
    url = f"{'wss' if tls else 'ws'}://127.0.0.1:{port}"
    try:
        yield SimpleNamespace(hub=hub, registry=registry, audit_path=audit_path, url=url, fingerprint=fingerprint)
    finally:
        await hub.close()


@asynccontextmanager
async def connected_agent(tmp_path: Path, workspace: Path, gw, *, scopes=ALL_SCOPES, **config_overrides):
    code, _ = gw.registry.create_enrollment(DEVICE, list(scopes))
    gateway_cfg = {"url": gw.url}
    if gw.fingerprint:
        gateway_cfg["fingerprint"] = gw.fingerprint
    config = load_agent_config(write_agent_config(tmp_path, workspace, gw.url, gateway=gateway_cfg, **config_overrides))
    identity = await enroll(config, code)
    agent = Agent(config, identity, audit=ComputerAuditLog(config.audit_path, route="agent", echo=False))
    task = asyncio.create_task(agent.run())
    await asyncio.wait_for(agent.connected.wait(), 5)
    await wait_for(lambda: gw.hub.connection(DEVICE) is not None)
    try:
        yield SimpleNamespace(agent=agent, task=task, config=config, identity=identity)
    finally:
        agent.stop()
        try:
            await asyncio.wait_for(task, 10)
        except FatalAgentError:
            pass


def mcp(gw, *, scopes=ALL_SCOPES, local_policy=None):
    server = create_computer_server(
        local_policy,
        audit=ComputerAuditLog(gw.audit_path, echo=False),
        hub=gw.hub,
        authorize=allow_scopes(*scopes),
    )
    return Client(server)


# ----------------------------------------------------------------- happy path


def test_enrolled_agent_serves_calls_through_the_gateway(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(tmp_path, workspace, gw) as remote:
            async with mcp(gw) as client:
                tools = {t.name for t in await client.list_tools()}
                devices = (await client.call_tool("list_devices", {})).structured_content["devices"]
                text = await client.call_tool("read_file", {"path": "docs/notes.md", "device": DEVICE})
                echoed = await client.call_tool("run_command", {"command": HI, "device": DEVICE})
                written = await client.call_tool(
                    "write_file", {"path": "work/remote.txt", "content": "from gateway", "device": DEVICE}
                )
            results = (text, echoed, written)
            return (tools, devices, *(r.structured_content for r in results), remote)

    tools, devices, text, echoed, written, remote = asyncio.run(scenario())
    assert "read_file" in tools and "list_devices" in tools
    assert [d["device"] for d in devices] == [DEVICE]
    assert devices[0]["online"] is True and "run_command" in devices[0]["tools"]
    assert text["content"] == "alpha\nbeta\ngamma\n"
    assert echoed["stdout"].strip() == "hi" and echoed["exit_code"] == 0
    assert (workspace / "work" / "remote.txt").read_text() == "from gateway"

    gateway_log = tmp_path / "gateway-audit.jsonl"
    agent_log = tmp_path / "agent-audit.jsonl"
    calls = [e for e in events(gateway_log) if e["event"] == "requested" and e["tool"] == "run_command"]
    request_id = calls[0]["request_id"]
    assert calls[0]["device"] == DEVICE
    assert lifecycle(gateway_log, request_id) == ["requested", "started", "completed"]
    assert lifecycle(agent_log, request_id) == ["requested", "started", "completed"]
    started = [e for e in events(gateway_log) if e.get("request_id") == request_id and e["event"] == "started"][0]
    assert started["argv"][-1] == "print('hi')"  # the agent's own view of what it ran
    assert {"device_enrolled", "device_connected"} <= {e["event"] for e in events(gateway_log)}


def test_local_and_remote_devices_side_by_side(tmp_path, workspace, policy):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(tmp_path, workspace, gw):
            async with mcp(gw, local_policy=policy) as client:
                devices = (await client.call_tool("list_devices", {})).structured_content["devices"]
                local = await client.call_tool("read_file", {"path": "docs/notes.md"})
                return [d["device"] for d in devices], local.structured_content

    names, local = asyncio.run(scenario())
    assert names == ["local", DEVICE]
    assert local["content"].startswith("alpha")


# ------------------------------------------------------------- enforcement


def test_agent_policy_is_authoritative_even_if_the_gateway_is_not(tmp_path, workspace):
    """A compromised gateway that ignores the agent's capabilities still cannot widen them."""

    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(
            tmp_path, workspace, gw, filesystem={"roots": [str(workspace)]}
        ):
            conn = gw.hub.connection(DEVICE)
            assert "write_file" not in conn.tools
            conn.tools = conn.tools | {"write_file", "kill_process"}  # gateway lies about what is allowed
            with pytest.raises(RemoteDenied, match="not enabled on this computer"):
                await gw.hub.call(DEVICE, "write_file", {"path": "work/x.txt", "content": "x"}, None)
            with pytest.raises(RemoteDenied, match="outside"):
                await gw.hub.call(DEVICE, "read_file", {"path": "../outside.txt"}, None)
            with pytest.raises(RemoteDenied, match="allowlist"):
                await gw.hub.call(DEVICE, "run_command", {"command": "touch pwned", "cwd": "work"}, None)

    asyncio.run(scenario())
    assert not (workspace / "work" / "x.txt").exists()
    assert not (workspace / "work" / "pwned").exists()
    agent_events = [e["event"] for e in events(tmp_path / "agent-audit.jsonl") if e.get("request_id")]
    assert agent_events.count("denied") == 3 and "started" not in agent_events


def test_remote_traversal_and_hidden_identity_are_denied(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(
            tmp_path, workspace, gw, identity=str(workspace / "work" / "identity.json")
        ):
            async with mcp(gw) as client:
                for args in (
                    {"path": "../outside.txt"},
                    {"path": "/etc/passwd"},
                    {"path": ".ssh/id_ed25519"},
                    {"path": "work/identity.json"},
                ):
                    with pytest.raises(ToolError, match="Denied by policy"):
                        await client.call_tool("read_file", {**args, "device": DEVICE})
                listing = await client.call_tool("list_directory", {"path": "work", "device": DEVICE})
                with pytest.raises(ToolError, match="Denied by policy"):
                    await client.call_tool(
                        "write_file", {"path": "work/identity.json", "content": "{}", "device": DEVICE}
                    )
                return listing.structured_content

    listing = asyncio.run(scenario())
    assert "identity.json" not in {e["path"] for e in listing["entries"]}
    assert "private_key" in (workspace / "work" / "identity.json").read_text()


def test_device_scopes_are_enforced_by_the_gateway(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(tmp_path, workspace, gw, scopes=["computer:read"]):
            async with mcp(gw) as client:
                await client.call_tool("read_file", {"path": "docs/notes.md", "device": DEVICE})
                with pytest.raises(ToolError, match="not authorized for 'run_command'"):
                    await client.call_tool("run_command", {"command": HI, "device": DEVICE})

    asyncio.run(scenario())
    agent_tools = [e["tool"] for e in events(tmp_path / "agent-audit.jsonl") if e["event"] == "requested"]
    assert agent_tools == ["read_file"]  # the denied call never reached the agent


def test_token_scopes_still_apply_to_remote_devices(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(tmp_path, workspace, gw):
            async with mcp(gw, scopes=["computer:read"]) as client:
                with pytest.raises(ToolError, match="not authorized"):
                    await client.call_tool("run_command", {"command": HI, "device": DEVICE})

    asyncio.run(scenario())


def test_unknown_and_offline_devices(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw:
            code, _ = gw.registry.create_enrollment(DEVICE, list(ALL_SCOPES))
            config = load_agent_config(write_agent_config(tmp_path, workspace, gw.url))
            await enroll(config, code)  # enrolled but never connected
            async with mcp(gw) as client:
                with pytest.raises(ToolError, match="Unknown device 'friday'"):
                    await client.call_tool("read_file", {"path": "x", "device": "friday"})
                with pytest.raises(ToolError, match="offline"):
                    await client.call_tool("read_file", {"path": "x", "device": DEVICE})
                with pytest.raises(ToolError, match="no local device"):
                    await client.call_tool("read_file", {"path": "x"})
                devices = (await client.call_tool("list_devices", {})).structured_content["devices"]
            return devices

    devices = asyncio.run(scenario())
    assert devices[0]["device"] == DEVICE and devices[0]["online"] is False
    outcomes = [e["event"] for e in events(tmp_path / "gateway-audit.jsonl") if e.get("request_id")]
    assert outcomes[:6] == ["requested", "denied", "requested", "failed", "requested", "denied"]


# ---------------------------------------------------------- authentication


def test_wrong_key_and_unknown_device_are_refused(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw:
            code, _ = gw.registry.create_enrollment(DEVICE, list(ALL_SCOPES))
            config = load_agent_config(write_agent_config(tmp_path, workspace, gw.url))
            real = await enroll(config, code)
            audit = ComputerAuditLog(tmp_path / "agent-audit.jsonl", route="agent", echo=False)
            impostor = Identity(real.device_id, DEVICE, real.gateway_id, Ed25519PrivateKey.generate())
            with pytest.raises(FatalAgentError, match="bad_signature"):
                await Agent(config, impostor, audit=audit).run()
            stranger = Identity("dev_0000000000000000", DEVICE, real.gateway_id, Ed25519PrivateKey.generate())
            with pytest.raises(FatalAgentError, match="unknown_device"):
                await Agent(config, stranger, audit=audit).run()
            other_gateway = Identity(real.device_id, DEVICE, "gw_somewhere_else", real.private_key)
            with pytest.raises(FatalAgentError, match="gateway identity"):
                await Agent(config, other_gateway, audit=audit).run()

    asyncio.run(scenario())
    reasons = [e.get("reason") for e in events(tmp_path / "gateway-audit.jsonl") if e["event"] == "device_auth_failed"]
    assert reasons == ["bad_signature", "unknown_device"]


def test_enrollment_codes_are_single_use(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw:
            code, _ = gw.registry.create_enrollment(DEVICE, list(ALL_SCOPES))
            config = load_agent_config(write_agent_config(tmp_path, workspace, gw.url))
            await enroll(config, code)
            with pytest.raises(FatalAgentError, match="already enrolled"):
                await enroll(config, code)
            other = load_agent_config(
                write_agent_config(tmp_path, workspace, gw.url, identity=str(tmp_path / "second-identity.json"))
            )
            with pytest.raises(FatalAgentError, match="bad_code"):
                await enroll(other, code)
            with pytest.raises(FatalAgentError, match="bad_code"):
                await enroll(other, "AAAA-BBBB-CCCC-DDDD")

    asyncio.run(scenario())
    rejected = [e for e in events(tmp_path / "gateway-audit.jsonl") if e["event"] == "device_enroll_rejected"]
    assert len(rejected) == 2


def test_enrollment_name_must_match_the_code(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw:
            code, _ = gw.registry.create_enrollment("friday", list(ALL_SCOPES))
            config = load_agent_config(write_agent_config(tmp_path, workspace, gw.url))
            with pytest.raises(FatalAgentError, match="issued for device 'friday'"):
                await enroll(config, code)

    asyncio.run(scenario())
    assert not (tmp_path / "agent-state" / "identity.json").exists()


def test_revoked_device_is_refused_on_the_very_next_call(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(tmp_path, workspace, gw):
            async with mcp(gw) as client:
                await client.call_tool("read_file", {"path": "docs/notes.md", "device": DEVICE})
                DeviceRegistry(gw.registry.path).revoke(DEVICE)
                with pytest.raises(ToolError, match="Unknown device"):  # before the monitor's next sweep
                    await client.call_tool("read_file", {"path": "docs/notes.md", "device": DEVICE})

    asyncio.run(scenario())


def test_revocation_disconnects_a_live_agent(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(tmp_path, workspace, gw) as remote:
            DeviceRegistry(gw.registry.path).revoke(DEVICE)  # as the admin CLI would, from another process
            with pytest.raises(FatalAgentError, match="revoked"):
                await asyncio.wait_for(remote.task, 5)
            assert gw.hub.connection(DEVICE) is None
            async with mcp(gw) as client:
                with pytest.raises(ToolError, match="Unknown device"):
                    await client.call_tool("read_file", {"path": "docs/notes.md", "device": DEVICE})
            # A revoked device cannot come back with its old key.
            audit = ComputerAuditLog(tmp_path / "agent-audit.jsonl", route="agent", echo=False)
            with pytest.raises(FatalAgentError, match="revoked"):
                await Agent(remote.config, remote.identity, audit=audit).run()

    asyncio.run(scenario())
    assert "device_revoked" in {e["event"] for e in events(tmp_path / "gateway-audit.jsonl")}


def test_tls_with_pinned_fingerprint(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path, tls=True) as gw:
            async with connected_agent(tmp_path, workspace, gw):
                conn = gw.hub.connection(DEVICE)
                assert conn.ws.transport.get_extra_info("ssl_object") is not None
                result = await gw.hub.call(DEVICE, "read_file", {"path": "docs/notes.md"}, None)
                assert result["content"].startswith("alpha")
            wrong = "sha256:" + ":".join(["00"] * 32)
            config = load_agent_config(
                write_agent_config(
                    tmp_path,
                    workspace,
                    gw.url,
                    gateway={"url": gw.url, "fingerprint": wrong},
                    identity=str(tmp_path / "other-identity.json"),
                )
            )
            code, _ = gw.registry.create_enrollment("friday", list(ALL_SCOPES))
            with pytest.raises(PinMismatch):
                await enroll(config, code)

    asyncio.run(scenario())


def test_agent_config_requires_tls_off_this_machine(tmp_path, workspace):
    with pytest.raises(PolicyError, match="wss://"):
        load_agent_config(write_agent_config(tmp_path, workspace, "ws://192.168.1.10:8792"))
    with pytest.raises(PolicyError, match="audit_log"):
        load_agent_config(write_agent_config(tmp_path, workspace, "ws://127.0.0.1:8792", audit_log=None))
    with pytest.raises(ValueError, match="fingerprint"):
        load_agent_config(
            write_agent_config(
                tmp_path, workspace, "wss://10.0.0.2:8792", gateway={"url": "wss://10.0.0.2:8792", "fingerprint": "abc"}
            )
        )
    assert load_agent_config(write_agent_config(tmp_path, workspace, "wss://10.0.0.2:8792")).tls


# ------------------------------------------------------------- transport


def test_replayed_and_out_of_order_calls_are_refused(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(tmp_path, workspace, gw):
            first = await gw.hub.call(DEVICE, "read_file", {"path": "docs/notes.md"}, None)
            assert first["content"].startswith("alpha")
            conn = gw.hub.connection(DEVICE)
            loop = asyncio.get_running_loop()

            async def raw_call(seq: int, request_id: str) -> dict:
                future = loop.create_future()
                conn.pending[request_id] = _Pending(future, None)
                frame = {"type": "call", "seq": seq, "request_id": request_id, "tool": "read_file"}
                await conn.ws.send(encode({**frame, "args": {"path": "docs/notes.md"}}))
                return await asyncio.wait_for(future, 5)

            replayed_seq = await raw_call(1, "fresh-id")
            used = [e["request_id"] for e in events(tmp_path / "agent-audit.jsonl") if e["event"] == "completed"]
            replayed_id = await raw_call(1000, used[0])
            accepted = await raw_call(1001, "another-fresh-id")
            return replayed_seq, replayed_id, accepted

    replayed_seq, replayed_id, accepted = asyncio.run(scenario())
    assert replayed_seq["ok"] is False and "sequence" in replayed_seq["error"]["message"]
    assert replayed_id["ok"] is False and "already used" in replayed_id["error"]["message"]
    assert accepted["ok"] is True


def test_missed_heartbeats_mark_the_device_offline_and_it_reconnects(tmp_path, workspace, monkeypatch):
    async def silent(self, ws, interval):
        await asyncio.sleep(3600)

    monkeypatch.setattr(Agent, "_heartbeats", silent)  # the agent stays connected but never reports in

    async def scenario():
        async with gateway(tmp_path, heartbeat=1.0) as gw, connected_agent(tmp_path, workspace, gw) as remote:
            first = gw.hub.connection(DEVICE)
            await wait_for(lambda: gw.hub.connection(DEVICE) is not first, timeout=8)
            await wait_for(lambda: gw.hub.connection(DEVICE) is not None, timeout=8)
            assert not remote.task.done()

    asyncio.run(scenario())
    assert "device_heartbeat_lost" in {e["event"] for e in events(tmp_path / "gateway-audit.jsonl")}


def test_agent_reconnects_after_gateway_restart(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(tmp_path, workspace, gw) as remote:
            port = gw.hub.port
            await gw.hub.close()
            await wait_for(lambda: not remote.agent.connected.is_set(), timeout=5)
            restarted = AgentHub(gw.registry, ComputerAuditLog(gw.audit_path, echo=False), call_timeout_seconds=30)
            await restarted.start("127.0.0.1", port)
            try:
                await asyncio.wait_for(remote.agent.connected.wait(), 10)
                await wait_for(lambda: restarted.connection(DEVICE) is not None)
                result = await restarted.call(DEVICE, "read_file", {"path": "docs/notes.md"}, None)
                assert result["content"].startswith("alpha")
            finally:
                await restarted.close()

    asyncio.run(scenario())


def test_remote_session_exit_reaches_the_gateway_audit(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(
            tmp_path, workspace, gw, commands={"mode": "unrestricted"}
        ):
            session = await gw.hub.call(DEVICE, "start_process", {"command": "exit 3", "wait_seconds": 2}, None)
            await wait_for(lambda: any(e["event"] == "exited" for e in events(tmp_path / "gateway-audit.jsonl")))
            return session

    session = asyncio.run(scenario())
    exited = [e for e in events(tmp_path / "gateway-audit.jsonl") if e["event"] == "exited"][0]
    assert exited["device"] == DEVICE and exited["session_id"] == session["session_id"]
    assert exited["exit_code"] == 3 and exited["success"] is False


# ------------------------------------------------------- gateway startup


@pytest.fixture
def gateway_config(tmp_path, workspace, monkeypatch):
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("CONTEXTBRIDGE_COMPUTER_TOKEN", "t" * 40)

    def launch(**agents):
        cfg = {
            "serve": {"host": "127.0.0.1", "port": 18791, "audit_log": str(tmp_path / "gw.jsonl")},
            "agents": {"enabled": True, "port": 18792, "registry": str(tmp_path / "devices.json"), **agents},
        }
        path = tmp_path / "gateway.yaml"
        path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        computer_main(["--config", str(path)])

    return launch


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "8.8.8.8", "friday.local"])
def test_agent_listener_refuses_public_or_wildcard_binds(gateway_config, host):
    with pytest.raises(SystemExit, match="could be public"):
        gateway_config(host=host, tls_cert="c", tls_key="k")


def test_agent_listener_off_loopback_requires_tls(gateway_config):
    with pytest.raises(SystemExit, match="required when agents.host is not loopback"):
        gateway_config(host="192.168.1.10")
    with pytest.raises(SystemExit, match="set together"):
        gateway_config(host="192.168.1.10", tls_cert="c")


def test_agent_listener_requires_a_registry_and_numeric_timing(gateway_config):
    with pytest.raises(SystemExit, match="registry is required"):
        gateway_config(registry=None)
    with pytest.raises(SystemExit, match="must be numbers"):
        gateway_config(heartbeat_seconds="soon")
