from __future__ import annotations

import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import anyio
import pytest
import yaml
from fastmcp import Client
from fastmcp.exceptions import ToolError

from contextbridge.computer.audit import AuditError, ComputerAuditLog
from contextbridge.computer.policy import PolicyError, load_policy
from contextbridge.computer.server import (
    ALL_SCOPES,
    COMMAND_TOOLS,
    READ_TOOLS,
    SCOPE_READ,
    SERVER_TOOLS,
    TOOL_SCOPES,
    WRITE_TOOLS,
    AuthorizationError,
    advertised_tool_names,
    computer_tool_names,
    create_computer_server,
    load_scopes,
)

posix_only = pytest.mark.skipif(os.name == "nt", reason="uses POSIX utilities")


def allow_scopes(*scopes: str):
    """Authorizer standing in for a bearer token that carries ``scopes``."""

    def authorize(tool: str) -> str:
        if TOOL_SCOPES.get(tool) not in scopes:
            raise AuthorizationError(f"Token is not authorized for '{tool}'.")
        return "test-client"

    return authorize


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit" / "computer.audit.jsonl"


@pytest.fixture
def audit(audit_path: Path) -> ComputerAuditLog:
    return ComputerAuditLog(audit_path, echo=False)


def events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def by_request(path: Path) -> list[list[str]]:
    """Event names grouped per request, in order."""
    groups: dict[str, list[str]] = {}
    for entry in events(path):
        if "request_id" in entry:
            groups.setdefault(entry["request_id"], []).append(entry["event"])
    return list(groups.values())


def run(server, fn):
    async def inner():
        async with Client(server) as client:
            return await fn(client)

    return anyio.run(inner)


# --------------------------------------------------------------- surface


def test_read_only_policy_exposes_only_read_tools(workspace, audit):
    policy = load_policy({"filesystem": {"roots": [str(workspace)]}, "processes": {"list": False}})
    server = create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES))
    assert computer_tool_names(policy) == READ_TOOLS
    assert advertised_tool_names(server) == SERVER_TOOLS  # registered once; filtered per caller and device

    async def listed(client):
        return {t.name for t in await client.list_tools()}

    assert run(server, listed) == READ_TOOLS | {"list_devices"}


def test_full_policy_surface(make_policy, audit):
    policy = make_policy(processes={"allow_kill": True})
    expected = READ_TOOLS | WRITE_TOOLS | COMMAND_TOOLS | {"list_processes", "kill_process"}
    assert computer_tool_names(policy) == expected
    assert set(TOOL_SCOPES) == expected | {"list_devices", "list_windows"} == SERVER_TOOLS
    server = create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES))

    async def listed(client):
        return {t.name for t in await client.list_tools()}

    assert run(server, listed) == expected | {"list_devices"}


def test_tool_annotations(policy, audit):
    async def annotations(client):
        return {t.name: t.annotations for t in await client.list_tools()}

    result = run(create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES)), annotations)
    assert result["read_file"].readOnlyHint is True
    assert result["write_file"].destructiveHint is True
    assert result["run_command"].readOnlyHint is False


# --------------------------------------------------------- authorization


def test_unauthenticated_calls_are_denied_at_execution(policy, audit, audit_path, workspace):
    """The default authorizer needs a bearer token; an in-process client has none."""
    server = create_computer_server(policy, audit=audit)

    async def calls(client):
        assert await client.list_tools() == []
        with pytest.raises(ToolError, match="Authentication required"):
            await client.call_tool("read_file", {"path": "docs/notes.md"})
        with pytest.raises(ToolError, match="Authentication required"):
            await client.call_tool("write_file", {"path": "work/x.txt", "content": "x"})

    run(server, calls)
    assert not (workspace / "work" / "x.txt").exists()
    assert by_request(audit_path) == [["requested", "denied"], ["requested", "denied"]]


def test_scopes_are_enforced_per_call(policy, audit, audit_path, workspace):
    server = create_computer_server(policy, audit=audit, authorize=allow_scopes(SCOPE_READ))

    async def calls(client):
        names = {t.name for t in await client.list_tools()}
        assert "read_file" in names and "write_file" not in names and "run_command" not in names
        await client.call_tool("read_file", {"path": "docs/notes.md"})
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("write_file", {"path": "work/x.txt", "content": "x"})
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("run_command", {"command": "echo hi"})

    run(server, calls)
    assert not (workspace / "work" / "x.txt").exists()
    assert by_request(audit_path) == [
        ["requested", "started", "completed"],
        ["requested", "denied"],
        ["requested", "denied"],
    ]


def test_tools_outside_policy_are_rejected(workspace, audit, audit_path):
    policy = load_policy({"filesystem": {"roots": [str(workspace)]}})
    server = create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES))

    async def call(client):
        with pytest.raises(ToolError, match="not permitted"):
            await client.call_tool("run_command", {"command": "echo hi"})
        with pytest.raises(ToolError, match="not permitted"):
            await client.call_tool("write_file", {"path": "work/x", "content": "x"})

    run(server, call)
    assert not (workspace / "work" / "x").exists()
    assert by_request(audit_path) == [["requested", "denied"], ["requested", "denied"]]


# ---------------------------------------------------------------- audit


def test_audit_lifecycle_for_successful_and_rejected_calls(policy, audit, audit_path):
    server = create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES))

    async def calls(client):
        await client.call_tool("write_file", {"path": "work/a.txt", "content": "top secret body"})
        read = await client.call_tool("read_file", {"path": "work/a.txt"})
        with pytest.raises(ToolError, match="Denied by policy"):
            await client.call_tool("read_file", {"path": ".ssh/id_ed25519"})
        with pytest.raises(ToolError, match="No such file"):
            await client.call_tool("read_file", {"path": "docs/missing.md"})
        return read.structured_content

    assert run(server, calls)["content"] == "top secret body"
    assert by_request(audit_path) == [
        ["requested", "started", "completed"],
        ["requested", "started", "completed"],
        ["requested", "denied"],
        ["requested", "failed"],
    ]
    log = events(audit_path)
    write_requested, write_started, write_completed = log[0:3]
    assert write_requested["path"] == "work/a.txt"
    assert write_requested["content_bytes"] == len("top secret body")
    assert "top secret body" not in audit_path.read_text()
    assert write_started["path"].endswith(os.path.join("work", "a.txt"))
    assert write_completed["success"] is True
    assert write_completed["client"] == "test-client"
    denied = log[6:8]
    assert denied[1]["detail"] == "PolicyViolation"
    assert "outside" in denied[1]["reason"] or "denied" in denied[1]["reason"]


@posix_only
def test_audit_distinguishes_completed_from_successful_commands(policy, audit, audit_path):
    server = create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES))

    async def calls(client):
        ok = await client.call_tool("run_command", {"command": "echo hi"})
        bad = await client.call_tool("run_command", {"command": "ls does-not-exist"})
        return ok.structured_content, bad.structured_content

    ok, bad = run(server, calls)
    assert ok["stdout"] == "hi\n" and bad["exit_code"] != 0
    completed = [e for e in events(audit_path) if e["event"] == "completed"]
    assert [(e["exit_code"] == 0, e["success"]) for e in completed] == [(True, True), (False, False)]
    started = [e for e in events(audit_path) if e["event"] == "started"]
    assert started[0]["argv"][-1] == "hi"
    assert completed[0]["pid"] > 0


@posix_only
def test_unlisted_command_is_denied_before_execution(policy, audit, audit_path, workspace):
    server = create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES))

    async def call(client):
        with pytest.raises(ToolError, match="allowlist"):
            await client.call_tool("run_command", {"command": "touch pwned", "cwd": str(workspace / "work")})
        with pytest.raises(ToolError, match="Shell operators"):
            await client.call_tool("run_command", {"command": "echo hi > pwned", "cwd": str(workspace / "work")})

    run(server, call)
    assert not (workspace / "work" / "pwned").exists()
    assert by_request(audit_path) == [["requested", "denied"], ["requested", "denied"]]


@posix_only
def test_timed_out_command_is_completed_but_not_successful(make_policy, audit, audit_path):
    policy = make_policy(commands={"mode": "unrestricted"})
    server = create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES))

    async def call(client):
        return (await client.call_tool("run_command", {"command": "sleep 30", "timeout_seconds": 1})).structured_content

    assert run(server, call)["timed_out"] is True
    completed = events(audit_path)[-1]
    assert completed["event"] == "completed"
    assert completed["timed_out"] is True and completed["success"] is False


@posix_only
def test_session_exit_is_audited(make_policy, audit, audit_path):
    policy = make_policy(commands={"mode": "unrestricted"})
    server = create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES))

    async def call(client):
        return (await client.call_tool("start_process", {"command": "exit 3", "wait_seconds": 2})).structured_content

    session = run(server, call)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not any(e["event"] == "exited" for e in events(audit_path)):
        time.sleep(0.05)
    exited = [e for e in events(audit_path) if e["event"] == "exited"]
    assert len(exited) == 1
    assert exited[0]["session_id"] == session["session_id"]
    assert exited[0]["exit_code"] == 3 and exited[0]["success"] is False


def test_audit_failure_blocks_execution(policy, audit, workspace):
    server = create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES))
    audit.close()
    audit._fh = open(os.devnull, "r")  # a handle that rejects writes, like a full or revoked disk

    async def call(client):
        with pytest.raises(ToolError, match="Audit log unavailable"):
            await client.call_tool("write_file", {"path": "work/blocked.txt", "content": "x"})

    run(server, call)
    assert not (workspace / "work" / "blocked.txt").exists()


def test_audit_log_that_cannot_be_opened_fails(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(AuditError):
        ComputerAuditLog(blocker / "audit.jsonl")


# --------------------------------------------------------------- config


def test_shipped_config_loads():
    config = Path(__file__).resolve().parents[1] / "configs" / "computer.yaml"
    cfg = yaml.safe_load(config.read_text(encoding="utf-8"))
    policy = load_policy(cfg, protected=(config,))
    assert policy.command_mode == "allowlist"
    assert not policy.can_write
    assert cfg["serve"]["host"] == "127.0.0.1"
    assert cfg["serve"]["audit_log"]


def test_scope_config_defaults_and_validation():
    assert load_scopes({}) == ALL_SCOPES
    assert load_scopes({"auth": {"scopes": ["computer:read", "computer:read"]}}) == ("computer:read",)
    for bad in ([], ["computer:root"], "computer:read"):
        with pytest.raises(PolicyError):
            load_scopes({"auth": {"scopes": bad}})


def test_desktop_observe_requires_host_opt_in_and_explicit_client_scope(workspace, audit, monkeypatch):
    from contextbridge.computer import desktop
    monkeypatch.setattr(desktop, "_linux_windows", lambda: [{"id": "0x1", "title": "Editor"}])
    # Swap only desktop's view of the OS: patching os.name itself breaks pathlib on Windows.
    monkeypatch.setattr(desktop, "os", SimpleNamespace(name="posix", environ=os.environ))
    policy = load_policy({"filesystem": {"roots": [str(workspace)]}, "desktop": {"observe": True}})
    assert "list_windows" in computer_tool_names(policy)

    async def list_and_call(client):
        names = {tool.name for tool in await client.list_tools()}
        result = await client.call_tool("list_windows", {})
        return names, result.data

    limited = create_computer_server(policy, audit=audit, authorize=allow_scopes(SCOPE_READ))
    async def listed(client):
        return {t.name for t in await client.list_tools()}
    assert "list_windows" not in run(limited, listed)

    granted = create_computer_server(policy, audit=audit, authorize=allow_scopes(*ALL_SCOPES))
    names, result = run(granted, list_and_call)
    assert "list_windows" in names
    assert result["count"] == 1
