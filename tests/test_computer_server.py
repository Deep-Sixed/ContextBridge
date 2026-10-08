from __future__ import annotations

import json
import os
from pathlib import Path

import anyio
import pytest
import yaml
from fastmcp import Client
from fastmcp.exceptions import ToolError

from contextbridge.computer.policy import load_policy
from contextbridge.computer.server import (
    COMMAND_TOOLS,
    READ_TOOLS,
    WRITE_TOOLS,
    advertised_tool_names,
    computer_tool_names,
    create_computer_server,
    main,
)
from uga.audit import UgaAuditLog


def _run(server, fn):
    async def inner():
        async with Client(server) as client:
            return await fn(client)

    return anyio.run(inner)


def test_read_only_policy_exposes_only_read_tools(workspace):
    policy = load_policy({"filesystem": {"roots": [str(workspace)]}, "processes": {"list": False}})
    server = create_computer_server(policy)
    assert computer_tool_names(policy) == READ_TOOLS
    assert advertised_tool_names(server) == READ_TOOLS

    async def listed(client):
        return {t.name for t in await client.list_tools()}

    assert _run(server, listed) == READ_TOOLS


def test_full_policy_surface(make_policy):
    policy = make_policy(processes={"allow_kill": True})
    expected = READ_TOOLS | WRITE_TOOLS | COMMAND_TOOLS | {"list_processes", "kill_process"}
    assert computer_tool_names(policy) == expected
    assert advertised_tool_names(create_computer_server(policy)) == expected


def test_tool_annotations(policy):
    async def annotations(client):
        return {t.name: t.annotations for t in await client.list_tools()}

    result = _run(create_computer_server(policy), annotations)
    assert result["read_file"].readOnlyHint is True
    assert result["write_file"].destructiveHint is True
    assert result["run_command"].readOnlyHint is False


def test_calls_are_audited_with_digests_not_content(policy, tmp_path):
    log = tmp_path / "audit.jsonl"
    server = create_computer_server(policy, audit=UgaAuditLog(log, route="computer"))

    async def calls(client):
        await client.call_tool("write_file", {"path": "work/a.txt", "content": "top secret body"})
        read = await client.call_tool("read_file", {"path": "work/a.txt"})
        with pytest.raises(ToolError, match="Denied by policy"):
            await client.call_tool("read_file", {"path": ".ssh/id_ed25519"})
        return read.structured_content

    content = _run(server, calls)
    assert content["content"] == "top secret body"
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    assert [(e["tool"], e["success"]) for e in entries] == [
        ("write_file", True),
        ("read_file", True),
        ("read_file", False),
    ]
    assert entries[0]["content_bytes"] == len("top secret body")
    assert "top secret body" not in log.read_text()
    assert entries[2]["detail"] == "policy_denied"
    assert entries[2]["path"] == ".ssh/id_ed25519"


@pytest.mark.skipif(os.name == "nt", reason="uses POSIX utilities")
def test_run_command_audit_includes_exit_code(policy, tmp_path):
    log = tmp_path / "audit.jsonl"
    server = create_computer_server(policy, audit=UgaAuditLog(log, route="computer"))

    async def call(client):
        return (await client.call_tool("run_command", {"command": "echo hi"})).structured_content

    assert _run(server, call)["stdout"] == "hi\n"
    entry = json.loads(log.read_text().splitlines()[-1])
    assert entry["command"] == "echo hi"
    assert entry["exit_code"] == 0


def test_hidden_tools_are_rejected(workspace, tmp_path):
    log = tmp_path / "audit.jsonl"
    policy = load_policy({"filesystem": {"roots": [str(workspace)]}})
    server = create_computer_server(policy, audit=UgaAuditLog(log, route="computer"))

    async def call(client):
        with pytest.raises(ToolError):
            await client.call_tool("run_command", {"command": "echo hi"})
        with pytest.raises(ToolError):
            await client.call_tool("write_file", {"path": "work/x", "content": "x"})

    _run(server, call)
    assert not (workspace / "work" / "x").exists()


def _write_config(path, workspace, transport="http", host="127.0.0.1"):
    path.write_text(
        f"serve:\n  transport: {transport}\n  host: {host}\n  port: 18791\n"
        f"filesystem:\n  roots: [{workspace}]\n",
        encoding="utf-8",
    )
    return str(path)


def test_http_requires_distinct_token(workspace, tmp_path, monkeypatch):
    config = _write_config(tmp_path / "c.yaml", workspace)
    monkeypatch.delenv("CONTEXTBRIDGE_COMPUTER_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="must be set"):
        main(["--config", config])
    monkeypatch.setenv("CONTEXTBRIDGE_COMPUTER_TOKEN", "same")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "same")
    with pytest.raises(SystemExit, match="must differ"):
        main(["--config", config])


def test_http_refuses_non_loopback_bind(workspace, tmp_path, monkeypatch):
    config = _write_config(tmp_path / "c.yaml", workspace, host="0.0.0.0")
    monkeypatch.setenv("CONTEXTBRIDGE_COMPUTER_TOKEN", "computer-token")
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="refusing to bind"):
        main(["--config", config])


def test_invalid_policy_fails_startup(tmp_path):
    config = tmp_path / "c.yaml"
    config.write_text("serve:\n  transport: stdio\nfilesystem:\n  roots: []\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="at least one directory"):
        main(["--config", str(config)])


def test_shipped_config_loads():
    config = Path(__file__).resolve().parents[1] / "configs" / "computer.yaml"
    policy = load_policy(yaml.safe_load(config.read_text(encoding="utf-8")), protected=(config,))
    assert policy.command_mode == "allowlist"
    assert not policy.can_write
    assert advertised_tool_names(create_computer_server(policy)) == computer_tool_names(policy)
