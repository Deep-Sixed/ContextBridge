"""Phase 1–2 acceptance tests.

Both gateways are launched exactly as in production — separate processes serving
HTTP with bearer authentication — and exercised through a real MCP client. The
child environment carries only Python and the gateway's own settings: no Node,
no npx, nothing from Desktop Commander.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import anyio
import httpx
import pytest
import yaml
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.exceptions import ToolError

from contextbridge.computer.server import main as computer_main

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "datacore" / "datacore.fetch.v1.jsonl"
COMPUTER_TOKEN = "computer-" + "c" * 40
KNOWLEDGE_TOKEN = "knowledge-" + "k" * 40

pytestmark = pytest.mark.skipif(os.name == "nt", reason="acceptance suite targets the Linux host")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _isolated_env(**extra: str) -> dict[str, str]:
    """Minimal environment: this Python, system binaries, and nothing else."""
    return {
        "PATH": os.pathsep.join([str(Path(sys.executable).parent), "/usr/bin", "/bin"]),
        "PYTHONPATH": str(REPO / "src"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
        **extra,
    }


@contextmanager
def serve(module: str, config: Path, port: int, env: dict[str, str]) -> Iterator[str]:
    proc = subprocess.Popen(
        [sys.executable, "-m", module, "--config", str(config)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            if proc.poll() is not None:
                raise AssertionError(f"{module} exited early:\n{proc.stderr.read()}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise AssertionError(f"{module} did not start listening on {port}") from None
                time.sleep(0.1)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def call(url: str, token: str | None, fn):
    async def inner():
        async with Client(url, auth=BearerAuth(token) if token else None) as client:
            return await fn(client)

    return anyio.run(inner)


def _computer_config(tmp_path: Path, workspace: Path, port: int, scopes: list[str] | None = None) -> Path:
    cfg = {
        "serve": {"host": "127.0.0.1", "port": port, "audit_log": str(tmp_path / "audit" / "computer.jsonl")},
        "filesystem": {"roots": [str(workspace)], "writable_roots": [str(workspace / "work")]},
        "commands": {"mode": "allowlist", "allow": ["echo", "ls"], "max_timeout_seconds": 5},
    }
    if scopes is not None:
        cfg["auth"] = {"scopes": scopes}
    path = tmp_path / "computer.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path


def _requests(audit_log: Path) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for line in audit_log.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        if "request_id" in entry:
            grouped.setdefault(entry["request_id"], []).append(entry)
    return grouped


# ------------------------------------------------------------ knowledge route


def test_knowledge_gateway_serves_search_and_fetch(tmp_path):
    port = _free_port()
    config = tmp_path / "contextbridge.yaml"
    config.write_text(f"name: ContextBridge\nserve:\n  host: 127.0.0.1\n  port: {port}\n", encoding="utf-8")
    env = _isolated_env(MCP_AUTH_TOKEN=KNOWLEDGE_TOKEN, UGA_DATACORE_JSONL=str(FIXTURE))
    with serve("uga.gateway", config, port, env) as url:

        async def use(client):
            tools = {t.name for t in await client.list_tools()}
            hits = (await client.call_tool("search", {"query": "approved knowledge"})).structured_content
            record = (await client.call_tool("fetch", {"id": "rec-002"})).structured_content
            return tools, hits, record

        tools, hits, record = call(url, KNOWLEDGE_TOKEN, use)
        assert tools == {"search", "fetch"}
        assert {hit["id"] for hit in hits["results"]} == {"rec-001"}
        assert record["title"] == "Computer route policy"

        for token in (None, "wrong-token", COMPUTER_TOKEN):
            with pytest.raises(httpx.HTTPStatusError) as err:
                call(url, token, lambda client: client.list_tools())
            assert err.value.response.status_code == 401


# ------------------------------------------------------------- computer route


@pytest.fixture
def computer(tmp_path, workspace):
    port = _free_port()
    config = _computer_config(tmp_path, workspace, port)
    env = _isolated_env(CONTEXTBRIDGE_COMPUTER_TOKEN=COMPUTER_TOKEN)
    with serve("contextbridge.computer", config, port, env) as url:
        yield url, tmp_path / "audit" / "computer.jsonl"


def test_computer_gateway_starts_and_serves_authorized_requests(computer, workspace):
    url, audit_log = computer

    async def use(client):
        tools = {t.name for t in await client.list_tools()}
        text = (await client.call_tool("read_file", {"path": "docs/notes.md"})).structured_content
        echoed = (await client.call_tool("run_command", {"command": "echo hello"})).structured_content
        listed = (await client.call_tool("run_command", {"command": "ls", "cwd": "docs"})).structured_content
        written = (await client.call_tool("write_file", {"path": "work/out.txt", "content": "ok"})).structured_content
        return tools, text, echoed, listed, written

    tools, text, echoed, listed, written = call(url, COMPUTER_TOKEN, use)
    assert {"read_file", "run_command", "write_file"} <= tools
    assert text["content"] == "alpha\nbeta\ngamma\n"
    assert echoed["exit_code"] == 0 and echoed["stdout"] == "hello\n"
    assert "notes.md" in listed["stdout"]
    assert written["bytes_written"] == 2 and (workspace / "work" / "out.txt").read_text() == "ok"

    lifecycles = [[e["event"] for e in group] for group in _requests(audit_log).values()]
    assert lifecycles == [["requested", "started", "completed"]] * 4
    completed = [group[-1] for group in _requests(audit_log).values()]
    assert all(e["success"] and e["client"] == "contextbridge-computer" for e in completed)
    first = audit_log.read_text(encoding="utf-8").splitlines()[0]
    assert json.loads(first)["event"] == "service_started"


def test_computer_gateway_requires_its_own_credential(computer):
    url, _ = computer
    for token in (None, "wrong-token", KNOWLEDGE_TOKEN):
        with pytest.raises(httpx.HTTPStatusError) as err:
            call(url, token, lambda client: client.list_tools())
        assert err.value.response.status_code == 401


def test_computer_gateway_rejects_traversal_and_unlisted_commands(computer, workspace):
    url, audit_log = computer
    attempts = [
        ("read_file", {"path": "../outside.txt"}, "outside"),
        ("read_file", {"path": "docs/../../outside.txt"}, "outside"),
        ("read_file", {"path": "/etc/passwd"}, "outside"),
        ("read_file", {"path": ".ssh/id_ed25519"}, "denied"),
        ("list_directory", {"path": str(workspace.parent)}, "outside"),
        ("write_file", {"path": "docs/notes.md", "content": "x"}, "writable"),
        ("write_file", {"path": "work/../../escape.txt", "content": "x"}, "writable"),
        ("run_command", {"command": "ls", "cwd": "/"}, "outside"),
        ("run_command", {"command": "touch pwned", "cwd": "work"}, "allowlist"),
        ("run_command", {"command": "echo x > pwned", "cwd": "work"}, "Shell operators"),
        ("run_command", {"command": "/bin/sh -c 'touch pwned'", "cwd": "work"}, "allowlist"),
    ]

    async def use(client):
        for tool, args, message in attempts:
            with pytest.raises(ToolError, match=message):
                await client.call_tool(tool, args)

    call(url, COMPUTER_TOKEN, use)
    assert not (workspace / "work" / "pwned").exists()
    assert not (workspace.parent / "escape.txt").exists()
    assert (workspace / "docs" / "notes.md").read_text() == "alpha\nbeta\ngamma\n"
    lifecycles = [[e["event"] for e in group] for group in _requests(audit_log).values()]
    assert lifecycles == [["requested", "denied"]] * len(attempts)


def test_computer_gateway_bounds_time_and_output(tmp_path, workspace):
    port = _free_port()
    cfg = {
        "serve": {"host": "127.0.0.1", "port": port, "audit_log": str(tmp_path / "audit.jsonl")},
        "filesystem": {"roots": [str(workspace)]},
        "commands": {"mode": "unrestricted", "max_timeout_seconds": 2, "max_output_bytes": 4096},
    }
    config = tmp_path / "computer.yaml"
    config.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    env = _isolated_env(CONTEXTBRIDGE_COMPUTER_TOKEN=COMPUTER_TOKEN)
    with serve("contextbridge.computer", config, port, env) as url:

        async def use(client):
            slow = await client.call_tool("run_command", {"command": "sleep 60", "timeout_seconds": 600})
            loud = await client.call_tool("run_command", {"command": "yes | head -c 2000000"})
            return slow.structured_content, loud.structured_content

        started = time.monotonic()
        slow, loud = call(url, COMPUTER_TOKEN, use)
        assert time.monotonic() - started < 20
    assert slow["timed_out"] is True and slow["timeout_seconds"] == 2
    assert loud["stdout_truncated"] is True and len(loud["stdout"]) < 4096 + 100
    outcomes = [group[-1] for group in _requests(tmp_path / "audit.jsonl").values()]
    assert [(e["event"], e["success"]) for e in outcomes] == [("completed", False), ("completed", True)]


def test_scopes_are_enforced_at_execution_time(tmp_path, workspace):
    port = _free_port()
    config = _computer_config(tmp_path, workspace, port, scopes=["computer:read"])
    env = _isolated_env(CONTEXTBRIDGE_COMPUTER_TOKEN=COMPUTER_TOKEN)
    with serve("contextbridge.computer", config, port, env) as url:

        async def use(client):
            tools = {t.name for t in await client.list_tools()}
            await client.call_tool("read_file", {"path": "docs/notes.md"})
            with pytest.raises(ToolError, match="not authorized"):
                await client.call_tool("run_command", {"command": "echo hi"})
            with pytest.raises(ToolError, match="not authorized"):
                await client.call_tool("write_file", {"path": "work/x.txt", "content": "x"})
            return tools

        tools = call(url, COMPUTER_TOKEN, use)
    assert "read_file" in tools and not tools & {"run_command", "write_file"}
    assert not (workspace / "work" / "x.txt").exists()


# ------------------------------------------------------------ startup gates


@pytest.fixture
def startup(tmp_path, workspace, monkeypatch):
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("CONTEXTBRIDGE_COMPUTER_TOKEN", COMPUTER_TOKEN)

    def launch(**serve_overrides):
        cfg = yaml.safe_load(_computer_config(tmp_path, workspace, 18791).read_text(encoding="utf-8"))
        cfg["serve"].update(serve_overrides)
        cfg["serve"] = {k: v for k, v in cfg["serve"].items() if v is not None}
        path = tmp_path / "startup.yaml"
        path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        computer_main(["--config", str(path)])

    return launch


@pytest.mark.parametrize(
    "env, message",
    [
        ({"CONTEXTBRIDGE_COMPUTER_TOKEN": None}, "must be set"),
        ({"CONTEXTBRIDGE_COMPUTER_TOKEN": "short"}, "at least 32"),
        ({"MCP_AUTH_TOKEN": COMPUTER_TOKEN}, "must differ"),
    ],
)
def test_missing_or_weak_credentials_fail_startup(startup, monkeypatch, env, message):
    for key, value in env.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    with pytest.raises(SystemExit, match=message):
        startup()


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "friday.local"])
def test_non_loopback_bind_fails_startup(startup, host):
    with pytest.raises(SystemExit, match="loopback"):
        startup(host=host)


def test_missing_audit_log_fails_startup(startup):
    with pytest.raises(SystemExit, match="audit_log is required"):
        startup(audit_log=None)


def test_unwritable_audit_log_fails_startup(startup, tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(SystemExit, match="Cannot open audit log"):
        startup(audit_log=str(blocker / "audit.jsonl"))


# ------------------------------------------------------------- independence


def test_no_desktop_commander_dependency():
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    deps = " ".join(pyproject["project"]["dependencies"]).lower()
    assert "desktop" not in deps and "commander" not in deps
    # Imports of a Desktop Commander module, its npm package, or launching Node/npx.
    pattern = re.compile(r"^\s*(import|from)\s+\S*desktop|wonderwhy-er|[\"']npx[\"']|[\"']node[\"']", re.M | re.I)
    offenders = [
        str(path.relative_to(REPO))
        for path in (REPO / "src").rglob("*.py")
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []
