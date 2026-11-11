"""MCP contract and entrypoint checks for the filesystem route (contextbridge.filesystem.gateway)."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import httpx
import importlib.metadata
import mcp.types
import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import McpError
from starlette.testclient import TestClient

import contextbridge
from conftest import TOKEN, read_audit
from helpers import assert_no_injection_text
from contextbridge.filesystem import gateway as fs_gateway
from contextbridge.filesystem.audit import GatewayAuditLog
from contextbridge.filesystem.fs import Filesystem, FsRoot
from contextbridge.filesystem.gateway import create_fs_server
from contextbridge.filesystem.policy import FS_READ_TOOLS, FS_WRITE_TOOLS
from contextbridge.filesystem.server import _guard_low_level_handlers

REPO = Path(__file__).resolve().parents[1]

EXPECTED_INPUTS = {
    "read_file": {"path", "offset", "length"},
    "read_multiple_files": {"paths"},
    "list_directory": {"path", "depth"},
    "get_file_info": {"path"},
    "write_file": {"path", "content", "mode"},
    "edit_block": {"file_path", "old_string", "new_string", "expected_replacements"},
    "create_directory": {"path"},
    "move_file": {"source", "destination"},
    "delete_file": {"path", "recursive"},
    "start_search": {
        "path",
        "pattern",
        "search_type",
        "file_pattern",
        "ignore_case",
        "literal",
        "include_hidden",
        "context_lines",
        "max_results",
        "timeout_ms",
    },
    "get_more_search_results": {"search_id", "offset", "length"},
    "stop_search": {"search_id"},
    "list_searches": set(),
}

# readOnlyHint, destructiveHint, idempotentHint; openWorldHint is always false.
EXPECTED_HINTS = {
    "read_file": (True, False, True),
    "read_multiple_files": (True, False, True),
    "list_directory": (True, False, True),
    "get_file_info": (True, False, True),
    "write_file": (False, True, False),
    "edit_block": (False, True, False),
    "create_directory": (False, False, True),
    "move_file": (False, False, False),
    "delete_file": (False, True, False),
    "start_search": (True, False, False),
    "get_more_search_results": (True, False, True),
    "stop_search": (True, False, True),
    "list_searches": (True, False, True),
}

_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 0,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest-client", "version": "1"},
    },
}


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    rw, ro = tmp_path / "rw", tmp_path / "ro"
    rw.mkdir(parents=True)
    ro.mkdir(parents=True)
    (ro / "notes.txt").write_text("hello\n", encoding="utf-8")
    return Path(os.path.realpath(rw)), Path(os.path.realpath(ro))


def _server(tmp_path: Path, *, writable: bool = True, audit_path: Path | None = None) -> FastMCP:
    rw, ro = _roots(tmp_path)
    roots = [FsRoot(rw, writable=writable), FsRoot(ro)]
    return create_fs_server(
        fs=Filesystem(roots), token=TOKEN, audit=GatewayAuditLog(audit_path, route="fs")
    )


def _session(server: FastMCP) -> dict[str, Any]:
    async def go() -> dict[str, Any]:
        async with Client(server) as client:
            return {"init": client.initialize_result, "tools": await client.list_tools()}

    return anyio.run(go)


def _call(server: FastMCP, tool: str, arguments: dict[str, Any]) -> Any:
    async def go() -> Any:
        async with Client(server) as client:
            return await client.call_tool(tool, arguments)

    return anyio.run(go)


def test_tool_surface_depends_on_writable_roots(tmp_path: Path) -> None:
    writable = _session(_server(tmp_path / "a"))["tools"]
    read_only = _session(_server(tmp_path / "b", writable=False))["tools"]

    assert {t.name for t in writable} == FS_READ_TOOLS | FS_WRITE_TOOLS == set(EXPECTED_INPUTS)
    assert {t.name for t in read_only} == FS_READ_TOOLS


def test_tools_declare_annotations_schemas_and_descriptions(tmp_path: Path) -> None:
    session = _session(_server(tmp_path))

    assert_no_injection_text("server instructions", session["init"].instructions or "")
    assert session["init"].serverInfo.version == contextbridge.__version__
    for tool in session["tools"]:
        declared = tool.annotations.model_dump(exclude_none=True) if tool.annotations else {}
        read_only, destructive, idempotent = EXPECTED_HINTS[tool.name]
        assert declared == {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": False,
        }, tool.name
        properties = set((tool.inputSchema or {}).get("properties") or {})
        assert properties == EXPECTED_INPUTS[tool.name], f"{tool.name} inputs: {properties}"
        assert tool.description, f"{tool.name} has no description"
        assert_no_injection_text(f"{tool.name} description", tool.description)


def test_instructions_name_each_root_and_its_mode(tmp_path: Path) -> None:
    rw, ro = tmp_path / "rw", tmp_path / "ro"
    instructions = _session(_server(tmp_path))["init"].instructions

    assert f"{os.path.realpath(rw)} (read-write)" in instructions
    assert f"{os.path.realpath(ro)} (read-only)" in instructions


def test_hidden_and_foreign_tools_are_denied_and_audited(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = _server(tmp_path, writable=False, audit_path=audit_path)
    denied = sorted(FS_WRITE_TOOLS | {"search", "fetch", "start_process", "shell"})

    async def go() -> Any:
        async with Client(server) as client:
            for name in denied:
                with pytest.raises(ToolError, match="not permitted on the filesystem route"):
                    await client.call_tool(name, {"path": "/etc/passwd", "content": "x"})
            return await client.call_tool("get_file_info", {"path": str(tmp_path / "ro")})

    assert anyio.run(go).structured_content["type"] == "directory"
    entries = [e for e in read_audit(audit_path) if e.get("detail") == "policy_denied"]
    assert sorted(e["tool"] for e in entries) == denied
    assert all("path" not in e for e in entries)


def test_audit_records_paths_sizes_and_denials(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = _server(tmp_path, audit_path=audit_path)
    target = str(tmp_path / "rw" / "out.txt")

    _call(server, "write_file", {"path": target, "content": "abc"})
    trash = _call(server, "delete_file", {"path": target}).structured_content["trash_path"]
    with pytest.raises(ToolError, match="read-only directory"):
        _call(server, "write_file", {"path": str(tmp_path / "ro" / "x"), "content": "x"})

    entries = [e for e in read_audit(audit_path) if e["route"] == "fs" and "path" in e]
    write, delete, refused = entries
    assert (write["tool"], write["path"], write["size"], write["success"]) == (
        "write_file",
        target,
        3,
        True,
    )
    assert (delete["tool"], delete["destination"]) == ("delete_file", trash)
    assert (refused["success"], refused["detail"]) == (False, "path_denied")
    # One line per request, written by the middleware with the tool's fields. The
    # SDK's own tools/list refresh during a call is not audited, so no other line
    # shares a call's request_id.
    lines = read_audit(audit_path)
    calls = [e for e in lines if e["tool"] not in ("initialize", "tools/list")]
    assert calls == entries
    ids = [e["request_id"] for e in lines]
    assert all(ids.count(e["request_id"]) == 1 for e in calls)


def test_search_over_mcp_is_audited_without_the_pattern(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = _server(tmp_path, writable=False, audit_path=audit_path)
    ro = str(Path(os.path.realpath(tmp_path / "ro")))

    async def go() -> tuple[Any, Any, Any]:
        async with Client(server) as client:
            started = await client.call_tool(
                "start_search", {"path": ro, "pattern": "hel+o", "search_type": "content"}
            )
            search_id = started.structured_content["search_id"]
            more = await client.call_tool("get_more_search_results", {"search_id": search_id})
            listed = await client.call_tool("list_searches", {})
            with pytest.raises(ToolError, match="search not found"):
                await client.call_tool("stop_search", {"search_id": "nope"})
        return started.structured_content, more.structured_content, listed.structured_content

    started, more, listed = anyio.run(go)

    assert started["status"] == "completed"
    assert [(r["path"], r["line"], r["text"]) for r in started["results"]] == [
        (str(Path(ro) / "notes.txt"), 1, "hello")
    ]
    assert more["results"] == started["results"]
    assert [s["search_id"] for s in listed["searches"]] == [started["search_id"]]
    entries = [e for e in read_audit(audit_path) if "search_id" in e or e.get("detail") == "not_found"]
    start, page, missing = entries
    assert (start["tool"], start["path"], start["result_count"]) == ("start_search", ro, 1)
    assert start["query_len"] == 5 and "hel+o" not in str(start)
    assert (page["tool"], page["search_id"]) == ("get_more_search_results", started["search_id"])
    assert (missing["tool"], missing["success"]) == ("stop_search", False)


def test_unexpected_errors_are_masked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(self: Filesystem, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("/secret/internal/path")

    monkeypatch.setattr(Filesystem, "read_file", broken)
    server = _server(tmp_path)

    with pytest.raises(ToolError) as excinfo:
        _call(server, "read_file", {"path": str(tmp_path / "ro" / "notes.txt")})

    assert "/secret" not in str(excinfo.value)


def test_requires_strong_token(tmp_path: Path) -> None:
    fs = Filesystem([FsRoot(tmp_path)])
    with pytest.raises(ValueError, match="CONTEXTBRIDGE_FS_AUTH_TOKEN must be at least"):
        create_fs_server(fs=fs, token="short")


def test_http_requires_bearer_token(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    audit = GatewayAuditLog(audit_path, route="fs")
    _, ro = _roots(tmp_path)
    server = create_fs_server(fs=Filesystem([FsRoot(ro)]), token=TOKEN, audit=audit)
    headers = {"Accept": "application/json, text/event-stream"}

    auth = {"Authorization": f"Bearer {TOKEN}"}

    # The server's HTTP app always carries the auth-failure audit middleware.
    with TestClient(server.http_app()) as client:
        missing = client.post("/mcp", json=_INITIALIZE, headers=headers)
        ok = client.post("/mcp", json=_INITIALIZE, headers={**headers, **auth})
        status_missing = client.get("/")
        status = client.get("/", headers=auth).json()

    assert (missing.status_code, ok.status_code, status_missing.status_code) == (401, 200, 401)
    assert status["tools"] == sorted(FS_READ_TOOLS)
    assert str(ro) not in str(status)
    auth_lines = [e["detail"] for e in read_audit(audit_path) if e["tool"] == "auth"]
    assert auth_lines == ["missing_token", "missing_token"]


def test_auth_failures_and_initialize_are_audited_with_the_client(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    _, ro = _roots(tmp_path)
    server = create_fs_server(
        fs=Filesystem([FsRoot(ro)]), token=TOKEN, audit=GatewayAuditLog(audit_path, route="fs")
    )
    headers = {"Accept": "application/json, text/event-stream"}

    with TestClient(server.http_app()) as client:
        wrong = client.post("/mcp", json=_INITIALIZE, headers={**headers, "Authorization": "Bearer " + "w" * 40})
        ok = client.post("/mcp", json=_INITIALIZE, headers={**headers, "Authorization": f"Bearer {TOKEN}"})

    assert (wrong.status_code, ok.status_code) == (401, 200)
    entries = read_audit(audit_path)
    (auth,) = [e for e in entries if e["tool"] == "auth"]
    assert (auth["detail"], auth["peer"]) == ("invalid_token", "testclient")
    (init,) = [e for e in entries if e["tool"] == "initialize"]
    assert (init["client"], init["peer"], init["route"]) == ("pytest-client", "testclient", "fs")


def test_resources_and_prompts_are_empty_or_denied(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = _server(tmp_path, audit_path=audit_path)

    async def go() -> list[Any]:
        async with Client(server) as client:
            listings = [
                await client.list_resources(),
                await client.list_resource_templates(),
                await client.list_prompts(),
            ]
            with pytest.raises(McpError, match="not permitted"):
                await client.read_resource("file:///etc/passwd")
            with pytest.raises(McpError, match="not permitted"):
                await client.get_prompt("anything")
            return listings

    assert anyio.run(go) == [[], [], []]
    outcome = {e["tool"]: e.get("detail", "ok") for e in read_audit(audit_path)}
    assert outcome["resources/list"] == outcome["resources/templates/list"] == outcome["prompts/list"] == "ok"
    assert outcome["resources/read"] == outcome["prompts/get"] == "policy_denied"


def test_low_level_handlers_outside_middleware_are_denied(tmp_path: Path) -> None:
    class FutureRequest:
        method = "future/method"

    audit_path = tmp_path / "audit.jsonl"
    server = FastMCP("x")
    handlers = server._mcp_server.request_handlers
    ping = handlers[mcp.types.PingRequest]
    handlers[FutureRequest] = ping

    _guard_low_level_handlers(server, GatewayAuditLog(audit_path, route="fs"))

    assert handlers[mcp.types.PingRequest] is ping
    with pytest.raises(McpError, match="not permitted"):
        anyio.run(handlers[FutureRequest], FutureRequest())
    (line,) = read_audit(audit_path)
    assert (line["tool"], line["detail"]) == ("future/method", "policy_denied")


def test_server_denies_logging_set_level(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = _server(tmp_path, audit_path=audit_path)
    if mcp.types.SetLevelRequest not in server._mcp_server.request_handlers:
        pytest.skip("this fastmcp release registers no logging/setLevel handler")

    async def go() -> None:
        async with Client(server) as client:
            with pytest.raises(McpError, match="not permitted"):
                await client.set_logging_level("debug")

    anyio.run(go)
    (line,) = [e for e in read_audit(audit_path) if e["tool"] == "logging/setLevel"]
    assert line["detail"] == "policy_denied"


@pytest.mark.parametrize("setting", ["CONTEXTBRIDGE_MCP_TOOL_TIMEOUT_SECONDS", "UGA_MCP_TOOL_TIMEOUT_SECONDS"])
def test_slow_calls_time_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, setting: str) -> None:
    """The per-call timeout answers the client; its pre-rename setting name still works."""

    def slow(self: Filesystem, *args: Any, **kwargs: Any) -> Any:
        time.sleep(2)
        return {}

    monkeypatch.setattr(Filesystem, "read_file", slow)
    monkeypatch.setenv(setting, "0.3")
    audit_path = tmp_path / "audit.jsonl"
    server = _server(tmp_path, audit_path=audit_path)

    started = time.monotonic()
    with pytest.raises(ToolError, match="timed out"):
        _call(server, "read_file", {"path": str(tmp_path / "ro" / "notes.txt")})
    assert time.monotonic() - started < 1.5
    (line,) = [e for e in read_audit(audit_path) if e["tool"] == "read_file"]
    assert line["detail"] == "timeout"


def test_installed_metadata_matches_package_version() -> None:
    try:
        installed = importlib.metadata.version("contextbridge")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("contextbridge is not installed; run pip install -e .")
    assert installed == contextbridge.__version__


def _write_config(tmp_path: Path, port: int, roots: str, serve_extra: str = "") -> Path:
    config = tmp_path / "fs.yaml"
    config.write_text(
        f"name: ContextBridge Files\nserve:\n  host: 127.0.0.1\n  port: {port}\n{serve_extra}"
        f"filesystem:\n  roots:\n{roots}",
        encoding="utf-8",
    )
    return config


def _run_main(monkeypatch: pytest.MonkeyPatch, config: Path) -> None:
    monkeypatch.setattr(sys, "argv", ["fs_gateway", "--config", str(config)])
    fs_gateway.main()


def test_main_refuses_a_missing_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "data").mkdir()
    config = _write_config(tmp_path, 1, "    - path: data\n")

    with pytest.raises(SystemExit, match="CONTEXTBRIDGE_FS_AUTH_TOKEN must be set"):
        _run_main(monkeypatch, config)


def test_main_refuses_the_computer_routes_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "data").mkdir()
    config = _write_config(tmp_path, 1, "    - path: data\n")

    monkeypatch.setenv("CONTEXTBRIDGE_FS_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("CONTEXTBRIDGE_COMPUTER_TOKEN", TOKEN)
    with pytest.raises(SystemExit, match="must differ from CONTEXTBRIDGE_COMPUTER_TOKEN"):
        _run_main(monkeypatch, config)


def test_main_refuses_bad_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTBRIDGE_FS_AUTH_TOKEN", TOKEN)
    config = _write_config(tmp_path, 1, "    - path: missing\n")

    with pytest.raises(SystemExit, match="startup failed: .*directory not found"):
        _run_main(monkeypatch, config)


def test_shipped_config_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTBRIDGE_FS_AUTH_TOKEN", TOKEN)

    with pytest.raises(SystemExit, match="filesystem.roots must list at least one directory"):
        _run_main(monkeypatch, REPO / "configs" / "contextbridge-fs.yaml")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def fs_gateway_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[str, Path, Path]]:
    tmp = tmp_path_factory.mktemp("fs-entrypoint")
    (tmp / "work").mkdir()
    port = _free_port()
    # A relative audit_log resolves against the config's directory, not the cwd.
    config = _write_config(
        tmp, port, "    - path: work\n      writable: true\n", "  audit_log: fs-audit.jsonl\n"
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("UGA_", "CONTEXTBRIDGE_"))
    }
    env["CONTEXTBRIDGE_FS_AUTH_TOKEN"] = TOKEN
    env["PYTHONPATH"] = str(REPO / "src")
    log = tmp / "fs-gateway.log"
    base = f"http://127.0.0.1:{port}"
    with log.open("w") as log_fh:
        proc = subprocess.Popen(
            [sys.executable, "-m", "contextbridge.filesystem.gateway", "--config", str(config)],
            cwd=tmp_path_factory.mktemp("fs-cwd"),
            env=env,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 30
            while True:
                if proc.poll() is not None:
                    pytest.fail(f"filesystem gateway exited early:\n{log.read_text()}")
                try:
                    status = httpx.get(
                        f"{base}/",
                        headers={"Authorization": f"Bearer {TOKEN}"},
                        timeout=1,
                        trust_env=False,
                    )
                    if status.status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() > deadline:
                    pytest.fail(f"filesystem gateway did not start:\n{log.read_text()}")
                time.sleep(0.2)
            assert "serving 13 tools over 1 root(s) (1 writable)" in log.read_text()
            yield base, Path(os.path.realpath(tmp / "work")), tmp / "fs-audit.jsonl"

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def test_entrypoint_rejects_requests_without_token(
    fs_gateway_url: tuple[str, Path, Path],
) -> None:
    base, _, audit_path = fs_gateway_url
    response = httpx.post(
        f"{base}/mcp",
        json=_INITIALIZE,
        headers={
            "Accept": "application/json, text/event-stream",
            "X-Forwarded-For": "203.0.113.9",
        },
        timeout=5,
        trust_env=False,
    )

    assert response.status_code == 401
    # Audited next to the config, with the TCP peer rather than the forwarded one.
    auth = [e for e in read_audit(audit_path) if e["tool"] == "auth"]
    assert auth and all(e["peer"] == "127.0.0.1" for e in auth)


def test_entrypoint_writes_and_reads_with_token(fs_gateway_url: tuple[str, Path, Path]) -> None:
    base, work, _ = fs_gateway_url
    target = str(work / "hello.txt")

    async def go() -> str:
        async with Client(f"{base}/mcp", auth=TOKEN) as client:
            await client.call_tool("write_file", {"path": target, "content": "hi\n"})
            result = await client.call_tool("read_file", {"path": target})
        return result.structured_content["content"]

    assert anyio.run(go) == "hi\n"
