from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import mcp.types
import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import McpError
from starlette.testclient import TestClient

from conftest import TOKEN, read_audit, record, write_jsonl
from uga.adapter import DatacoreStore
from uga.audit import UgaAuditLog
from uga.gateway import (
    _config_relative,
    _datacore_path,
    _guard_low_level_handlers,
    create_uga_server,
)


def _store(tmp_path: Path) -> DatacoreStore:
    return DatacoreStore.from_jsonl(write_jsonl(tmp_path / "d.jsonl", [record("r1"), record("r2")]))


def _call(server: Any, tool: str, arguments: dict[str, Any]) -> Any:
    async def go() -> Any:
        async with Client(server) as client:
            return await client.call_tool(tool, arguments)

    return anyio.run(go)


class _SlowScanStore(DatacoreStore):
    """A scan that takes 2s, yielding a chunk marker every 50ms like a long real scan."""

    chunks_scanned = 0

    def iter_search(self, query: str, *, limit: int | None = None) -> Iterator[dict | None]:
        for _ in range(40):
            time.sleep(0.05)
            type(self).chunks_scanned += 1
            yield None
        yield from super().iter_search(query, limit=limit)


class _BrokenStore(DatacoreStore):
    def iter_search(self, query: str, *, limit: int | None = None) -> Iterator[dict | None]:
        raise FileNotFoundError(2, "No such file or directory", "/secret/path/missing.jsonl")


def test_tool_timeout_stops_the_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UGA_MCP_TOOL_TIMEOUT_SECONDS", "0.3")
    audit_path = tmp_path / "audit.jsonl"
    server = create_uga_server(
        store=_SlowScanStore(_store(tmp_path)._records), token=TOKEN, audit=UgaAuditLog(audit_path)
    )

    started = time.monotonic()
    with pytest.raises(ToolError, match="timed out"):
        _call(server, "search", {"query": "r1"})
    assert time.monotonic() - started < 1.2

    scanned_at_timeout = _SlowScanStore.chunks_scanned
    time.sleep(0.5)
    assert _SlowScanStore.chunks_scanned == scanned_at_timeout, "scan kept running after timeout"
    search_lines = [e for e in read_audit(audit_path) if e["tool"] == "search"]
    assert len(search_lines) == 1
    assert search_lines[0]["success"] is False
    assert search_lines[0]["detail"] == "timeout"


def test_error_details_are_masked(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = create_uga_server(store=_BrokenStore({}), token=TOKEN, audit=UgaAuditLog(audit_path))

    with pytest.raises(ToolError) as excinfo:
        _call(server, "search", {"query": "x"})

    assert "/secret" not in str(excinfo.value)
    (line,) = [e for e in read_audit(audit_path) if e["tool"] == "search"]
    assert line["detail"] == "FileNotFoundError"


def test_not_found_echo_and_audit_are_clipped(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = create_uga_server(store=_store(tmp_path), token=TOKEN, audit=UgaAuditLog(audit_path))

    with pytest.raises(ToolError, match="Record not found: nope"):
        _call(server, "fetch", {"id": "nope"})
    with pytest.raises(ToolError) as excinfo:
        _call(server, "fetch", {"id": "x" * 100_000})

    assert len(str(excinfo.value)) < 300
    fetch_lines = [e for e in read_audit(audit_path) if e["tool"] == "fetch"]
    assert [e["detail"] for e in fetch_lines] == ["not_found", "not_found"]
    assert len(fetch_lines[1]["record_id"]) < 300


def test_one_audit_line_per_request(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = create_uga_server(store=_store(tmp_path), token=TOKEN, audit=UgaAuditLog(audit_path))

    async def go() -> None:
        async with Client(server) as client:
            with pytest.raises(ToolError, match="not permitted"):
                await client.call_tool("shell", {"command": "id"})
            await client.call_tool("search", {"query": "r1"})
            await client.call_tool("fetch", {"id": "r1"})

    anyio.run(go)

    entries = read_audit(audit_path)
    request_ids = [e["request_id"] for e in entries]
    assert len(request_ids) == len(set(request_ids)), entries
    by_tool = {e["tool"]: e for e in entries}
    assert by_tool["shell"]["detail"] == "policy_denied"
    assert by_tool["search"]["result_count"] == 1 and "query_hash" in by_tool["search"]
    assert by_tool["fetch"]["record_id"] == "r1" and by_tool["fetch"]["success"] is True


def test_resources_and_prompts_are_empty_or_denied(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = create_uga_server(store=_store(tmp_path), token=TOKEN, audit=UgaAuditLog(audit_path))

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
    assert outcome["resources/list"] == "ok"
    assert outcome["resources/templates/list"] == "ok"
    assert outcome["prompts/list"] == "ok"
    assert outcome["resources/read"] == "policy_denied"
    assert outcome["prompts/get"] == "policy_denied"


def test_low_level_handlers_outside_middleware_are_denied(tmp_path: Path) -> None:
    class FutureRequest:
        method = "future/method"

    audit_path = tmp_path / "audit.jsonl"
    server = FastMCP("x")
    handlers = server._mcp_server.request_handlers
    ping = handlers[mcp.types.PingRequest]
    handlers[FutureRequest] = ping

    _guard_low_level_handlers(server, UgaAuditLog(audit_path))

    assert handlers[mcp.types.PingRequest] is ping
    with pytest.raises(McpError, match="not permitted"):
        anyio.run(handlers[FutureRequest], FutureRequest())
    (line,) = read_audit(audit_path)
    assert (line["tool"], line["detail"]) == ("future/method", "policy_denied")


def test_server_denies_logging_set_level(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = create_uga_server(store=_store(tmp_path), token=TOKEN, audit=UgaAuditLog(audit_path))
    if mcp.types.SetLevelRequest not in server._mcp_server.request_handlers:
        pytest.skip("this fastmcp release registers no logging/setLevel handler")

    async def go() -> None:
        async with Client(server) as client:
            with pytest.raises(McpError, match="not permitted"):
                await client.set_logging_level("debug")

    anyio.run(go)
    (line,) = [e for e in read_audit(audit_path) if e["tool"] == "logging/setLevel"]
    assert line["detail"] == "policy_denied"


def test_server_requires_strong_token(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must be set"):
        create_uga_server(store=_store(tmp_path))
    with pytest.raises(ValueError, match="at least"):
        create_uga_server(store=_store(tmp_path), token="x")


def test_server_requires_data_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_AUTH_TOKEN", TOKEN)
    with pytest.raises(ValueError, match="UGA_DATACORE_JSONL"):
        create_uga_server()


def test_server_reads_data_source_and_token_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # what ~ expands to on Windows
    write_jsonl(tmp_path / "d.jsonl", [record()])
    monkeypatch.setenv("MCP_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("UGA_DATACORE_JSONL", "~/d.jsonl")

    server = create_uga_server()

    assert server.auth is not None
    assert _call(server, "fetch", {"id": "r1"}).structured_content["id"] == "r1"


def test_server_rejects_missing_env_data_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MCP_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("UGA_DATACORE_JSONL", str(tmp_path / "missing.jsonl"))
    with pytest.raises(ValueError, match="not found"):
        create_uga_server()


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


def test_http_app_audits_auth_failures(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = create_uga_server(store=_store(tmp_path), token=TOKEN, audit=UgaAuditLog(audit_path))
    headers = {"Accept": "application/json, text/event-stream"}

    # No extra middleware: auditing must come with the server's own http_app.
    with TestClient(server.http_app()) as client:
        missing = client.post("/mcp", json=_INITIALIZE, headers=headers)
        wrong = client.post(
            "/mcp", json=_INITIALIZE, headers={**headers, "Authorization": "Bearer " + "w" * 40}
        )
        ok = client.post(
            "/mcp", json=_INITIALIZE, headers={**headers, "Authorization": f"Bearer {TOKEN}"}
        )

    assert (missing.status_code, wrong.status_code, ok.status_code) == (401, 401, 200)
    entries = read_audit(audit_path)
    auth = [e for e in entries if e["tool"] == "auth"]
    assert [e["detail"] for e in auth] == ["missing_token", "invalid_token"]
    assert all(e["peer"] == "testclient" for e in auth)
    (init,) = [e for e in entries if e["tool"] == "initialize"]
    assert init["client"] == "pytest-client"
    assert init["peer"] == "testclient"


def test_fetch_truncates_long_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UGA_MCP_FETCH_MAX_CHARS", "10")
    store = DatacoreStore.from_jsonl(
        write_jsonl(tmp_path / "d.jsonl", [record("long", text="x" * 25), record("short", text="tiny")])
    )
    server = create_uga_server(store=store, token=TOKEN, audit=UgaAuditLog(None))

    long = _call(server, "fetch", {"id": "long"}).structured_content
    short = _call(server, "fetch", {"id": "short"}).structured_content

    assert (long["text"], long["truncated"], long["text_length"]) == ("x" * 10, True, 25)
    assert short["text"] == "tiny"
    assert "truncated" not in short and "text_length" not in short


def test_fetch_cap_defaults_to_100k_chars(tmp_path: Path) -> None:
    text = "y" * 100_001
    store = DatacoreStore.from_jsonl(write_jsonl(tmp_path / "d.jsonl", [record("big", text=text)]))
    server = create_uga_server(store=store, token=TOKEN, audit=UgaAuditLog(None))

    payload = _call(server, "fetch", {"id": "big"}).structured_content

    assert len(payload["text"]) == 100_000
    assert payload["text_length"] == 100_001


def test_status_route_requires_token(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    audit = UgaAuditLog(audit_path)
    server = create_uga_server(
        name="ContextBridge", store=_store(tmp_path), token=TOKEN, audit=audit
    )

    with TestClient(server.http_app()) as client:
        anonymous = client.get("/")
        wrong = client.get("/", headers={"Authorization": "Bearer " + "w" * 40})
        ok = client.get("/", headers={"Authorization": f"Bearer {TOKEN}"})

    assert (anonymous.status_code, wrong.status_code, ok.status_code) == (401, 401, 200)
    assert anonymous.headers["www-authenticate"].startswith("Bearer")
    assert "tools" not in anonymous.json() and "service" not in anonymous.json()
    assert ok.json() == {"service": "ContextBridge", "mcp_path": "/mcp", "tools": ["fetch", "search"]}
    auth = [e["detail"] for e in read_audit(audit_path) if e["tool"] == "auth"]
    assert auth == ["missing_token", "invalid_token"]

def test_datacore_path_is_required(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="No datacore export configured"):
        _datacore_path({}, config_path=tmp_path / "c.yaml")


def test_datacore_path_resolves_relative_to_config(tmp_path: Path) -> None:
    (tmp_path / "configs").mkdir()
    data = write_jsonl(tmp_path / "configs" / "d.jsonl", [record()])

    resolved = _datacore_path(
        {"datacore_jsonl": "d.jsonl"}, config_path=tmp_path / "configs" / "c.yaml"
    )

    assert resolved == data


def test_datacore_path_must_exist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UGA_DATACORE_JSONL", str(tmp_path / "missing.jsonl"))
    with pytest.raises(ValueError, match="not found"):
        _datacore_path({}, config_path=tmp_path / "c.yaml")


def test_config_relative_paths(tmp_path: Path) -> None:
    config = tmp_path / "configs" / "c.yaml"

    assert _config_relative("audit.jsonl", config) == tmp_path / "configs" / "audit.jsonl"
    absolute = Path(tmp_path.anchor) / "var" / "log" / "a.jsonl"  # "/var/..." has no drive, so is relative, on Windows
    assert _config_relative(str(absolute), config) == absolute
