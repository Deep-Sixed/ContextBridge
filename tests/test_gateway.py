from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import anyio
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from starlette.testclient import TestClient

from conftest import TOKEN, read_audit, record, write_jsonl
from uga.adapter import DatacoreStore
from uga.audit import UgaAuditLog
from uga.gateway import _datacore_path, create_uga_server, http_middleware


def _store(tmp_path: Path) -> DatacoreStore:
    return DatacoreStore.from_jsonl(write_jsonl(tmp_path / "d.jsonl", [record("r1"), record("r2")]))


def _call(server: Any, tool: str, arguments: dict[str, Any]) -> Any:
    async def go() -> Any:
        async with Client(server) as client:
            return await client.call_tool(tool, arguments)

    return anyio.run(go)


class _SlowStore(DatacoreStore):
    def search_records(self, query: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        time.sleep(1.5)
        return super().search_records(query, limit=limit)


class _BrokenStore(DatacoreStore):
    def search_records(self, query: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        raise FileNotFoundError(2, "No such file or directory", "/secret/path/missing.jsonl")


def test_tool_timeout_fires(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UGA_MCP_TOOL_TIMEOUT_SECONDS", "0.3")
    audit_path = tmp_path / "audit.jsonl"
    server = create_uga_server(
        store=_SlowStore(_store(tmp_path)._records), token=TOKEN, audit=UgaAuditLog(audit_path)
    )

    started = time.monotonic()
    with pytest.raises(ToolError, match="timed out"):
        _call(server, "search", {"query": "r1"})

    assert time.monotonic() - started < 1.2
    assert {"tool": "search", "success": False, "detail": "timeout"}.items() <= read_audit(
        audit_path
    )[-1].items()


def test_error_details_are_masked(tmp_path: Path) -> None:
    server = create_uga_server(
        store=_BrokenStore({}), token=TOKEN, audit=UgaAuditLog(tmp_path / "audit.jsonl")
    )

    with pytest.raises(ToolError) as excinfo:
        _call(server, "search", {"query": "x"})

    assert "/secret" not in str(excinfo.value)


def test_not_found_message_still_reaches_client(tmp_path: Path) -> None:
    server = create_uga_server(store=_store(tmp_path), token=TOKEN, audit=UgaAuditLog(None))

    with pytest.raises(ToolError, match="Record not found: nope"):
        _call(server, "fetch", {"id": "nope"})


def test_tool_and_middleware_audit_lines_share_request_id(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = create_uga_server(store=_store(tmp_path), token=TOKEN, audit=UgaAuditLog(audit_path))

    _call(server, "search", {"query": "r1"})
    _call(server, "fetch", {"id": "r1"})

    search_lines = [e for e in read_audit(audit_path) if e["tool"] == "search"]
    fetch_lines = [e for e in read_audit(audit_path) if e["tool"] == "fetch"]
    assert len(search_lines) == len(fetch_lines) == 2
    assert search_lines[0]["request_id"] == search_lines[1]["request_id"]
    assert fetch_lines[0]["request_id"] == fetch_lines[1]["request_id"]
    assert search_lines[0]["request_id"] != fetch_lines[0]["request_id"]


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
    monkeypatch.setenv("MCP_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("UGA_DATACORE_JSONL", str(write_jsonl(tmp_path / "d.jsonl", [record()])))

    server = create_uga_server()

    assert server.auth is not None
    assert _call(server, "fetch", {"id": "r1"}).structured_content["id"] == "r1"


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


def test_http_auth_and_failures_are_audited(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    audit = UgaAuditLog(audit_path)
    server = create_uga_server(store=_store(tmp_path), token=TOKEN, audit=audit)
    headers = {"Accept": "application/json, text/event-stream"}

    with TestClient(server.http_app(middleware=http_middleware(audit))) as client:
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
