"""MCP contract for ContextBridge, modelled on computer-use-linux's mcp_safety_check.py.

These tests pin the tool surface, its safety annotations, the reported server
version, and the audit trail, so a dependency bump or refactor that changes any
of them fails CI instead of reaching clients.
"""

from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

import uga
from uga import gateway
from uga.policy import UGA_ALLOWED_TOOLS, UGA_FORBIDDEN_TOOL_EXAMPLES

CLIENT_INFO = {"name": "contract-test", "version": "1.0"}

EXPECTED_INPUTS = {"search": {"query"}, "fetch": {"id"}}

EXPECTED_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"you\s+are\s+now\s+a",
        r"your\s+new\s+(task|role|instructions?)\s+(is|are)",
        r"system\s*:",
        r"<\s*(system|human|assistant|user)\s*>",
        r"do\s+not\s+(tell|inform|mention|reveal)",
        r"(curl|wget|fetch)\s+https?://",
        r"base64\.(b64decode|decodebytes)",
        r"\b(exec|eval)\s*\(",
    ]
]


def _client(server: FastMCP) -> Client:
    return Client(server, client_info=CLIENT_INFO)


def _assert_no_injection_text(label: str, text: str) -> None:
    for pattern in INJECTION_PATTERNS:
        assert not pattern.search(text), f"{label} matches {pattern.pattern!r}"


@pytest.mark.anyio
async def test_tool_surface_matches_policy(server: FastMCP) -> None:
    async with _client(server) as client:
        tools = await client.list_tools()
    assert {tool.name for tool in tools} == set(UGA_ALLOWED_TOOLS) == set(EXPECTED_INPUTS)


@pytest.mark.anyio
async def test_tools_declare_complete_read_only_annotations(server: FastMCP) -> None:
    async with _client(server) as client:
        tools = await client.list_tools()
    for tool in tools:
        assert tool.annotations is not None, f"{tool.name} has no annotations"
        declared = tool.annotations.model_dump(exclude_none=True)
        for key, expected in EXPECTED_ANNOTATIONS.items():
            assert declared.get(key) is expected, f"{tool.name} {key}={declared.get(key)!r}"


@pytest.mark.anyio
async def test_tool_names_schemas_and_descriptions(server: FastMCP) -> None:
    async with _client(server) as client:
        tools = await client.list_tools()
        instructions = client.initialize_result.instructions or ""
    _assert_no_injection_text("server instructions", instructions)
    for tool in tools:
        assert re.fullmatch(r"[a-z][a-z0-9_]*", tool.name), tool.name
        properties = set((tool.inputSchema or {}).get("properties") or {})
        assert properties == EXPECTED_INPUTS[tool.name], f"{tool.name} inputs: {properties}"
        assert tool.description, f"{tool.name} has no description"
        _assert_no_injection_text(f"{tool.name} description", tool.description)


@pytest.mark.anyio
async def test_server_reports_package_version(server: FastMCP) -> None:
    async with _client(server) as client:
        server_info = client.initialize_result.serverInfo
    assert server_info.name == "ContextBridge"
    assert server_info.version == uga.__version__


def test_installed_metadata_matches_package_version() -> None:
    try:
        installed = importlib.metadata.version("contextbridge")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("contextbridge is not installed; run pip install -e .")
    assert installed == uga.__version__


@pytest.mark.anyio
async def test_forbidden_tools_are_denied_and_audited(server: FastMCP, audit_lines) -> None:
    async with _client(server) as client:
        for name in sorted(UGA_FORBIDDEN_TOOL_EXAMPLES):
            with pytest.raises(ToolError, match="not permitted"):
                await client.call_tool(name, {"command": "id", "query": "secret"})
        # A denied call must leave the session usable.
        result = await client.call_tool("search", {"query": "alpha"})
    assert [hit["id"] for hit in result.structured_content["results"]] == ["r1"]

    denied = [entry for entry in audit_lines() if entry.get("detail") == "policy_denied"]
    assert {entry["tool"] for entry in denied} == set(UGA_FORBIDDEN_TOOL_EXAMPLES)
    for entry in denied:
        assert entry["success"] is False
        # Arguments to a denied tool are never written to the audit log.
        assert "query_hash" not in entry and "record_id" not in entry


@pytest.mark.anyio
async def test_each_tool_call_is_audited_once_with_request_and_client(
    server: FastMCP, audit_lines
) -> None:
    async with _client(server) as client:
        await client.call_tool("search", {"query": "alpha"})
        await client.call_tool("fetch", {"id": "r1"})

    entries = audit_lines()
    initialize = next(entry for entry in entries if entry["tool"] == "initialize")
    assert initialize["client"] == "contract-test/1.0"

    calls = [entry for entry in entries if entry["tool"] in EXPECTED_INPUTS]
    assert [entry["tool"] for entry in calls] == ["search", "fetch"]
    search, fetch = calls
    assert search["success"] is True and search["result_count"] == 1
    assert len(search["query_hash"]) == 16
    assert "query_preview" not in search
    assert fetch["success"] is True and fetch["record_id"] == "r1"
    for entry in calls:
        assert entry["client"] == "contract-test/1.0"
        assert re.fullmatch(r"mcp-\d+", entry["request_id"]), entry["request_id"]
    assert search["request_id"] != fetch["request_id"]


@pytest.mark.anyio
async def test_query_preview_is_opt_in(
    audit_path: Path, audit_lines, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("UGA_AUDIT_QUERY_PREVIEW", "1")
    server = gateway.create_uga_server(name="ContextBridge")
    async with _client(server) as client:
        await client.call_tool("search", {"query": "alpha"})
    (entry,) = [entry for entry in audit_lines() if entry["tool"] == "search"]
    assert entry["query_preview"] == "alpha"


@pytest.mark.anyio
async def test_missing_record_is_audited_as_not_found(server: FastMCP, audit_lines) -> None:
    async with _client(server) as client:
        with pytest.raises(ToolError, match="Record not found: missing"):
            await client.call_tool("fetch", {"id": "missing"})
        await client.call_tool("fetch", {"id": "r1"})

    fetches = [entry for entry in audit_lines() if entry["tool"] == "fetch"]
    assert [(entry["success"], entry.get("detail"), entry["record_id"]) for entry in fetches] == [
        (False, "not_found", "missing"),
        (True, None, "r1"),
    ]


@pytest.mark.anyio
async def test_unexpected_failure_audits_original_exception_type(
    server: FastMCP, audit_lines, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("UGA_DATACORE_JSONL", str(tmp_path / "absent.jsonl"))
    async with _client(server) as client:
        with pytest.raises(ToolError):
            await client.call_tool("search", {"query": "alpha"})
    (entry,) = [entry for entry in audit_lines() if entry["tool"] == "search"]
    assert entry["success"] is False
    assert entry["detail"] == "FileNotFoundError"
