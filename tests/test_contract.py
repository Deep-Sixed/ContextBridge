"""MCP contract for ContextBridge, modelled on computer-use-linux's mcp_safety_check.py.

These tests pin what clients see over MCP: the tool surface, its safety
annotations, the input schemas, the reported server version, and policy denial.
A dependency bump or refactor that changes any of them fails CI instead of
reaching clients.
"""

from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path
from typing import Any

import anyio
import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

import uga
from conftest import TOKEN, read_audit, record, write_jsonl
from uga.adapter import DatacoreStore
from uga.audit import UgaAuditLog
from uga.gateway import create_uga_server
from uga.policy import UGA_ALLOWED_TOOLS, UGA_FORBIDDEN_TOOL_EXAMPLES

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


def _server(tmp_path: Path, audit_path: Path | None = None) -> FastMCP:
    store = DatacoreStore.from_jsonl(write_jsonl(tmp_path / "d.jsonl", [record("r1")]))
    return create_uga_server(
        name="ContextBridge", store=store, token=TOKEN, audit=UgaAuditLog(audit_path)
    )


def _session(server: FastMCP) -> dict[str, Any]:
    """Initialize and list tools, as a client does on connect."""

    async def go() -> dict[str, Any]:
        async with Client(server) as client:
            return {"init": client.initialize_result, "tools": await client.list_tools()}

    return anyio.run(go)


def _assert_no_injection_text(label: str, text: str) -> None:
    for pattern in INJECTION_PATTERNS:
        assert not pattern.search(text), f"{label} matches {pattern.pattern!r}"


def test_tool_surface_matches_policy(tmp_path: Path) -> None:
    tools = _session(_server(tmp_path))["tools"]

    assert {tool.name for tool in tools} == set(UGA_ALLOWED_TOOLS) == set(EXPECTED_INPUTS)


def test_tools_declare_complete_read_only_annotations(tmp_path: Path) -> None:
    for tool in _session(_server(tmp_path))["tools"]:
        assert tool.annotations is not None, f"{tool.name} has no annotations"
        declared = tool.annotations.model_dump(exclude_none=True)
        for key, expected in EXPECTED_ANNOTATIONS.items():
            assert declared.get(key) is expected, f"{tool.name} {key}={declared.get(key)!r}"


def test_tool_names_schemas_and_descriptions(tmp_path: Path) -> None:
    session = _session(_server(tmp_path))

    _assert_no_injection_text("server instructions", session["init"].instructions or "")
    for tool in session["tools"]:
        assert re.fullmatch(r"[a-z][a-z0-9_]*", tool.name), tool.name
        properties = set((tool.inputSchema or {}).get("properties") or {})
        assert properties == EXPECTED_INPUTS[tool.name], f"{tool.name} inputs: {properties}"
        assert tool.description, f"{tool.name} has no description"
        _assert_no_injection_text(f"{tool.name} description", tool.description)


def test_server_instructions_explain_tools_and_untrusted_text(tmp_path: Path) -> None:
    instructions = _session(_server(tmp_path))["init"].instructions or ""

    for required in [
        "Call search",
        "Call fetch with an id",
        "not instructions",
        "truncated=true",
    ]:
        assert required in instructions, f"server instructions missing {required!r}"

def test_server_reports_package_version(tmp_path: Path) -> None:
    server_info = _session(_server(tmp_path))["init"].serverInfo

    assert server_info.name == "ContextBridge"
    assert server_info.version == uga.__version__


def test_installed_metadata_matches_package_version() -> None:
    try:
        installed = importlib.metadata.version("contextbridge")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("contextbridge is not installed; run pip install -e .")
    assert installed == uga.__version__


def test_forbidden_tools_are_denied_and_audited(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    server = _server(tmp_path, audit_path)

    async def go() -> Any:
        async with Client(server) as client:
            for name in sorted(UGA_FORBIDDEN_TOOL_EXAMPLES):
                with pytest.raises(ToolError, match="not permitted"):
                    await client.call_tool(name, {"command": "id", "query": "secret"})
            # A denied call must leave the session usable.
            return await client.call_tool("fetch", {"id": "r1"})

    assert anyio.run(go).structured_content["id"] == "r1"
    denied = [entry for entry in read_audit(audit_path) if entry.get("detail") == "policy_denied"]
    assert {entry["tool"] for entry in denied} == set(UGA_FORBIDDEN_TOOL_EXAMPLES)
    for entry in denied:
        assert entry["success"] is False
        # Arguments to a denied tool are never written to the audit log.
        assert "query_hash" not in entry and "record_id" not in entry
