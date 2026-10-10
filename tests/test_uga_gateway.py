from __future__ import annotations

import sys
from pathlib import Path

import anyio
import pytest
from conftest import TOKEN
from fastmcp import Client
from fastmcp.exceptions import ToolError

import uga.gateway as gateway
from uga.adapter import DatacoreStore
from uga.gateway import advertised_tool_names, create_uga_server
from uga.policy import UGA_ALLOWED_TOOLS

FIXTURE = Path(__file__).parent / "fixtures" / "datacore" / "datacore.fetch.v1.jsonl"


@pytest.fixture
def knowledge_server():
    return create_uga_server(store=DatacoreStore.from_jsonl(FIXTURE), token=TOKEN)


def run(server, fn):
    async def inner():
        async with Client(server) as client:
            return await fn(client)

    return anyio.run(inner)


def test_knowledge_route_advertises_only_search_and_fetch(knowledge_server):
    assert advertised_tool_names(knowledge_server) == set(UGA_ALLOWED_TOOLS)


def test_search_and_fetch(knowledge_server):
    async def calls(client):
        found = await client.call_tool("search", {"query": "allowlists"})
        record = await client.call_tool("fetch", {"id": "rec-001"})
        with pytest.raises(ToolError, match="not found"):
            await client.call_tool("fetch", {"id": "missing"})
        with pytest.raises(ToolError):
            await client.call_tool("list_directory", {"path": "/"})
        return found.structured_content, record.structured_content

    found, record = run(knowledge_server, calls)
    assert [hit["id"] for hit in found["results"]] == ["rec-002"]
    assert record["title"] == "ContextBridge architecture"
    assert "search and fetch" in record["text"]


def test_missing_token_fails_startup(tmp_path, monkeypatch):
    config = tmp_path / "contextbridge.yaml"
    config.write_text("serve:\n  host: 127.0.0.1\n  port: 18790\n", encoding="utf-8")
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(sys, "argv", ["uga.gateway", "--config", str(config)])
    with pytest.raises(SystemExit, match="MCP_AUTH_TOKEN"):
        gateway.main()
