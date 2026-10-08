"""End-to-end check of the real HTTP entrypoint: no bearer token, no MCP."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastmcp import Client

REPO = Path(__file__).resolve().parents[1]
FIXTURE_JSONL = Path(__file__).parent / "fixtures" / "contract.jsonl"
TOKEN = "contract-test-token"

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "auth-test", "version": "0"},
    },
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def gateway_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    tmp = tmp_path_factory.mktemp("http")
    port = _free_port()
    config = tmp / "contextbridge.yaml"
    config.write_text(
        f"name: ContextBridge\nserve:\n  transport: http\n  host: 127.0.0.1\n  port: {port}\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "MCP_AUTH_TOKEN": TOKEN,
        "UGA_DATACORE_JSONL": str(FIXTURE_JSONL),
        "PYTHONPATH": str(REPO / "src"),
    }
    env.pop("UGA_AUDIT_LOG", None)
    log = tmp / "gateway.log"
    base = f"http://127.0.0.1:{port}"
    with log.open("w") as log_fh:
        proc = subprocess.Popen(
            [sys.executable, "-m", "uga.gateway", "--config", str(config)],
            env=env,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 30
            while True:
                if proc.poll() is not None:
                    pytest.fail(f"gateway exited early:\n{log.read_text()}")
                try:
                    if httpx.get(f"{base}/", timeout=1, trust_env=False).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() > deadline:
                    pytest.fail(f"gateway did not start:\n{log.read_text()}")
                time.sleep(0.2)
            yield base
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


@pytest.mark.parametrize("authorization", [None, "Bearer wrong-token"])
def test_mcp_endpoint_rejects_missing_or_wrong_token(
    gateway_url: str, authorization: str | None
) -> None:
    headers = dict(MCP_HEADERS)
    if authorization:
        headers["Authorization"] = authorization
    response = httpx.post(
        f"{gateway_url}/mcp", json=INITIALIZE, headers=headers, timeout=5, trust_env=False
    )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_mcp_endpoint_serves_tools_with_token(gateway_url: str) -> None:
    async with Client(f"{gateway_url}/mcp", auth=TOKEN) as client:
        tools = await client.list_tools()
        result = await client.call_tool("search", {"query": "alpha"})
    assert {tool.name for tool in tools} == {"search", "fetch"}
    assert [hit["id"] for hit in result.structured_content["results"]] == ["r1"]
