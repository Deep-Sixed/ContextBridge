"""End-to-end check of the real ``python -m uga.gateway`` entrypoint over HTTP.

The in-process tests build the server directly; this one runs ``main()`` so that
config parsing, startup validation, and ``server.run`` are covered too.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import anyio
import httpx
import pytest
from fastmcp import Client

from conftest import TOKEN, record, write_jsonl

REPO = Path(__file__).resolve().parents[1]

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "entrypoint-test", "version": "0"},
    },
}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def gateway_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    tmp = tmp_path_factory.mktemp("entrypoint")
    write_jsonl(tmp / "d.jsonl", [record("r1"), record("r2")])
    port = _free_port()
    config = tmp / "contextbridge.yaml"
    config.write_text(
        "name: ContextBridge\n"
        "datacore_jsonl: d.jsonl\n"
        f"serve:\n  transport: http\n  host: 127.0.0.1\n  port: {port}\n",
        encoding="utf-8",
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("UGA_") and key != "MCP_AUTH_TOKEN"
    }
    env["MCP_AUTH_TOKEN"] = TOKEN
    env["PYTHONPATH"] = str(REPO / "src")
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
                    pytest.fail(f"gateway did not start:\n{log.read_text()}")
                time.sleep(0.2)
            assert "serving search/fetch over 2 records" in log.read_text()
            yield base
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def test_entrypoint_rejects_requests_without_token(gateway_url: str) -> None:
    response = httpx.post(
        f"{gateway_url}/mcp",
        json=INITIALIZE,
        headers={"Accept": "application/json, text/event-stream"},
        timeout=5,
        trust_env=False,
    )

    assert response.status_code == 401


def test_entrypoint_serves_tools_with_token(gateway_url: str) -> None:
    async def go() -> tuple[set[str], list[str]]:
        async with Client(f"{gateway_url}/mcp", auth=TOKEN) as client:
            tools = await client.list_tools()
            result = await client.call_tool("search", {"query": "r2"})
        return {tool.name for tool in tools}, [hit["id"] for hit in result.structured_content["results"]]

    names, hits = anyio.run(go)

    assert names == {"search", "fetch"}
    assert hits == ["r2"]
