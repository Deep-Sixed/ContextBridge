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
from dataclasses import dataclass
from pathlib import Path

import anyio
import httpx
import pytest
from fastmcp import Client

from conftest import TOKEN, read_audit, record, write_jsonl

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


@dataclass
class Gateway:
    url: str
    audit_log: Path
    cwd: Path


@pytest.fixture(scope="module")
def gateway(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Gateway]:
    tmp = tmp_path_factory.mktemp("entrypoint")
    # Started from another directory: relative config paths must not follow the CWD.
    cwd = tmp_path_factory.mktemp("cwd")
    write_jsonl(tmp / "d.jsonl", [record("r1"), record("r2")])
    port = _free_port()
    config = tmp / "contextbridge.yaml"
    config.write_text(
        "name: ContextBridge\n"
        "datacore_jsonl: d.jsonl\n"
        f"serve:\n  transport: http\n  host: 127.0.0.1\n  port: {port}\n"
        "  audit_log: audit.jsonl\n",
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
            cwd=cwd,
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
            assert "serving search/fetch over 2 records" in log.read_text()
            yield Gateway(url=base, audit_log=tmp / "audit.jsonl", cwd=cwd)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


@pytest.fixture(scope="module")
def gateway_url(gateway: Gateway) -> str:
    return gateway.url


def test_entrypoint_rejects_requests_without_token(gateway: Gateway) -> None:
    response = httpx.post(
        f"{gateway.url}/mcp",
        json=INITIALIZE,
        # A local client must not be able to choose the peer address that is audited.
        headers={
            "Accept": "application/json, text/event-stream",
            "X-Forwarded-For": "203.0.113.9",
        },
        timeout=5,
        trust_env=False,
    )

    assert response.status_code == 401
    rejected = [e for e in read_audit(gateway.audit_log) if e["tool"] == "auth"]
    assert rejected[-1]["detail"] == "missing_token"
    assert rejected[-1]["peer"] == "127.0.0.1"


def test_entrypoint_audit_log_is_relative_to_config(gateway: Gateway) -> None:
    assert gateway.audit_log.is_file()
    assert not (gateway.cwd / "audit.jsonl").exists()


def test_entrypoint_serves_tools_with_token(gateway_url: str) -> None:
    async def go() -> tuple[set[str], list[str]]:
        async with Client(f"{gateway_url}/mcp", auth=TOKEN) as client:
            tools = await client.list_tools()
            result = await client.call_tool("search", {"query": "r2"})
        return {tool.name for tool in tools}, [hit["id"] for hit in result.structured_content["results"]]

    names, hits = anyio.run(go)

    assert names == {"search", "fetch"}
    assert hits == ["r2"]
