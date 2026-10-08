"""Shared fixtures for the ContextBridge MCP contract tests."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastmcp import FastMCP

from uga import gateway

FIXTURE_JSONL = Path(__file__).parent / "fixtures" / "contract.jsonl"


def _reset_gateway_singletons() -> None:
    if gateway._audit is not None:
        gateway._audit.close()
    gateway._audit = None
    gateway._store = None


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def audit_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the gateway at the fixture JSONL and a fresh audit file."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("UGA_DATACORE_JSONL", str(FIXTURE_JSONL))
    monkeypatch.setenv("UGA_AUDIT_LOG", str(path))
    monkeypatch.delenv("UGA_AUDIT_QUERY_PREVIEW", raising=False)
    _reset_gateway_singletons()
    yield path
    _reset_gateway_singletons()


@pytest.fixture
def audit_lines(audit_path: Path) -> Callable[[], list[dict[str, Any]]]:
    def read() -> list[dict[str, Any]]:
        if not audit_path.exists():
            return []
        return [json.loads(line) for line in audit_path.read_text().splitlines() if line]

    return read


@pytest.fixture
def server(audit_path: Path) -> FastMCP:
    return gateway.create_uga_server(name="ContextBridge")
