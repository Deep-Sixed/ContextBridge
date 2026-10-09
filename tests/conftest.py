from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

TOKEN = "t" * 40

_GATEWAY_ENV = (
    "MCP_AUTH_TOKEN",
    "UGA_DATACORE_JSONL",
    "UGA_AUDIT_LOG",
    "UGA_AUDIT_LOG_QUERY_TEXT",
    "UGA_MCP_TOOL_TIMEOUT_SECONDS",
    "UGA_MCP_METADATA_TIMEOUT_SECONDS",
    "UGA_MCP_SEARCH_LIMIT",
    "UGA_MCP_FETCH_MAX_CHARS",
    "CONTEXTBRIDGE_FS_AUTH_TOKEN",
    "CONTEXTBRIDGE_FS_AUDIT_LOG",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _GATEWAY_ENV:
        monkeypatch.delenv(name, raising=False)


def record(record_id: Any = "r1", **fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": record_id,
        "title": f"Title {record_id}",
        "text": f"Body {record_id}",
        "url": f"https://example.test/{record_id}",
    }
    base.update(fields)
    return base


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return path


def read_audit(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
