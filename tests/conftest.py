from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from helpers import PY

from contextbridge.computer.policy import ComputerPolicy, load_policy

# ------------------------------------------------------------ knowledge route

TOKEN = "t" * 40

_GATEWAY_ENV = (
    "MCP_AUTH_TOKEN",
    "UGA_DATACORE_JSONL",
    "UGA_AUDIT_LOG",
    "UGA_AUDIT_LOG_QUERY_TEXT",
    "UGA_AUDIT_HASH_KEY",
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


# ------------------------------------------------------------- computer route


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A readable root containing a writable subdirectory and some denied files."""
    root = tmp_path / "root"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "notes.md").write_bytes(b"alpha\nbeta\ngamma\n")  # LF on every OS; reads return it verbatim
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("def main():\n    return 'hello'\n", encoding="utf-8")
    (root / ".ssh").mkdir()
    (root / ".ssh" / "id_ed25519").write_text("PRIVATE", encoding="utf-8")
    (root / ".env").write_text("SECRET=1\n", encoding="utf-8")
    (root / "work").mkdir()
    (tmp_path / "outside.txt").write_text("outside\n", encoding="utf-8")
    return root


@pytest.fixture
def make_policy(workspace: Path):
    def _make(**overrides: Any) -> ComputerPolicy:
        cfg: dict[str, Any] = {
            "filesystem": {"roots": [str(workspace)], "writable_roots": [str(workspace / "work")]},
            "commands": {"mode": "allowlist", "allow": ["echo", "ls", "sleep", "cat", "env", PY]},
            "processes": {"list": True, "allow_kill": False},
        }
        for section, values in overrides.items():
            cfg.setdefault(section, {}).update(values)
        return load_policy(cfg)

    return _make


@pytest.fixture
def policy(make_policy) -> ComputerPolicy:
    return make_policy()
