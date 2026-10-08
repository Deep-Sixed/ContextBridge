from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from conftest import read_audit

from uga.audit import UgaAuditLog


def test_query_text_is_not_logged_by_default(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    UgaAuditLog(path).record(tool="search", query="salary of jane doe", success=True)

    (entry,) = read_audit(path)

    assert "query_preview" not in entry
    assert "jane" not in path.read_text()
    assert entry["query_len"] == len("salary of jane doe")
    assert len(entry["query_hash"]) == 16


def test_query_text_is_logged_when_opted_in(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    UgaAuditLog(path, log_query_text=True).record(tool="search", query="hello", success=True)

    assert read_audit(path)[0]["query_preview"] == "hello"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits; Windows uses ACLs")
def test_audit_file_is_private(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    UgaAuditLog(path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


class _BrokenStream:
    def write(self, _s: str) -> int:
        raise BrokenPipeError

    def flush(self) -> None:
        raise BrokenPipeError


def test_broken_stderr_does_not_raise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stderr", _BrokenStream())
    path = tmp_path / "audit.jsonl"

    UgaAuditLog(path).record(tool="search", query="q", success=True)

    assert read_audit(path)[0]["tool"] == "search"
