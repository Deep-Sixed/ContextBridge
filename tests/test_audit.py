from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest
from conftest import read_audit

from contextbridge.computer.audit import ComputerAuditLog
from contextbridge.filesystem.audit import GatewayAuditLog


def test_query_text_is_not_logged_by_default(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    GatewayAuditLog(path).record(tool="search", query="salary of jane doe", success=True)

    (entry,) = read_audit(path)

    assert "query_preview" not in entry
    assert "jane" not in path.read_text()
    assert entry["query_len"] == len("salary of jane doe")
    assert len(entry["query_hash"]) == 16


def test_query_text_is_logged_when_opted_in(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    GatewayAuditLog(path, log_query_text=True).record(tool="search", query="hello", success=True)

    assert read_audit(path)[0]["query_preview"] == "hello"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits; Windows uses ACLs")
def test_audit_file_is_private(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    GatewayAuditLog(path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits; Windows uses ACLs")
def test_existing_audit_file_is_made_private(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    path.chmod(0o644)

    GatewayAuditLog(path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_audit_log_refuses_symlink(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.jsonl"
    target.write_text("")
    os.symlink(target, tmp_path / "audit.jsonl")

    with pytest.raises(OSError):
        GatewayAuditLog(tmp_path / "audit.jsonl")


def test_query_hash_is_keyed(tmp_path: Path) -> None:
    def query_hash(audit: GatewayAuditLog, name: str) -> str:
        audit_path = tmp_path / name
        audit._fh = audit_path.open("a")
        audit.record(tool="search", query="salary of jane doe", success=True)
        audit._fh.close()
        return read_audit(audit_path)[0]["query_hash"]

    plain = hashlib.sha256(b"salary of jane doe").hexdigest()[:16]
    keyed = query_hash(GatewayAuditLog(None, hash_key=b"k" * 32), "a.jsonl")

    assert keyed == query_hash(GatewayAuditLog(None, hash_key=b"k" * 32), "b.jsonl")
    assert keyed != plain
    assert query_hash(GatewayAuditLog(None), "c.jsonl") != query_hash(GatewayAuditLog(None), "d.jsonl")


def test_client_supplied_fields_are_clipped(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    GatewayAuditLog(path).record(tool="t" * 10_000, client_label="c" * 10_000, success=False)

    (entry,) = read_audit(path)

    for key in ("tool", "client"):
        assert len(entry[key]) < 300, key


class _BrokenStream:
    def write(self, _s: str) -> int:
        raise BrokenPipeError

    def flush(self) -> None:
        raise BrokenPipeError


def test_broken_stderr_does_not_raise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stderr", _BrokenStream())
    path = tmp_path / "audit.jsonl"

    GatewayAuditLog(path).record(tool="search", query="q", success=True)

    assert read_audit(path)[0]["tool"] == "search"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits; Windows uses ACLs")
def test_computer_and_agent_audit_logs_are_private(tmp_path: Path) -> None:
    fresh = tmp_path / "new" / "computer.audit.jsonl"
    existing = tmp_path / "agent.audit.jsonl"
    existing.write_text("")
    existing.chmod(0o644)

    for path, route in ((fresh, "computer"), (existing, "agent")):
        log = ComputerAuditLog(path, route=route, echo=False)
        log.record("service_started")
        log.close()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert read_audit(fresh)[0]["event"] == "service_started"


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="needs POSIX symlinks")
def test_computer_audit_log_refuses_symlink(tmp_path: Path) -> None:
    from contextbridge.computer.audit import AuditError

    target = tmp_path / "elsewhere.jsonl"
    target.write_text("")
    os.symlink(target, tmp_path / "audit.jsonl")
    with pytest.raises(AuditError):
        ComputerAuditLog(tmp_path / "audit.jsonl")
