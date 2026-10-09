"""Minimal audit logging for UGA tool calls."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import time
from pathlib import Path
from typing import Any

# Longest client-supplied string (tool name, record id, client name, ...) written
# to the log; longer values are cut so a client cannot bloat or flood the log.
MAX_FIELD_LEN = 200


def clip(value: str, *, max_len: int = MAX_FIELD_LEN) -> str:
    if len(value) <= max_len:
        return value
    return f"{value[:max_len]}...[{len(value) - max_len} more chars]"


def _query_preview(query: str, *, max_len: int = 80) -> str:
    q = (query or "").strip()
    if len(q) <= max_len:
        return q
    return q[: max_len - 3] + "..."


class UgaAuditLog:
    """Append-only JSONL audit sink. Failures to write never block tool execution.

    Query text is not logged unless ``log_query_text`` is set; by default only a
    keyed hash and the length are recorded. Without ``hash_key`` a random key is
    used, so the same query hashes the same only within one process.
    """

    def __init__(
        self,
        path: str | Path | None,
        *,
        route: str = "uga",
        log_query_text: bool = False,
        hash_key: bytes | None = None,
    ) -> None:
        self.route = route
        self._log_query_text = log_query_text
        self._hash_key = hash_key or secrets.token_bytes(32)
        self._fh = None
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(p, flags, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError(f"audit log is not a regular file: {p}")
                # The mode passed to os.open only applies when the file is created.
                os.fchmod(fd, 0o600)
            except BaseException:
                os.close(fd)
                raise
            self._fh = os.fdopen(fd, "a", buffering=1, encoding="utf-8")

    def _query_hash(self, query: str) -> str:
        digest = hmac.new(self._hash_key, (query or "").encode("utf-8"), hashlib.sha256)
        return digest.hexdigest()[:16]

    def record(
        self,
        *,
        tool: str,
        query: str | None = None,
        record_id: str | None = None,
        result_count: int | None = None,
        success: bool,
        detail: str | None = None,
        client_label: str | None = None,
        peer: str | None = None,
        request_id: str | None = None,
        elapsed_ms: int | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "route": self.route,
            "tool": clip(tool),
            "success": success,
        }
        if request_id:
            entry["request_id"] = clip(request_id)
        if client_label:
            entry["client"] = clip(client_label)
        if peer:
            entry["peer"] = clip(peer)
        if elapsed_ms is not None:
            entry["elapsed_ms"] = elapsed_ms
        if query is not None:
            entry["query_hash"] = self._query_hash(query)
            entry["query_len"] = len(query)
            if self._log_query_text:
                entry["query_preview"] = _query_preview(query)
        if record_id is not None:
            entry["record_id"] = clip(record_id)
        if result_count is not None:
            entry["result_count"] = result_count
        if detail:
            entry["detail"] = clip(detail)
        line = json.dumps(entry, separators=(",", ":"))
        if self._fh:
            try:
                self._fh.write(line + "\n")
            except (OSError, ValueError):
                pass
        try:
            print(f"[uga audit] {line}", file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass
