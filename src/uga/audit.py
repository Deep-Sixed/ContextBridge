"""Minimal audit logging for UGA tool calls."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any


def _query_preview(query: str, *, max_len: int = 80) -> str:
    q = (query or "").strip()
    if len(q) <= max_len:
        return q
    return q[: max_len - 3] + "..."


def _query_hash(query: str) -> str:
    return hashlib.sha256((query or "").encode("utf-8")).hexdigest()[:16]


class UgaAuditLog:
    """Append-only JSONL audit sink. Failures to write never block tool execution.

    Query text is not logged unless ``log_query_text`` is set; by default only a
    hash and the length are recorded.
    """

    def __init__(
        self, path: str | Path | None, *, route: str = "uga", log_query_text: bool = False
    ) -> None:
        self.route = route
        self._log_query_text = log_query_text
        self._fh = None
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            self._fh = os.fdopen(fd, "a", buffering=1, encoding="utf-8")

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
            "tool": tool,
            "success": success,
        }
        if request_id:
            entry["request_id"] = request_id
        if client_label:
            entry["client"] = client_label
        if peer:
            entry["peer"] = peer
        if elapsed_ms is not None:
            entry["elapsed_ms"] = elapsed_ms
        if query is not None:
            entry["query_hash"] = _query_hash(query)
            entry["query_len"] = len(query)
            if self._log_query_text:
                entry["query_preview"] = _query_preview(query)
        if record_id is not None:
            entry["record_id"] = record_id
        if result_count is not None:
            entry["result_count"] = result_count
        if detail:
            entry["detail"] = detail
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
