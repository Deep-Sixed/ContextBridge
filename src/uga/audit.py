"""Minimal audit logging for UGA tool calls."""

from __future__ import annotations

import hashlib
import json
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

    Queries are recorded as a SHA-256 prefix only. A plain-text preview is written
    only when ``include_query_preview`` is set, because query text can carry
    sensitive content into stderr and the audit file.
    """

    def __init__(
        self,
        path: str | Path | None,
        *,
        route: str = "uga",
        include_query_preview: bool = False,
    ) -> None:
        self.route = route
        self.include_query_preview = include_query_preview
        self._fh = None
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._fh = p.open("a", buffering=1, encoding="utf-8")

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

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
        if elapsed_ms is not None:
            entry["elapsed_ms"] = elapsed_ms
        if query is not None:
            if self.include_query_preview:
                entry["query_preview"] = _query_preview(query)
            entry["query_hash"] = _query_hash(query)
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
            except OSError:
                pass
        print(f"[uga audit] {line}", file=sys.stderr, flush=True)
