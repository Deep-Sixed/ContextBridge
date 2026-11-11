"""Audit trail for the computer route.

Each tool call produces a sequence of events sharing one ``request_id``:

``requested``  the call arrived (always written first)
``denied``     authentication, authorization, or policy refused it; nothing ran
``failed``     it was refused for another reason before anything ran (bad input, missing file)
``started``    every check passed and the operation is about to touch the machine
``completed``  the operation finished; ``success`` says whether it achieved its goal
               (for commands: exit code 0 and no timeout)

Background sessions add ``exited`` when their process ends.

Writes are fail-closed: if an event cannot be recorded, :class:`AuditError` is
raised, and an operation whose ``requested`` or ``started`` event fails never runs.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO


class AuditError(RuntimeError):
    """Raised when an audit event cannot be written."""


_AUDITED_ARGS = (
    "path",
    "source",
    "destination",
    "command",
    "cwd",
    "pattern",
    "file_pattern",
    "mode",
    "session_id",
    "pid",
    "force",
    "timeout_seconds",
    "device",
    "recursive",
    "trash_id",
    "pages",
    "sheet",
    "cell_range",
    "start_cell",
    "find",
    "delete_pages",
    "rotate_pages",
    "insert_pdf",
    "insert_at",
    "output_path",
)
_DIGESTED_ARGS = ("content", "old_string", "new_string", "input", "old_text", "new_text", "rows")
_OUTCOME_FIELDS = ("pid", "session_id", "exit_code", "timed_out", "stdout_truncated", "stderr_truncated")
MAX_AUDIT_VALUE = 1000


def summarize_args(arguments: dict[str, Any] | None) -> dict[str, Any]:
    """Audit-safe view of tool arguments: paths and commands verbatim, content as size + hash."""
    fields: dict[str, Any] = {}
    args = arguments if isinstance(arguments, dict) else {}
    for key in _AUDITED_ARGS:
        value = args.get(key)
        if value is None:
            continue
        if isinstance(value, str) and len(value) > MAX_AUDIT_VALUE:
            value = value[: MAX_AUDIT_VALUE - 3] + "..."
        fields[key] = value
    for key in _DIGESTED_ARGS:
        value = args.get(key)
        if value is not None:
            text = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
            data = text.encode("utf-8")
            fields[f"{key}_bytes"] = len(data)
            fields[f"{key}_sha256"] = hashlib.sha256(data).hexdigest()[:16]
    return fields


def digest_args(arguments: dict[str, Any]) -> dict[str, Any]:
    """Size and hash of a whole argument object (for tools whose arguments ContextBridge does not know)."""
    data = json.dumps(arguments, default=str, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"args_bytes": len(data), "args_sha256": hashlib.sha256(data).hexdigest()[:16]}


def outcome_fields(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    return {k: result[k] for k in _OUTCOME_FIELDS if k in result}


class ComputerAuditLog:
    """Append-only JSONL audit sink shared by tool calls and session threads."""

    def __init__(self, path: str | Path | None, *, route: str = "computer", echo: bool = True) -> None:
        self.path = Path(path) if path else None
        self.route = route
        self._echo = echo
        self._lock = threading.Lock()
        self._fh: TextIO | None = None
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._fh = self.path.open("a", buffering=1, encoding="utf-8")
            except OSError as exc:
                raise AuditError(f"Cannot open audit log {self.path}: {exc}") from exc

    def record(self, event: str, **fields: Any) -> None:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "route": self.route,
            "event": event,
        }
        entry.update({k: v for k, v in fields.items() if v is not None})
        line = json.dumps(entry, separators=(",", ":"), default=str)
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.write(line + "\n")
                    self._fh.flush()
                except (OSError, ValueError) as exc:
                    raise AuditError(f"Cannot write audit log {self.path}: {exc}") from exc
            if self._echo:
                print(f"[{self.route} audit] {line}", file=sys.stderr, flush=True)

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None


@dataclass
class CallAudit:
    """Audit state for the tool call currently executing."""

    log: ComputerAuditLog
    request_id: str
    tool: str
    client: str | None
    device: str | None = None
    on_started: Callable[[dict[str, Any]], None] | None = None
    started: bool = False

    def emit(self, event: str, **fields: Any) -> None:
        self.log.record(
            event, request_id=self.request_id, tool=self.tool, device=self.device, client=self.client, **fields
        )

    def mark_started(self, **fields: Any) -> None:
        """Record ``started`` once; ``on_started`` (e.g. telling the gateway) must succeed too."""
        if self.started:
            return
        self.emit("started", **fields)
        if self.on_started is not None:
            self.on_started(fields)
        self.started = True


_current_call: ContextVar[CallAudit | None] = ContextVar("contextbridge_current_call", default=None)


def bind_call(call: CallAudit):
    return _current_call.set(call)


def unbind_call(token) -> None:
    _current_call.reset(token)


def current_call() -> CallAudit | None:
    return _current_call.get()


def mark_started(**fields: Any) -> None:
    """Record that the current operation passed every check and is about to run.

    Engine functions call this immediately before touching the machine. Outside a
    tool call (direct engine use in tests or scripts) it does nothing.
    """
    call = _current_call.get()
    if call is not None:
        call.mark_started(**fields)
