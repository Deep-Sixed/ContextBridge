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

import json
import sys
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO


class AuditError(RuntimeError):
    """Raised when an audit event cannot be written."""


class ComputerAuditLog:
    """Append-only JSONL audit sink shared by tool calls and session threads."""

    def __init__(self, path: str | Path | None, *, echo: bool = True) -> None:
        self.path = Path(path) if path else None
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
            "route": "computer",
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
                print(f"[computer audit] {line}", file=sys.stderr, flush=True)

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
    started: bool = False

    def emit(self, event: str, **fields: Any) -> None:
        self.log.record(event, request_id=self.request_id, tool=self.tool, client=self.client, **fields)


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
    if call is None or call.started:
        return
    call.emit("started", **fields)
    call.started = True
