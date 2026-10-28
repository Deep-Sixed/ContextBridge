"""Durable task evidence ledger; no command execution or scheduling.

A request is not automatically evidence of a start or successful completion.
"""
from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path

_STATES = ("requested", "authorized", "started", "completed", "failed", "unknown")
_ALLOWED = {
    None: {"requested"},
    "requested": {"authorized", "failed"},
    "authorized": {"started", "failed"},
    "started": {"completed", "failed", "unknown"},
    "unknown": {"completed", "failed"},
    "completed": set(),
    "failed": set(),
}


class TaskTransitionError(ValueError):
    pass


class TaskLedger:
    """Immutable event sequence per task, persisted transactionally to SQLite."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, state TEXT NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, "
                "task_id TEXT NOT NULL, state TEXT NOT NULL, at REAL NOT NULL, "
                "detail TEXT NOT NULL, FOREIGN KEY(task_id) REFERENCES tasks(id))"
            )

    def _connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def create(self, *, description: str) -> str:
        if not isinstance(description, str) or not description.strip() or len(description) > 512:
            raise TaskTransitionError("description must be 1-512 characters")
        task_id = uuid.uuid4().hex
        with self._connection() as db:
            db.execute("INSERT INTO tasks(id,state) VALUES (?,?)", (task_id, "requested"))
            db.execute(
                "INSERT INTO events(task_id,state,at,detail) VALUES (?,?,?,?)",
                (task_id, "requested", time.time(), description),
            )
        return task_id

    def transition(self, task_id: str, next_state: str, *, detail: str = "") -> None:
        if next_state not in _STATES or not isinstance(detail, str) or len(detail) > 2048:
            raise TaskTransitionError("invalid task transition")
        with self._connection() as db:
            row = db.execute("SELECT state FROM tasks WHERE id=?", (task_id,)).fetchone()
            old = row[0] if row else None
            if next_state not in _ALLOWED[old]:
                raise TaskTransitionError(f"transition from {old!r} to {next_state!r} refused")
            db.execute("UPDATE tasks SET state=? WHERE id=?", (next_state, task_id))
            db.execute(
                "INSERT INTO events(task_id,state,at,detail) VALUES (?,?,?,?)",
                (task_id, next_state, time.time(), detail),
            )

    def history(self, task_id: str) -> list[dict]:
        with self._connection() as db:
            rows = db.execute(
                "SELECT seq,state,at,detail FROM events WHERE task_id=? ORDER BY seq", (task_id,)
            ).fetchall()
        return [
            {"seq": seq, "state": state, "at": timestamp, "detail": detail}
            for seq, state, timestamp, detail in rows
        ]
