"""Search sessions for the filesystem route.

``start_search`` checks the arguments and the path, then runs the search in a
separate worker process (``fs_search_worker.py``) so it can always be stopped,
even inside a slow regular expression. A reader thread collects the worker's
results; clients page through them with ``more`` while the search runs or after it
finishes. Running searches, kept sessions, results and bytes per session are all
capped.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .fs import Filesystem, FsError, _os_errors

WORKER = Path(__file__).with_name("search_worker.py")

SEARCH_TYPES = ("files", "content")
DEFAULT_MAX_RESULTS = 500
MAX_RESULTS = 5000
MAX_CONTEXT_LINES = 10
DEFAULT_TIMEOUT_MS = 30_000
MAX_TIMEOUT_MS = 300_000
DEFAULT_PAGE = 100
MAX_PAGE = 500
MAX_LINE_CHARS = 500
MAX_RUNNING = 4
MAX_SESSIONS = 10
MAX_SESSION_BYTES = 8 * 1024 * 1024
# start_search waits this long for a search to finish before returning what it has.
INITIAL_WAIT_SECONDS = 1.0
# Grace period after the worker's own deadline before it is killed.
KILL_GRACE_SECONDS = 2.0


def expand_file_pattern(file_pattern: str | None) -> list[str]:
    """Split ``"*.py|*.md"`` and expand one level of braces: ``"*.{ts,tsx}"``."""
    if file_pattern is None:
        return []
    globs: list[str] = []
    for part in (p.strip() for p in file_pattern.split("|")):
        if not part:
            raise FsError("file_pattern has an empty glob")
        match = re.fullmatch(r"(.*)\{([^{}]*)\}(.*)", part)
        if match:
            prefix, options, suffix = match.groups()
            globs.extend(prefix + option.strip() + suffix for option in options.split(","))
        else:
            globs.append(part)
    return globs


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class _Session:
    search_id: str
    search_type: str
    pattern: str
    path: str
    proc: subprocess.Popen[bytes]
    started_at: str = field(default_factory=_iso_now)
    started: float = field(default_factory=time.monotonic)
    finished_at: float | None = None
    status: str = "running"
    results: list[dict[str, Any]] = field(default_factory=list)
    result_bytes: int = 0
    limit_reached: bool = False
    summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    finished: threading.Event = field(default_factory=threading.Event)

    def elapsed_ms(self) -> int:
        end = self.finished_at if self.finished_at is not None else time.monotonic()
        return max(0, round((end - self.started) * 1000))

    def state(self) -> dict[str, Any]:
        """Status fields shared by every response. Call with the lock held."""
        state: dict[str, Any] = {
            "search_id": self.search_id,
            "status": self.status,
            "search_type": self.search_type,
            "path": self.path,
            "total_results": len(self.results),
            "limit_reached": self.limit_reached,
            "elapsed_ms": self.elapsed_ms(),
        }
        if self.summary:
            state["files_scanned"] = self.summary.get("files_scanned", 0)
            state["skipped"] = self.summary.get("skipped", {})
        if self.error:
            state["error"] = self.error
        return state


class SearchManager:
    """Runs and tracks searches over one Filesystem's roots."""

    def __init__(self, fs: Filesystem) -> None:
        self._fs = fs
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    # -- tools ------------------------------------------------------------------

    def start(
        self,
        path: str,
        pattern: str,
        search_type: str = "files",
        file_pattern: str | None = None,
        ignore_case: bool = True,
        literal: bool = False,
        include_hidden: bool = False,
        context_lines: int = 0,
        max_results: int = DEFAULT_MAX_RESULTS,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, Any]:
        if search_type not in SEARCH_TYPES:
            raise FsError("search_type must be 'files' or 'content'")
        if not isinstance(pattern, str) or not pattern:
            raise FsError("pattern must be a non-empty string")
        if search_type == "content" and not literal:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise FsError(f"invalid regular expression: {exc}") from None
        if not 1 <= max_results <= MAX_RESULTS:
            raise FsError(f"max_results must be between 1 and {MAX_RESULTS}")
        if not 0 <= context_lines <= MAX_CONTEXT_LINES:
            raise FsError(f"context_lines must be between 0 and {MAX_CONTEXT_LINES}")
        if not 100 <= timeout_ms <= MAX_TIMEOUT_MS:
            raise FsError(f"timeout_ms must be between 100 and {MAX_TIMEOUT_MS}")
        globs = expand_file_pattern(file_pattern)
        target = self._fs.resolve(path)
        with _os_errors(path):
            if not target.path.exists():
                raise FsError(f"{path}: not found", code="not_found")
            if not (target.path.is_dir() or (search_type == "content" and target.path.is_file())):
                raise FsError(f"{path}: not a directory", code="not_a_directory")

        job = {
            "start": str(target.path),
            "skip": [str(root.trash) for root in self._fs.roots],
            "search_type": search_type,
            "pattern": pattern,
            "literal": literal,
            "ignore_case": ignore_case,
            "file_globs": globs,
            "include_hidden": include_hidden,
            "context_lines": context_lines,
            "max_results": max_results,
            "max_file_bytes": self._fs.limits.max_search_file_bytes,
            "max_line_chars": MAX_LINE_CHARS,
            "deadline_seconds": timeout_ms / 1000,
            "hard_deadline_seconds": timeout_ms / 1000 + KILL_GRACE_SECONDS + 1,
        }
        with self._lock:
            running = sum(1 for s in self._sessions.values() if s.status == "running")
            if running >= MAX_RUNNING:
                raise FsError(
                    f"{MAX_RUNNING} searches are already running; stop one or wait",
                    code="busy",
                )
            self._evict()
            try:
                proc = subprocess.Popen(
                    [sys.executable, "-I", str(WORKER)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
            except OSError:
                raise FsError("could not start the search worker", code="os_error") from None
            session = _Session(uuid.uuid4().hex, search_type, pattern, str(target.path), proc)
            self._sessions[session.search_id] = session
        try:
            assert proc.stdin is not None
            proc.stdin.write(json.dumps(job).encode("utf-8"))
            proc.stdin.close()
        except OSError:
            pass  # The reader thread reports the worker's exit.
        killer = threading.Timer(job["deadline_seconds"] + KILL_GRACE_SECONDS, self._expire, (session,))
        killer.daemon = True
        killer.start()
        threading.Thread(target=self._collect, args=(session, killer), daemon=True).start()
        session.finished.wait(min(INITIAL_WAIT_SECONDS, job["deadline_seconds"] + KILL_GRACE_SECONDS))
        return self._page(session, 0, DEFAULT_PAGE)

    def more(self, search_id: str, offset: int = 0, length: int = DEFAULT_PAGE) -> dict[str, Any]:
        if not 1 <= length <= MAX_PAGE:
            raise FsError(f"length must be between 1 and {MAX_PAGE}")
        return self._page(self._get(search_id), offset, length)

    def stop(self, search_id: str) -> dict[str, Any]:
        session = self._get(search_id)
        with session.lock:
            if session.status == "running":
                session.status = "cancelled"
                session.proc.kill()
        session.finished.wait(5)
        with session.lock:
            return session.state()

    def list(self) -> dict[str, Any]:
        with self._lock:
            sessions = list(self._sessions.values())
        searches = []
        for session in sessions:
            with session.lock:
                state = session.state()
            state["pattern"] = session.pattern[:80]
            state["started_at"] = session.started_at
            searches.append(state)
        return {"searches": searches}

    def close(self) -> None:
        """Kill every running search (for shutdown and tests)."""
        with self._lock:
            sessions = list(self._sessions.values())
        for session in sessions:
            with session.lock:
                if session.status == "running":
                    session.status = "cancelled"
                    session.proc.kill()
        for session in sessions:
            session.finished.wait(5)

    # -- internals --------------------------------------------------------------

    def _get(self, search_id: str) -> _Session:
        with self._lock:
            session = self._sessions.get(search_id)
        if session is None:
            raise FsError(f"search not found: {search_id}", code="not_found")
        return session

    def _evict(self) -> None:
        """Drop the oldest finished sessions to make room. Call with self._lock held."""
        finished = sorted(
            (s for s in self._sessions.values() if s.status != "running"),
            key=lambda s: s.started,
        )
        while len(self._sessions) >= MAX_SESSIONS and finished:
            del self._sessions[finished.pop(0).search_id]

    def _page(self, session: _Session, offset: int, length: int) -> dict[str, Any]:
        with session.lock:
            total = len(session.results)
            start = max(0, total + offset) if offset < 0 else min(offset, total)
            results = session.results[start : start + length]
            page = session.state()
            page.update(
                {
                    "results": results,
                    "offset": start,
                    "has_more": start + len(results) < total or session.status == "running",
                }
            )
        return page

    def _expire(self, session: _Session) -> None:
        with session.lock:
            if session.status == "running":
                session.status = "timed_out"
                session.proc.kill()

    def _collect(self, session: _Session, killer: threading.Timer) -> None:
        proc = session.proc
        assert proc.stdout is not None
        try:
            for raw in proc.stdout:
                message = json.loads(raw)
                with session.lock:
                    if "result" in message:
                        if session.result_bytes + len(raw) > MAX_SESSION_BYTES:
                            session.limit_reached = True
                            if session.status == "running":
                                session.status = "completed"
                            proc.kill()
                            break
                        session.results.append(message["result"])
                        session.result_bytes += len(raw)
                    elif "done" in message:
                        session.summary = message["done"]
                        session.limit_reached = session.limit_reached or message["done"]["limit_reached"]
                        if session.status == "running":
                            session.status = "timed_out" if message["done"]["timed_out"] else "completed"
                    elif "error" in message and session.status == "running":
                        session.status = "failed"
                        session.error = "search failed"
        except (OSError, ValueError):
            pass
        finally:
            killer.cancel()
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            proc.stdout.close()
            with session.lock:
                if session.status == "running":
                    session.status = "failed"
                    session.error = "search worker exited unexpectedly"
                session.finished_at = time.monotonic()
            session.finished.set()
