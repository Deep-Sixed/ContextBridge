"""Search worker for the filesystem route's start_search tool.

Runs as its own process (``python -I fs_search_worker.py``) so a search, including
a slow regular expression, can always be stopped by killing it. Uses only the
standard library. Reads one JSON job from stdin and writes JSON lines to stdout:
``{"result": {...}}`` per match, then ``{"done": {...}}``, or ``{"error": "..."}``.

If the job sets ``hard_deadline_seconds``, the worker also arms ``signal.alarm`` so it
dies on time even if it is stuck and the server is gone.

The server has already checked the start path against its roots. The walk never
follows symlinks, skips the paths in ``skip`` (the trash), and opens files with
O_NOFOLLOW, so it stays under the start path.
"""

from __future__ import annotations

import fnmatch
import json
import math
import os
import re
import signal
import stat
import sys
import time
from collections.abc import Callable, Iterator
from typing import Any

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_BINARY_SNIFF_BYTES = 8192
_DEADLINE_CHECK_LINES = 1000


class _Stop(Exception):
    """Raised to end the walk early: result limit or deadline reached."""


def _name_matcher(pattern: str, ignore_case: bool) -> Callable[[str], bool]:
    """A glob when the pattern has *, ? or [; otherwise a substring match."""
    fold = str.casefold if ignore_case else str
    needle = fold(pattern)
    if any(ch in pattern for ch in "*?["):
        return lambda name: fnmatch.fnmatchcase(fold(name), needle)
    return lambda name: needle in fold(name)


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit]


class _Search:
    def __init__(self, job: dict[str, Any], emit: Callable[[dict[str, Any]], None]) -> None:
        self.job = job
        self.emit = emit
        self.skip = set(job.get("skip", []))
        self.include_hidden = bool(job.get("include_hidden"))
        self.max_results = int(job["max_results"])
        self.max_file_bytes = int(job["max_file_bytes"])
        self.max_line_chars = int(job["max_line_chars"])
        self.context = int(job.get("context_lines", 0))
        self.deadline = time.monotonic() + float(job["deadline_seconds"])
        globs = [g.casefold() for g in job.get("file_globs") or []]
        self.file_ok: Callable[[str], bool] = (
            (lambda name: any(fnmatch.fnmatchcase(name.casefold(), g) for g in globs))
            if globs
            else (lambda name: True)
        )
        self.count = 0
        self.files_scanned = 0
        self.skipped = {"binary": 0, "too_large": 0, "unreadable": 0}
        self.limit_reached = False
        self.timed_out = False

    def _check_deadline(self) -> None:
        if time.monotonic() >= self.deadline:
            self.timed_out = True
            raise _Stop

    def _add(self, result: dict[str, Any]) -> None:
        self.emit({"result": result})
        self.count += 1
        if self.count >= self.max_results:
            self.limit_reached = True
            raise _Stop

    def _walk(self, start: str) -> Iterator[os.DirEntry[str]]:
        """Depth-first, children sorted by name, symlinks reported but not followed."""
        stack = [start]
        while stack:
            directory = stack.pop()
            self._check_deadline()
            try:
                with os.scandir(directory) as it:
                    entries = sorted(it, key=lambda entry: entry.name)
            except OSError:
                self.skipped["unreadable"] += 1
                continue
            subdirs: list[str] = []
            for entry in entries:
                if entry.path in self.skip:
                    continue
                if not self.include_hidden and entry.name.startswith("."):
                    continue
                yield entry
                try:
                    if entry.is_dir(follow_symlinks=False):
                        subdirs.append(entry.path)
                except OSError:
                    self.skipped["unreadable"] += 1
            stack.extend(reversed(subdirs))

    def _files(self, start: str) -> None:
        matches = _name_matcher(self.job["pattern"], bool(self.job.get("ignore_case", True)))
        for entry in self._walk(start):
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError:
                self.skipped["unreadable"] += 1
                continue
            if stat.S_ISLNK(mode):
                kind = "symlink"
            elif stat.S_ISDIR(mode):
                kind = "directory"
            elif stat.S_ISREG(mode):
                kind = "file"
            else:
                kind = "other"
            if kind == "directory" and self.job.get("file_globs"):
                continue
            if kind != "directory" and not self.file_ok(entry.name):
                continue
            if matches(entry.name):
                self._add({"path": entry.path, "type": kind})

    def _read(self, path: str) -> str | None:
        try:
            fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC)
        except OSError:
            self.skipped["unreadable"] += 1
            return None
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                return None
            if st.st_size > self.max_file_bytes:
                self.skipped["too_large"] += 1
                return None
            try:
                data = fh.read(self.max_file_bytes + 1)
            except OSError:
                self.skipped["unreadable"] += 1
                return None
        if len(data) > self.max_file_bytes:
            self.skipped["too_large"] += 1
            return None
        if b"\0" in data[:_BINARY_SNIFF_BYTES]:
            self.skipped["binary"] += 1
            return None
        return data.decode("utf-8", errors="replace")

    def _search_file(self, path: str, regex: re.Pattern[str]) -> None:
        text = self._read(path)
        if text is None:
            return
        self.files_scanned += 1
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        lines = [line.removesuffix("\r") for line in lines]
        limit = self.max_line_chars
        for index, line in enumerate(lines):
            if index % _DEADLINE_CHECK_LINES == 0:
                self._check_deadline()
            if not regex.search(line):
                continue
            result: dict[str, Any] = {"path": path, "line": index + 1, "text": _clip(line, limit)}
            if len(line) > limit:
                result["truncated"] = True
            if self.context:
                result["before"] = [_clip(x, limit) for x in lines[max(0, index - self.context) : index]]
                result["after"] = [_clip(x, limit) for x in lines[index + 1 : index + 1 + self.context]]
            self._add(result)

    def _content(self, start: str) -> None:
        flags = re.IGNORECASE if self.job.get("ignore_case", True) else 0
        pattern = self.job["pattern"]
        regex = re.compile(re.escape(pattern) if self.job.get("literal") else pattern, flags)
        if os.path.isfile(start) and not os.path.islink(start):
            self._search_file(start, regex)
            return
        for entry in self._walk(start):
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                self.skipped["unreadable"] += 1
                continue
            if self.file_ok(entry.name):
                self._search_file(entry.path, regex)

    def run(self) -> dict[str, Any]:
        try:
            if self.job["search_type"] == "files":
                self._files(self.job["start"])
            else:
                self._content(self.job["start"])
        except _Stop:
            pass
        return {
            "result_count": self.count,
            "files_scanned": self.files_scanned,
            "skipped": self.skipped,
            "limit_reached": self.limit_reached,
            "timed_out": self.timed_out,
        }


def run(job: dict[str, Any], emit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    """Run one search, calling ``emit`` for each result; return the summary."""
    return _Search(job, emit).run()


def main() -> int:
    out = sys.stdout
    last_flush = time.monotonic()

    def write(message: dict[str, Any]) -> None:
        nonlocal last_flush
        out.write(json.dumps(message, separators=(",", ":")) + "\n")
        now = time.monotonic()
        if now - last_flush > 0.1:
            out.flush()
            last_flush = now

    try:
        job = json.loads(sys.stdin.read())
        # A kernel-enforced backstop: SIGALRM's default action ends the process even
        # inside a regular expression match, and even if the server that would kill
        # it has died. There is no alarm on Windows.
        if hasattr(signal, "alarm") and job.get("hard_deadline_seconds"):
            signal.alarm(max(1, math.ceil(float(job["hard_deadline_seconds"]))))
        write({"done": run(job, write)})
        out.flush()
    except BrokenPipeError:
        # The server went away; nobody is reading the results.
        return 0
    except Exception as exc:
        try:
            write({"error": f"{type(exc).__name__}: {exc}"})
            out.flush()
        except BrokenPipeError:
            pass
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
