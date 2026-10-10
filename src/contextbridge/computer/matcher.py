"""Caller-supplied regular expressions, matched in a child process that can be killed.

Python's ``re`` backtracks, so a pattern such as ``(a+)+$`` takes exponential time
on some lines, and it holds the GIL while it does. Matched in-process, one such
pattern would stall every thread of the gateway or agent (other calls, heartbeats,
session readers) until it finished. :class:`RegexWorker` runs the matching in a
short-lived child interpreter instead; the caller waits with a deadline and kills
the child (with :class:`~.proctree.ProcessTree`) when it passes.
"""

from __future__ import annotations

import contextlib
import json
import queue
import subprocess
import sys
import threading
import time
from typing import Any

from .proctree import ProcessTree

WORKER_TAG = "contextbridge search_code regex worker"
_EXIT_SECONDS = 0.5
_CLOSE_SECONDS = 2.0

# Runs with -I (no environment variables, user site, or script directory on sys.path)
# and reads only the stdlib. Protocol: one JSON line {pattern, flags}, then per text a
# JSON line {text, max} answered by a JSON list of matching line indices.
_WORKER = f"""# {WORKER_TAG}
import json, re, sys
inp, out = sys.stdin.buffer, sys.stdout.buffer
spec = json.loads(inp.readline())
matcher = re.compile(spec["pattern"], spec["flags"])
for raw in inp:
    request = json.loads(raw)
    hits = []
    for index, line in enumerate(request["text"].splitlines()):
        if matcher.search(line):
            hits.append(index)
            if len(hits) >= request["max"]:
                break
    out.write(json.dumps(hits).encode("ascii") + b"\\n")
    out.flush()
"""


class RegexWorkerError(RuntimeError):
    """The worker could not be started or stopped answering."""


def _line(message: dict[str, Any]) -> bytes:
    return json.dumps(message).encode("ascii") + b"\n"  # ASCII JSON: no encoding or newline surprises


class RegexWorker:
    """One compiled pattern in a child interpreter, searched text by text until :meth:`close`."""

    def __init__(self, pattern: str, flags: int, *, env: dict[str, str]) -> None:
        if not sys.executable:
            raise RegexWorkerError("no Python interpreter is available to run the regex worker")
        try:
            self._tree = ProcessTree(
                [sys.executable, "-I", "-c", _WORKER],
                cwd=None,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise RegexWorkerError(f"could not start the regex worker: {exc}") from None
        self._proc = self._tree.proc
        self._replies: queue.Queue[bytes | None] = queue.Queue()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        self._closed = False
        self._send({"pattern": pattern, "flags": flags})

    def _read(self) -> None:
        try:
            for raw in self._proc.stdout:
                self._replies.put(raw)
        except (OSError, ValueError):
            pass
        finally:
            self._replies.put(None)

    def _send(self, message: dict[str, Any]) -> None:
        try:
            self._proc.stdin.write(_line(message))
            self._proc.stdin.flush()
        except (OSError, ValueError):
            self.close()
            raise RegexWorkerError("the regex worker exited unexpectedly") from None

    def search(self, text: str, max_hits: int, deadline: float) -> list[int] | None:
        """Indices into ``text.splitlines()`` of lines that match, at most ``max_hits`` of them.

        Returns None, and kills the worker, if no answer arrives by ``deadline``
        (a :func:`time.monotonic` value).
        """
        self._send({"text": text, "max": max_hits})
        try:
            raw = self._replies.get(timeout=max(0.0, deadline - time.monotonic()))
        except queue.Empty:
            self.close(kill=True)
            return None
        if raw is None:
            self.close()
            raise RegexWorkerError("the regex worker exited unexpectedly")
        return json.loads(raw)

    def close(self, *, kill: bool = False) -> None:
        """Stop the worker: an idle one exits at end of input; a busy one, or ``kill``, is killed."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(OSError):
            self._proc.stdin.close()
        if not kill:
            try:
                self._proc.wait(timeout=_EXIT_SECONDS)
            except subprocess.TimeoutExpired:
                kill = True
        if kill:
            self._tree.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self._proc.wait(timeout=_CLOSE_SECONDS)
        self._tree.release()
        self._reader.join(_CLOSE_SECONDS)
        with contextlib.suppress(OSError):
            self._proc.stdout.close()

    def __enter__(self) -> RegexWorker:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
