"""Line matching for ``search_code``, and the worker process that runs regular expressions.

Python's ``re`` holds the interpreter lock for the whole of a match, so a slow
pattern (``^(x+)+y`` against a line of x's) stops every thread in the process
and cannot be interrupted. A caller-supplied regular expression therefore never
runs in the gateway or the agent: ``search_code`` starts this file as its own
process (``python -I search_worker.py``) and kills it at the search deadline.

Protocol: the first line on stdin is a JSON job (``pattern``, ``case_sensitive``,
``context_lines``, ``limit``, ``max_bytes``, ``hard_deadline_seconds``); each
later line is a JSON string naming a file to search. The parent has already
checked every path against its policy. stdout carries JSON lines:
``{"hit": {...}}`` per match, ``{"scanned": n}`` after each file read, and
``{"truncated": true}`` when the result limit stopped the search.

This file uses only the standard library and no relative imports, so it runs
as a script without the package on ``sys.path``.
"""

from __future__ import annotations

import json
import math
import os
import re
import signal
import stat
import sys
from collections.abc import Iterator
from typing import Any

BINARY_SNIFF_BYTES = 8192
MAX_LINE_CHARS = 2000


def text_encoding(path: str | os.PathLike[str]) -> str | None:
    """The encoding to read ``path`` with, or None if it looks binary.

    Recognizes byte-order marks, so UTF-16 files (what Windows PowerShell's ``>``
    writes) and UTF-8 files with a BOM are text.
    """
    with open(path, "rb") as fh:
        head = fh.read(BINARY_SNIFF_BYTES)
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if b"\x00" in head:
        return None
    return "utf-8"


def clip(line: str) -> str:
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + "…"


def read_lines(path: str | os.PathLike[str], max_bytes: int) -> list[str] | None:
    """The lines of a text file, or None for anything ``search_code`` skips.

    Skipped: FIFOs and devices (never opened), files over ``max_bytes``, binary
    files, and files that cannot be read.
    """
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        encoding = text_encoding(path)
        if encoding is None:
            return None
        with open(path, encoding=encoding, errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return None


def line_hits(path: str, lines: list[str], matcher: re.Pattern[str], context_lines: int) -> Iterator[dict[str, Any]]:
    for index, line in enumerate(lines):
        if not matcher.search(line):
            continue
        hit: dict[str, Any] = {"path": path, "line": index + 1, "text": clip(line)}
        if context_lines:
            lo = max(0, index - context_lines)
            hit["before"] = [clip(x) for x in lines[lo:index]]
            hit["after"] = [clip(x) for x in lines[index + 1 : index + 1 + context_lines]]
        yield hit


def main() -> int:
    stdin = sys.stdin.buffer
    out = sys.stdout.buffer

    def write(message: dict[str, Any]) -> None:
        out.write(json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n")

    try:
        job = json.loads(stdin.readline())
        # A kernel-enforced backstop: SIGALRM's default action ends the process even inside
        # a match, and even if the parent that would kill it has died. Windows has no alarm;
        # there the parent's job object ends this process with it.
        if hasattr(signal, "alarm") and job.get("hard_deadline_seconds"):
            signal.alarm(max(1, math.ceil(float(job["hard_deadline_seconds"]))))
        matcher = re.compile(job["pattern"], 0 if job.get("case_sensitive") else re.IGNORECASE)
        context_lines, limit, max_bytes = int(job["context_lines"]), int(job["limit"]), int(job["max_bytes"])
        found = scanned = 0
        for raw in stdin:
            path = json.loads(raw)
            lines = read_lines(path, max_bytes)
            if lines is None:
                continue
            scanned += 1
            write({"scanned": scanned})
            for hit in line_hits(path, lines, matcher, context_lines):
                if found >= limit:
                    write({"truncated": True})
                    out.flush()
                    return 0
                write({"hit": hit})
                found += 1
            out.flush()
        out.flush()
    except BrokenPipeError:
        return 0  # the parent went away; nobody is reading
    return 0


if __name__ == "__main__":
    sys.exit(main())
