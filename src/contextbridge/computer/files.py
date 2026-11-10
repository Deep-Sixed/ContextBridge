"""Filesystem operations for the computer route.

Every function takes the active :class:`ComputerPolicy` and resolves each path
through it before touching the disk. Listings and searches silently skip
entries the policy hides.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import search_worker
from .audit import mark_started
from .policy import ComputerPolicy, PolicyViolation
from .proctree import ProcessTree
from .search_worker import text_encoding as _text_encoding

_MAX_DEPTH = 5
_SEARCH_WORKER = Path(search_worker.__file__)
# How long past the search deadline the worker's own alarm waits, in case nobody is left to kill it.
_WORKER_ALARM_GRACE_SECONDS = 5.0
_WORKER_EXIT_SECONDS = 0.5


# Binary formats the document tools read; read_file points callers there.
DOCUMENT_SUFFIXES = (".pdf", ".docx", ".xlsx", ".xlsm")


class FileOperationError(ValueError):
    """Raised when a file operation cannot be completed as requested."""


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _kind(st: os.stat_result) -> str:
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if stat.S_ISDIR(st.st_mode):
        return "directory"
    if stat.S_ISREG(st.st_mode):
        return "file"
    return "other"


def _require_file(path: Path, raw: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"No such file: {raw}")
    if not path.is_file():
        raise FileOperationError(f"Not a regular file: {raw}")


def _atomic_write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".cbtmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        if path.exists():
            shutil.copymode(path, tmp)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ------------------------------------------------------------------ reading


def list_directory(policy: ComputerPolicy, path: str, *, depth: int = 1) -> dict[str, Any]:
    root = policy.resolve(path)
    if not root.is_dir():
        raise FileOperationError(f"Not a directory: {path}")
    depth = max(1, min(int(depth), _MAX_DEPTH))
    mark_started(path=str(root))
    entries: list[dict[str, Any]] = []
    truncated = False

    def walk(directory: Path, level: int) -> None:
        nonlocal truncated
        try:
            children = sorted(os.scandir(directory), key=lambda e: e.name.casefold())
        except OSError:
            return
        for child in children:
            if len(entries) >= policy.max_results:
                truncated = True
                return
            child_path = Path(child.path)
            if not policy.is_visible(child_path):
                continue
            try:
                st = child.stat(follow_symlinks=False)
            except OSError:
                continue
            kind = _kind(st)
            entry: dict[str, Any] = {
                "path": str(child_path.relative_to(root)),
                "type": kind,
                "modified": _iso(st.st_mtime),
            }
            if kind == "file":
                entry["size"] = st.st_size
            entries.append(entry)
            if kind == "directory" and level < depth:
                walk(child_path, level + 1)

    walk(root, 1)
    return {"path": str(root), "entries": entries, "truncated": truncated}


def read_file(
    policy: ComputerPolicy, path: str, *, offset: int = 0, length: int | None = None
) -> dict[str, Any]:
    """Read text lines. ``offset`` is 0-based; a negative offset reads the last N lines."""
    resolved = policy.resolve(path)
    _require_file(resolved, path)
    mark_started(path=str(resolved))
    size = resolved.stat().st_size
    encoding = _text_encoding(resolved)
    if encoding is None:
        hint = " Use read_document for PDF, Word, and Excel files." if resolved.suffix.lower() in DOCUMENT_SUFFIXES else ""
        raise FileOperationError(f"{path} looks like a binary file ({size} bytes); only text files can be read.{hint}")
    budget = policy.max_read_bytes
    used = 0
    truncated = False
    total_lines = 0
    with resolved.open("r", encoding=encoding, errors="replace", newline="") as fh:
        if offset < 0:
            tail: deque[str] = deque(maxlen=-offset)
            for line in fh:
                tail.append(line)
                total_lines += 1
            selected = list(tail)
            if length is not None:
                selected = selected[: max(0, length)]
            start = total_lines - len(tail)
            lines: list[str] = []
            for line in selected:
                used += len(line.encode("utf-8"))
                if used > budget:
                    truncated = True
                    break
                lines.append(line)
        else:
            start = offset
            lines = []
            for index, line in enumerate(fh):
                total_lines = index + 1
                if index < offset:
                    continue
                if truncated or (length is not None and len(lines) >= length):
                    continue
                used += len(line.encode("utf-8"))
                if used > budget:
                    truncated = True
                    continue
                lines.append(line)
    return {
        "path": str(resolved),
        "encoding": encoding,
        "content": "".join(lines),
        "start_line": start,
        "lines_returned": len(lines),
        "total_lines": total_lines,
        "size": size,
        "truncated": truncated,
    }


def get_file_info(policy: ComputerPolicy, path: str) -> dict[str, Any]:
    resolved = policy.resolve(path)
    if not resolved.exists():
        raise FileNotFoundError(f"No such file or directory: {path}")
    mark_started(path=str(resolved))
    st = resolved.stat()
    info: dict[str, Any] = {
        "path": str(resolved),
        "type": _kind(st),
        "size": st.st_size,
        "modified": _iso(st.st_mtime),
        "accessed": _iso(st.st_atime),
        "permissions": stat.filemode(st.st_mode),
        "readable": os.access(resolved, os.R_OK),
        "writable_by_policy": _writable(policy, resolved),
    }
    if resolved.is_file() and st.st_size <= policy.max_read_bytes:
        encoding = _text_encoding(resolved)
        info["binary"] = encoding is None
        if encoding is not None:
            info["encoding"] = encoding
            with resolved.open("r", encoding=encoding, errors="replace", newline="") as fh:
                info["line_count"] = sum(1 for _ in fh)
    return info


def _writable(policy: ComputerPolicy, path: Path) -> bool:
    if not policy.can_write:
        return False
    try:
        policy.resolve(str(path), write=True)
    except PolicyViolation:
        return False
    return True


def _walk_files(policy: ComputerPolicy, root: Path, deadline: float):
    """Yield visible files and directories under ``root``; stops at ``deadline``."""
    for dirpath, dirnames, filenames in os.walk(root):
        if time.monotonic() > deadline:
            return
        base = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if policy.is_visible(base / d))
        for name in dirnames:
            yield base / name, True
        for name in sorted(filenames):
            candidate = base / name
            if policy.is_visible(candidate):
                yield candidate, False


def search_files(
    policy: ComputerPolicy, path: str, pattern: str, *, max_results: int | None = None
) -> dict[str, Any]:
    """Find files and directories by name: a glob (``*.py``) or a case-insensitive substring."""
    root = policy.resolve(path)
    if not root.is_dir():
        raise FileOperationError(f"Not a directory: {path}")
    if not pattern:
        raise FileOperationError("A search pattern is required.")
    limit = min(max_results or policy.max_results, policy.max_results)
    needle = pattern.casefold()
    is_glob = any(ch in pattern for ch in "*?[")
    deadline = time.monotonic() + policy.max_search_seconds
    mark_started(path=str(root))
    matches: list[dict[str, Any]] = []
    truncated = False
    for candidate, is_dir in _walk_files(policy, root, deadline):
        name = candidate.name.casefold()
        if (fnmatch.fnmatchcase(name, needle) if is_glob else needle in name):
            if len(matches) >= limit:
                truncated = True
                break
            matches.append({"path": str(candidate), "type": "directory" if is_dir else "file"})
    timed_out = time.monotonic() > deadline
    return {"path": str(root), "matches": matches, "truncated": truncated or timed_out, "timed_out": timed_out}


def search_code(
    policy: ComputerPolicy,
    path: str,
    pattern: str,
    *,
    file_pattern: str | None = None,
    regex: bool = False,
    case_sensitive: bool = False,
    context_lines: int = 0,
    max_results: int | None = None,
) -> dict[str, Any]:
    """Search text file contents under ``path``; binary and oversized files are skipped.

    A regular expression is matched in a separate worker process that is killed at the
    search deadline, because a slow pattern would otherwise stall this whole process
    (see :mod:`.search_worker`). Literal searches cannot backtrack and run here.
    """
    root = policy.resolve(path)
    if not pattern:
        raise FileOperationError("A search pattern is required.")
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        matcher = re.compile(pattern if regex else re.escape(pattern), flags)
    except re.error as exc:
        raise FileOperationError(f"Invalid regular expression: {exc}") from None
    limit = min(max_results or policy.max_results, policy.max_results)
    context_lines = max(0, min(int(context_lines), 5))
    deadline = time.monotonic() + policy.max_search_seconds
    file_glob = file_pattern.casefold() if file_pattern else None

    if root.is_file():
        candidates = iter([(root, False)])
    elif root.is_dir():
        candidates = _walk_files(policy, root, deadline)
    else:
        raise FileNotFoundError(f"No such file or directory: {path}")
    mark_started(path=str(root))

    def targets() -> Iterator[str]:
        for candidate, is_dir in candidates:
            if is_dir:
                continue
            if file_glob and not fnmatch.fnmatchcase(candidate.name.casefold(), file_glob):
                continue
            yield str(candidate)

    if regex:
        job = {
            "pattern": pattern,
            "case_sensitive": case_sensitive,
            "context_lines": context_lines,
            "limit": limit,
            "max_bytes": policy.max_read_bytes,
            "hard_deadline_seconds": policy.max_search_seconds + _WORKER_ALARM_GRACE_SECONDS,
        }
        matches, files_scanned, truncated, killed = _search_in_worker(job, targets(), deadline)
    else:
        matches, files_scanned, truncated, killed = [], 0, False, False
        for target in targets():
            if time.monotonic() > deadline or truncated:
                break
            lines = search_worker.read_lines(target, policy.max_read_bytes)
            if lines is None:
                continue
            files_scanned += 1
            for hit in search_worker.line_hits(target, lines, matcher, context_lines):
                if len(matches) >= limit:
                    truncated = True
                    break
                matches.append(hit)
    # A killed worker is a timeout whatever the clock reads: time.monotonic() ticks every ~16 ms on
    # Windows before Python 3.13, so it can still equal the deadline just after the timer fired.
    timed_out = killed or time.monotonic() > deadline
    return {
        "path": str(root),
        "matches": matches,
        "files_scanned": files_scanned,
        "truncated": truncated or timed_out,
        "timed_out": timed_out,
    }


def _search_in_worker(
    job: dict[str, Any], targets: Iterator[str], deadline: float
) -> tuple[list[dict[str, Any]], int, bool, bool]:
    """Run a regular-expression search in a worker process.

    Returns (matches, files_scanned, truncated, killed). The worker is killed at ``deadline``,
    even in the middle of a match (``killed``). What it reported before then is kept.
    """
    try:
        # -I: the worker needs nothing from the environment or the user's site-packages.
        tree = ProcessTree(
            [sys.executable, "-I", str(_SEARCH_WORKER)],
            cwd=None,
            env=None,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise FileOperationError(f"Could not start the search worker: {exc}") from None
    proc = tree.proc
    assert proc.stdin is not None and proc.stdout is not None
    killed = threading.Event()

    def expire() -> None:
        killed.set()
        tree.kill()

    def feed() -> None:
        # Paths are sent as they are found, so the worker searches while the walk continues.
        try:
            proc.stdin.write(json.dumps(job).encode("ascii") + b"\n")
            for target in targets:
                proc.stdin.write(json.dumps(target).encode("ascii") + b"\n")
                proc.stdin.flush()
        except (OSError, ValueError):
            pass  # the worker finished early (result limit) or was killed
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    timer = threading.Timer(max(0.0, deadline - time.monotonic()), expire)
    timer.daemon = True
    feeder = threading.Thread(target=feed, daemon=True)
    matches: list[dict[str, Any]] = []
    files_scanned = 0
    truncated = False
    limit = job["limit"]
    exit_code: int | None = None
    try:
        timer.start()
        feeder.start()
        for raw in proc.stdout:
            try:
                message = json.loads(raw)
            except ValueError:
                break  # a line cut short when the worker was killed
            if "hit" in message:
                if len(matches) >= limit:
                    truncated = True
                    break
                matches.append(message["hit"])
            elif "scanned" in message:
                files_scanned = message["scanned"]
            elif message.get("truncated"):
                truncated = True
        else:
            # stdout closed: the worker is exiting on its own (or the timer killed it).
            try:
                exit_code = proc.wait(timeout=_WORKER_EXIT_SECONDS)
            except subprocess.TimeoutExpired:
                pass
    finally:
        timer.cancel()
        if proc.poll() is None:
            tree.kill()
        proc.wait()
        tree.release()
        proc.stdout.close()
        feeder.join(_WORKER_EXIT_SECONDS)
    if exit_code not in (None, 0) and not killed.is_set():
        raise FileOperationError("The search worker failed.")
    return matches, files_scanned, truncated, killed.is_set()


# ------------------------------------------------------------------ writing


def _encode_for_write(policy: ComputerPolicy, content: str, encoding: str = "utf-8") -> bytes:
    data = content.encode(encoding)
    if len(data) > policy.max_write_bytes:
        raise FileOperationError(
            f"Content is {len(data)} bytes; the limit is {policy.max_write_bytes} bytes per write."
        )
    return data


def _require_parent(path: Path, raw: str) -> None:
    if not path.parent.is_dir():
        raise FileOperationError(f"Parent directory of {raw} does not exist; create it first.")


def write_file(policy: ComputerPolicy, path: str, content: str, *, mode: str = "rewrite") -> dict[str, Any]:
    if mode not in ("rewrite", "append"):
        raise FileOperationError("mode must be 'rewrite' or 'append'.")
    resolved = policy.resolve(path, write=True)
    if resolved.exists() and not resolved.is_file():
        raise FileOperationError(f"Not a regular file: {path}")
    _require_parent(resolved, path)
    data = _encode_for_write(policy, content)
    created = not resolved.exists()
    mark_started(path=str(resolved), bytes=len(data))
    if mode == "append":
        with resolved.open("ab") as fh:
            fh.write(data)
    elif created:
        with resolved.open("xb") as fh:  # normal umask permissions for new files
            fh.write(data)
    else:
        _atomic_write(resolved, data)
    return {"path": str(resolved), "mode": mode, "bytes_written": len(data), "created": created}


def edit_block(
    policy: ComputerPolicy,
    path: str,
    old_string: str,
    new_string: str,
    *,
    expected_replacements: int = 1,
) -> dict[str, Any]:
    """Replace exact occurrences of ``old_string``; the count must equal ``expected_replacements``."""
    if not old_string:
        raise FileOperationError("old_string must not be empty.")
    if expected_replacements < 1:
        raise FileOperationError("expected_replacements must be at least 1.")
    resolved = policy.resolve(path, write=True)
    _require_file(resolved, path)
    encoding = _text_encoding(resolved)
    if resolved.stat().st_size > policy.max_read_bytes or encoding is None:
        raise FileOperationError(f"{path} is binary or larger than the read limit; it cannot be edited.")
    with resolved.open("r", encoding=encoding, newline="") as fh:
        original = fh.read()
    found = original.count(old_string)
    if found != expected_replacements:
        hint = " Check whitespace and line endings." if found == 0 else ""
        raise FileOperationError(
            f"Expected {expected_replacements} occurrence(s) of old_string in {path}, found {found}.{hint}"
        )
    updated = original.replace(old_string, new_string)
    data = _encode_for_write(policy, updated, encoding)  # keeps the file's encoding and BOM
    mark_started(path=str(resolved), replacements=found)
    _atomic_write(resolved, data)
    return {"path": str(resolved), "replacements": found}


def create_directory(policy: ComputerPolicy, path: str) -> dict[str, Any]:
    resolved = policy.resolve(path, write=True)
    if resolved.exists() and not resolved.is_dir():
        raise FileOperationError(f"{path} exists and is not a directory.")
    created = not resolved.exists()
    mark_started(path=str(resolved))
    resolved.mkdir(parents=True, exist_ok=True)
    return {"path": str(resolved), "created": created}


def move_file(policy: ComputerPolicy, source: str, destination: str) -> dict[str, Any]:
    src = policy.resolve(source, write=True, follow_symlinks=False)
    dst = policy.resolve(destination, write=True, follow_symlinks=False)
    if not os.path.lexists(src):
        raise FileNotFoundError(f"No such file or directory: {source}")
    policy.guard_move(src)
    if os.path.lexists(dst):
        raise FileOperationError(f"Destination already exists: {destination}")
    _require_parent(dst, destination)
    if src.is_dir() and not src.is_symlink() and dst.is_relative_to(src):
        raise FileOperationError("Cannot move a directory into itself.")
    mark_started(source=str(src), destination=str(dst))
    shutil.move(str(src), str(dst))
    return {"source": str(src), "destination": str(dst)}
