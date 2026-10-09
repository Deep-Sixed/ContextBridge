"""Filesystem operations for the computer route.

Every function takes the active :class:`ComputerPolicy` and resolves each path
through it before touching the disk. Listings and searches silently skip
entries the policy hides.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import stat
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import mark_started
from .policy import ComputerPolicy, PolicyViolation

_BINARY_SNIFF_BYTES = 8192
_MAX_LINE_CHARS = 2000
_MAX_DEPTH = 5


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


def _text_encoding(path: Path) -> str | None:
    """The encoding to read ``path`` with, or None if it looks binary.

    Recognizes byte-order marks, so UTF-16 files (what Windows PowerShell's ``>``
    writes) and UTF-8 files with a BOM are text.
    """
    with path.open("rb") as fh:
        head = fh.read(_BINARY_SNIFF_BYTES)
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if b"\x00" in head:
        return None
    return "utf-8"


def _is_binary(path: Path) -> bool:
    return _text_encoding(path) is None


def _require_file(path: Path, raw: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"No such file: {raw}")
    if not path.is_file():
        raise FileOperationError(f"Not a regular file: {raw}")


def _clip(line: str) -> str:
    return line if len(line) <= _MAX_LINE_CHARS else line[:_MAX_LINE_CHARS] + "…"


def _bounded_lines(fh: Any, limit: int):
    """Yield ``(line, dropped)`` for each line of a text stream, holding at most ``limit`` characters.

    A longer line yields only its first ``limit`` characters; the rest is read in
    ``limit``-sized pieces and discarded, and ``dropped`` counts them. A file with
    no newlines therefore never sits in memory whole.
    """
    pending = ""
    while True:
        line, pending = pending or fh.readline(limit), ""
        if not line:
            return
        dropped = 0
        piece = line
        # A piece ends its line when it is short (line break or end of file) or ends in a line break.
        while len(piece) == limit and not piece.endswith(("\n", "\r")):
            piece = fh.readline(limit)
            dropped += len(piece.rstrip("\r\n"))
        if len(piece) == limit and piece.endswith("\r"):
            # The cut may have split "\r\n"; the next read then returns the "\n" alone.
            after = fh.readline(limit)
            if after != "\n":
                pending = after
        yield line, dropped


def _clip_to_budget(line: str, dropped: int, budget: int) -> str:
    """The head of a line too long for the read limit, ending in a marker that says so."""
    body = line.rstrip("\r\n")

    def marker(omitted: int) -> str:
        return f" … [{omitted} more characters on this line; clipped at the {budget}-byte read limit]\n"

    # Size the head against the longest marker it could need, so head + marker fits the budget.
    room = max(0, budget - len(marker(len(body) + dropped).encode("utf-8")))
    head = body.encode("utf-8")[:room].decode("utf-8", "ignore")
    return head + marker(len(body) + dropped - len(head))


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
    """Read text lines. ``offset`` is 0-based; a negative offset reads the last N lines.

    Memory stays within a small multiple of ``max_read_bytes`` whatever the file
    holds: lines are read in bounded pieces, and a negative offset counts the lines
    in a first pass instead of buffering them. Returned content stops at the read
    limit (``truncated``). A single line longer than the limit can never be
    returned whole; when it is the first requested line, its head comes back
    with a marker (``line_clipped``), so paging forward always makes progress.
    """
    resolved = policy.resolve(path)
    _require_file(resolved, path)
    mark_started(path=str(resolved))
    size = resolved.stat().st_size
    encoding = _text_encoding(resolved)
    if encoding is None:
        raise FileOperationError(
            f"{path} looks like a binary file ({size} bytes); only text files can be read."
        )
    budget = policy.max_read_bytes
    limit = budget + 1  # characters; a longer line is over budget in any encoding

    def open_text():
        return resolved.open("r", encoding=encoding, errors="replace", newline="")

    if offset < 0:
        with open_text() as fh:
            counted = sum(1 for _ in _bounded_lines(fh, limit))
        start = max(0, counted + offset)
    else:
        start = offset
    used = 0
    truncated = False
    clipped = False
    total_lines = 0
    lines: list[str] = []
    with open_text() as fh:
        for index, (line, dropped) in enumerate(_bounded_lines(fh, limit)):
            total_lines = index + 1
            if index < start or truncated or (length is not None and len(lines) >= length):
                continue
            line_bytes = len(line.encode("utf-8"))
            if not dropped and used + line_bytes <= budget:
                lines.append(line)
                used += line_bytes
                continue
            truncated = True
            if not lines:  # the first requested line alone is over the limit
                lines.append(_clip_to_budget(line, dropped, budget))
                clipped = True
    return {
        "path": str(resolved),
        "encoding": encoding,
        "content": "".join(lines),
        "start_line": start,
        "lines_returned": len(lines),
        "total_lines": total_lines,
        "size": size,
        "truncated": truncated,
        "line_clipped": clipped,
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
                # Bounded even if the file grew past the limit since the stat above.
                info["line_count"] = sum(1 for _ in _bounded_lines(fh, policy.max_read_bytes + 1))
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
    """Search text file contents under ``path``; binary and oversized files are skipped."""
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

    matches: list[dict[str, Any]] = []
    files_scanned = 0
    truncated = False
    for candidate, is_dir in candidates:
        if is_dir:
            continue
        if time.monotonic() > deadline or truncated:
            break
        if file_glob and not fnmatch.fnmatchcase(candidate.name.casefold(), file_glob):
            continue
        try:
            if not candidate.is_file():  # never open FIFOs or devices
                continue
            if candidate.stat().st_size > policy.max_read_bytes:
                continue
            encoding = _text_encoding(candidate)
            if encoding is None:
                continue
            with candidate.open("r", encoding=encoding, errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        files_scanned += 1
        for index, line in enumerate(lines):
            if not matcher.search(line):
                continue
            if len(matches) >= limit:
                truncated = True
                break
            hit: dict[str, Any] = {"path": str(candidate), "line": index + 1, "text": _clip(line)}
            if context_lines:
                lo = max(0, index - context_lines)
                hit["before"] = [_clip(x) for x in lines[lo:index]]
                hit["after"] = [_clip(x) for x in lines[index + 1 : index + 1 + context_lines]]
            matches.append(hit)
    timed_out = time.monotonic() > deadline
    return {
        "path": str(root),
        "matches": matches,
        "files_scanned": files_scanned,
        "truncated": truncated or timed_out,
        "timed_out": timed_out,
    }


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
