"""Filesystem operations for the ContextBridge filesystem route.

Every client path must be absolute. It is resolved with symlinks followed and must
land inside one of the configured roots. Writes need a writable root. Deleting
moves the item into the root's trash directory, which no tool can reach, so it can
be recovered.

Known limits: a symlink swapped in by another local process between the check and
the operation can still redirect it (only the final component is opened with
O_NOFOLLOW), and hard links that already exist inside a root are not detected.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import stat
import tempfile
import time
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

TRASH_DIR_NAME = ".contextbridge-trash"
DEFAULT_MAX_READ_BYTES = 1024 * 1024
DEFAULT_MAX_WRITE_BYTES = 1024 * 1024
DEFAULT_MAX_LIST_ENTRIES = 1000
DEFAULT_MAX_SEARCH_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_READ_LINES = 1000
DEFAULT_LIST_DEPTH = 2
MAX_LIST_DEPTH = 10
MAX_MULTI_READ_FILES = 50

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

_ERRNO_REASONS = {
    errno.ENOENT: ("not_found", "not found"),
    errno.EACCES: ("permission_denied", "permission denied"),
    errno.EPERM: ("permission_denied", "permission denied"),
    errno.EEXIST: ("exists", "already exists"),
    errno.ENOTDIR: ("not_a_directory", "not a directory"),
    errno.EISDIR: ("is_a_directory", "is a directory"),
    errno.ENOTEMPTY: ("not_empty", "directory not empty"),
    errno.EXDEV: ("cross_device", "crosses filesystems"),
    errno.ELOOP: ("symlink_loop", "too many levels of symbolic links"),
    errno.ENOSPC: ("no_space", "no space left on device"),
    errno.EROFS: ("read_only_fs", "read-only filesystem"),
}


class FsError(Exception):
    """A failed operation. The message is safe to return to the client."""

    def __init__(self, message: str, *, code: str = "invalid_request") -> None:
        super().__init__(message)
        self.code = code


class FsPathDenied(FsError):
    """The path is outside every root, inside a trash directory, or read-only."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="path_denied")


@contextlib.contextmanager
def _os_errors(label: str) -> Iterator[None]:
    """Turn an OSError into an FsError that names the client's path, not ours."""
    try:
        yield
    except OSError as exc:
        code, reason = _ERRNO_REASONS.get(exc.errno, ("os_error", "operation failed"))
        raise FsError(f"{label}: {reason}", code=code) from None


@dataclass(frozen=True)
class FsRoot:
    path: Path
    writable: bool = False

    @property
    def trash(self) -> Path:
        return self.path / TRASH_DIR_NAME

    def contains(self, path: Path) -> bool:
        return path == self.path or self.path in path.parents


@dataclass(frozen=True)
class FsLimits:
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES
    max_write_bytes: int = DEFAULT_MAX_WRITE_BYTES
    max_list_entries: int = DEFAULT_MAX_LIST_ENTRIES
    max_search_file_bytes: int = DEFAULT_MAX_SEARCH_FILE_BYTES


@dataclass(frozen=True)
class _Target:
    path: Path
    root: FsRoot


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    return "other"


def _open_regular(path: Path, label: str) -> BinaryIO:
    """Open a regular file for reading without following a final symlink."""
    with _os_errors(label):
        mode = os.stat(path).st_mode
        if stat.S_ISDIR(mode):
            raise FsError(f"{label}: is a directory", code="is_a_directory")
        if not stat.S_ISREG(mode):
            raise FsError(f"{label}: not a regular file", code="not_a_file")
        # O_NONBLOCK keeps a FIFO swapped in after the check from blocking open().
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise FsError(f"{label}: not a regular file", code="not_a_file")
    return os.fdopen(fd, "rb")


def _lines(fh: BinaryIO, label: str, max_bytes: int) -> Iterator[bytes]:
    """Yield lines with their endings, refusing any line over ``max_bytes``."""
    line_no = 0
    while True:
        line = fh.readline(max_bytes + 1)
        if not line:
            return
        if len(line) > max_bytes:
            raise FsError(
                f"{label}: line {line_no} is longer than the {max_bytes}-byte read limit",
                code="too_large",
            )
        line_no += 1
        yield line


def _decode(data: bytes, label: str) -> str:
    if b"\0" in data:
        raise FsError(f"{label}: not a UTF-8 text file", code="binary")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise FsError(f"{label}: not a UTF-8 text file", code="binary") from None


def _atomic_write(path: Path, data: bytes) -> None:
    """Replace ``path`` via a temporary file in the same directory.

    A new file is created directly so the process umask applies; an existing file
    keeps its permission bits.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, 0o666)
    except FileExistsError:
        fd = None
    if fd is not None:
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(path)
            raise
        return
    mode = stat.S_IMODE(os.stat(path).st_mode)
    tmp_fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class Filesystem:
    """Path-checked file operations over a fixed set of roots."""

    def __init__(self, roots: Sequence[FsRoot], limits: FsLimits | None = None) -> None:
        if not roots:
            raise ValueError("at least one filesystem root is required")
        self.roots = tuple(roots)
        self.limits = limits or FsLimits()

    @property
    def writable(self) -> bool:
        return any(root.writable for root in self.roots)

    def resolve(self, raw: str, *, write: bool = False, follow_final: bool = True) -> _Target:
        """Check ``raw`` against the roots and return its real path.

        With ``follow_final`` false a final symlink is kept as is, so moving or
        deleting it acts on the link rather than its target.
        """
        if not isinstance(raw, str) or not raw.strip():
            raise FsError("path must be a non-empty string")
        if "\0" in raw:
            raise FsPathDenied("path contains a NUL byte")
        try:
            candidate = Path(raw).expanduser()
        except RuntimeError:
            raise FsPathDenied(f"cannot expand home directory: {raw}") from None
        if not candidate.is_absolute():
            raise FsPathDenied(f"path must be absolute: {raw}")
        if follow_final or candidate.name in ("", ".."):
            real = Path(os.path.realpath(candidate))
        else:
            real = Path(os.path.realpath(candidate.parent)) / candidate.name
        root = next((r for r in self.roots if r.contains(real)), None)
        if root is None:
            raise FsPathDenied(f"path is outside the allowed directories: {raw}")
        if real == root.trash or root.trash in real.parents:
            raise FsPathDenied(f"path is reserved: {raw}")
        if write and not root.writable:
            raise FsPathDenied(f"path is in a read-only directory: {raw}")
        return _Target(real, root)

    # -- reading ----------------------------------------------------------------

    def _read_text(
        self, path: str, offset: int, length: int | None, max_bytes: int
    ) -> dict[str, Any]:
        length = DEFAULT_READ_LINES if length is None else length
        if length < 1:
            raise FsError("length must be at least 1")
        target = self.resolve(path)
        limit = self.limits.max_read_bytes
        with _open_regular(target.path, path) as fh, _os_errors(path):
            if offset >= 0:
                start = offset
            else:
                # Count first, then read forward: holding the last N lines would cost N lines of memory.
                total = sum(1 for _ in _lines(fh, path, limit))
                fh.seek(0)
                start = max(0, total + offset)
            selected: list[bytes] = []
            has_more = False
            for index, line in enumerate(_lines(fh, path, limit)):
                if index < start:
                    continue
                if len(selected) == length:
                    has_more = True
                    break
                selected.append(line)
        kept: list[bytes] = []
        used = 0
        for line in selected:
            if used + len(line) > max_bytes:
                has_more = True
                break
            kept.append(line)
            used += len(line)
        if selected and not kept:
            # Only reachable when read_multiple_files has used up most of its budget:
            # _lines already refused any single line over max_read_bytes.
            raise FsError(f"{path}: skipped: response size limit reached", code="too_large")
        return {
            "path": str(target.path),
            "content": _decode(b"".join(kept), path),
            "start_line": start,
            "line_count": len(kept),
            "has_more": has_more,
            "bytes": used,
        }

    def read_file(self, path: str, offset: int = 0, length: int | None = None) -> dict[str, Any]:
        """Read UTF-8 text by line. A negative ``offset`` reads the last lines."""
        return self._read_text(path, offset, length, self.limits.max_read_bytes)

    def read_multiple_files(self, paths: Sequence[str]) -> dict[str, Any]:
        """Read several files; one file's error does not fail the others."""
        if not paths:
            raise FsError("paths must list at least one file")
        if len(paths) > MAX_MULTI_READ_FILES:
            raise FsError(f"at most {MAX_MULTI_READ_FILES} files can be read at once")
        budget = self.limits.max_read_bytes
        files: list[dict[str, Any]] = []
        for path in paths:
            if budget <= 0:
                files.append({"path": path, "error": "skipped: response size limit reached"})
                continue
            try:
                result = self._read_text(path, 0, None, budget)
            except FsError as exc:
                files.append({"path": path, "error": str(exc)})
                continue
            budget -= result["bytes"]
            files.append(result)
        return {"files": files, "bytes": self.limits.max_read_bytes - budget}

    def list_directory(self, path: str, depth: int = DEFAULT_LIST_DEPTH) -> dict[str, Any]:
        """List entries up to ``depth`` levels deep without following symlinks."""
        if not 1 <= depth <= MAX_LIST_DEPTH:
            raise FsError(f"depth must be between 1 and {MAX_LIST_DEPTH}")
        target = self.resolve(path)
        with _os_errors(path):
            if not target.path.is_dir():
                raise FsError(f"{path}: not a directory", code="not_a_directory")
        entries: list[dict[str, Any]] = []
        limit = self.limits.max_list_entries
        truncated = False

        def walk(directory: Path, prefix: str, level: int) -> None:
            nonlocal truncated
            with os.scandir(directory) as it:
                children = sorted(it, key=lambda entry: entry.name)
            for child in children:
                if Path(child.path) == target.root.trash:
                    continue
                if len(entries) >= limit:
                    truncated = True
                    return
                item: dict[str, Any] = {
                    "path": prefix + child.name,
                    "type": _kind(child.stat(follow_symlinks=False).st_mode),
                }
                entries.append(item)
                if item["type"] == "directory" and level < depth:
                    try:
                        walk(Path(child.path), item["path"] + "/", level + 1)
                    except PermissionError:
                        item["error"] = "permission denied"
                    if truncated:
                        return

        with _os_errors(path):
            walk(target.path, "", 1)
        return {"path": str(target.path), "entries": entries, "truncated": truncated}

    def get_file_info(self, path: str) -> dict[str, Any]:
        """Size, timestamps, permissions and type, following symlinks."""
        link = self.resolve(path, follow_final=False)
        target = self.resolve(path)
        with _os_errors(path):
            st = os.stat(target.path)
            is_link = os.path.islink(link.path)
        return {
            "path": str(target.path),
            "type": _kind(st.st_mode),
            "size": st.st_size,
            "modified": _iso(st.st_mtime),
            "accessed": _iso(st.st_atime),
            "changed": _iso(st.st_ctime),
            "permissions": oct(stat.S_IMODE(st.st_mode))[2:],
            "is_symlink": is_link,
            "writable": target.root.writable,
        }

    # -- writing ----------------------------------------------------------------

    def _check_write_size(self, data: bytes) -> None:
        if len(data) > self.limits.max_write_bytes:
            raise FsError(
                f"content is larger than the {self.limits.max_write_bytes}-byte write limit",
                code="too_large",
            )

    def write_file(self, path: str, content: str, mode: str = "rewrite") -> dict[str, Any]:
        """Create or overwrite a file (atomically), or append to it."""
        if mode not in ("rewrite", "append"):
            raise FsError("mode must be 'rewrite' or 'append'")
        data = content.encode("utf-8")
        self._check_write_size(data)
        target = self.resolve(path, write=True)
        with _os_errors(path):
            if not target.path.parent.is_dir():
                raise FsError(f"{path}: parent directory does not exist", code="not_found")
            if os.path.lexists(target.path) and not target.path.is_file():
                raise FsError(f"{path}: not a regular file", code="not_a_file")
            if mode == "append":
                flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | _O_NOFOLLOW | _O_CLOEXEC
                with os.fdopen(os.open(target.path, flags, 0o666), "ab") as fh:
                    fh.write(data)
            else:
                _atomic_write(target.path, data)
        return {"path": str(target.path), "mode": mode, "bytes": len(data)}

    def edit_block(
        self, path: str, old_string: str, new_string: str, expected_replacements: int = 1
    ) -> dict[str, Any]:
        """Replace exact text; the number of matches must equal ``expected_replacements``."""
        if not old_string:
            raise FsError("old_string must not be empty")
        if expected_replacements < 1:
            raise FsError("expected_replacements must be at least 1")
        target = self.resolve(path, write=True)
        limit = self.limits.max_write_bytes
        with _open_regular(target.path, path) as fh, _os_errors(path):
            data = fh.read(limit + 1)
        if len(data) > limit:
            raise FsError(f"{path}: file is larger than the {limit}-byte edit limit", code="too_large")
        text = _decode(data, path)
        found = text.count(old_string)
        if found == 0:
            raise FsError(f"{path}: old_string not found", code="no_match")
        if found != expected_replacements:
            raise FsError(
                f"{path}: expected {expected_replacements} occurrence(s) of old_string, found "
                f"{found}; add surrounding text to make it unique or set expected_replacements",
                code="ambiguous",
            )
        updated = text.replace(old_string, new_string).encode("utf-8")
        self._check_write_size(updated)
        with _os_errors(path):
            _atomic_write(target.path, updated)
        return {"path": str(target.path), "replacements": found, "bytes": len(updated)}

    def create_directory(self, path: str) -> dict[str, Any]:
        """Create a directory and any missing parents."""
        target = self.resolve(path, write=True)
        with _os_errors(path):
            if os.path.lexists(target.path) and not target.path.is_dir():
                raise FsError(f"{path}: already exists and is not a directory", code="exists")
            existed = target.path.is_dir()
            os.makedirs(target.path, exist_ok=True)
        return {"path": str(target.path), "created": not existed}

    def move_file(self, source: str, destination: str) -> dict[str, Any]:
        """Move or rename a file or directory. Never overwrites the destination."""
        src = self.resolve(source, write=True, follow_final=False)
        dst = self.resolve(destination, write=True, follow_final=False)
        if src.path == src.root.path:
            raise FsError(f"{source}: an allowed directory itself cannot be moved")
        with _os_errors(source):
            if not os.path.lexists(src.path):
                raise FsError(f"{source}: not found", code="not_found")
        with _os_errors(destination):
            if os.path.lexists(dst.path):
                raise FsError(f"{destination}: already exists", code="exists")
            if not dst.path.parent.is_dir():
                raise FsError(f"{destination}: parent directory does not exist", code="not_found")
        if src.path in dst.path.parents:
            raise FsError(f"{destination}: cannot move a directory into itself")
        # os.rename replaces a destination created after the check above; the
        # stdlib has no portable no-replace rename.
        with _os_errors(source):
            os.rename(src.path, dst.path)
        return {"source": str(src.path), "destination": str(dst.path)}

    def delete_file(self, path: str, recursive: bool = False) -> dict[str, Any]:
        """Move a file, symlink or directory into the root's trash.

        A non-empty directory needs ``recursive``. The item keeps its name under
        ``<root>/.contextbridge-trash/<trash_id>/``, next to ``<trash_id>.json``
        recording where it came from.
        """
        target = self.resolve(path, write=True, follow_final=False)
        if target.path == target.root.path:
            raise FsError(f"{path}: an allowed directory itself cannot be deleted")
        with _os_errors(path):
            kind = _kind(os.lstat(target.path).st_mode)
            if kind == "directory" and not recursive:
                with os.scandir(target.path) as it:
                    if next(it, None) is not None:
                        raise FsError(
                            f"{path}: directory is not empty; set recursive to delete it",
                            code="not_empty",
                        )
            trash_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex[:8]}"
            holder = target.root.trash / trash_id
            os.makedirs(target.root.trash, mode=0o700, exist_ok=True)
            os.mkdir(holder, 0o700)
            try:
                os.rename(target.path, holder / target.path.name)
            except OSError:
                with contextlib.suppress(OSError):
                    os.rmdir(holder)
                raise
            manifest = {"original_path": str(target.path), "type": kind, "deleted_at": _iso(time.time())}
            with contextlib.suppress(OSError):
                (target.root.trash / f"{trash_id}.json").write_text(
                    json.dumps(manifest) + "\n", encoding="utf-8"
                )
        return {
            "path": str(target.path),
            "type": kind,
            "trash_id": trash_id,
            "trash_path": str(holder / target.path.name),
        }


# -- configuration ----------------------------------------------------------------

_ROOT_KEYS = frozenset({"path", "writable"})
_LIMIT_KEYS = ("max_read_bytes", "max_write_bytes", "max_list_entries", "max_search_file_bytes")


def filesystem_from_config(section: Any, *, config_path: Path) -> Filesystem:
    """Build a Filesystem from the ``filesystem`` config section.

    Roots must exist, must not overlap, and are read-only unless ``writable: true``.
    A relative root path is resolved against the config file's directory.
    """
    if not isinstance(section, dict):
        raise ValueError("filesystem: section is required")
    unknown = set(section) - {"roots", *_LIMIT_KEYS}
    if unknown:
        raise ValueError(f"filesystem: unknown key(s): {', '.join(sorted(unknown))}")
    entries = section.get("roots")
    if not isinstance(entries, list) or not entries:
        raise ValueError("filesystem.roots must list at least one directory")
    base = config_path.resolve().parent
    roots: list[FsRoot] = []
    for index, entry in enumerate(entries):
        where = f"filesystem.roots[{index}]"
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError(f"{where}: must be a mapping with a 'path' string")
        unknown = set(entry) - _ROOT_KEYS
        if unknown:
            raise ValueError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
        writable = entry.get("writable", False)
        if not isinstance(writable, bool):
            raise ValueError(f"{where}.writable must be true or false")
        path = Path(entry["path"]).expanduser()
        if not path.is_absolute():
            path = base / path
        if not path.is_dir():
            raise ValueError(f"{where}: directory not found: {path}")
        roots.append(FsRoot(Path(os.path.realpath(path)), writable))
    for i, a in enumerate(roots):
        for b in roots[i + 1 :]:
            if a.contains(b.path) or b.contains(a.path):
                raise ValueError(f"filesystem.roots overlap: {a.path} and {b.path}")
    limits: dict[str, int] = {}
    for key in _LIMIT_KEYS:
        if key in section:
            value = section[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"filesystem.{key} must be a positive integer")
            limits[key] = value
    return Filesystem(roots, FsLimits(**limits))
