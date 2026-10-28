"""Native deletion: ``delete_file``, ``list_deleted``, and ``restore_deleted``.

``filesystem.delete`` chooses what deleting means on a device:

* ``trash`` (default): the item moves to ``.contextbridge-trash/<id>/`` inside the
  writable root that held it, with a ``<id>.json`` manifest beside it, and
  ``restore_deleted`` puts it back. No file tool can reach the trash, so a client
  cannot make its own deletions permanent; the owner empties it on the host.
  The layout matches the filesystem route's (``uga.fs``), so either route's
  deletions in a shared folder can be listed and restored here.
* ``permanent``: the item is removed outright.
* ``disabled``: there is no delete tool.

Whatever the mode, deletion only happens inside writable roots and never touches
a root, a protected or hidden path, or a folder holding anything the file tools
may not see (a ``.ssh`` or ``.env`` inside, say). Folders need ``recursive=true``
and are capped at ``filesystem.max_delete_entries`` entries.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any

from .audit import mark_started
from .files import FileOperationError
from .policy import TRASH_DIRNAME, ComputerPolicy, PolicyViolation

_TRASH_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")


def _kind(path: Path) -> str:
    if path.is_symlink():
        return "symlink"
    if path.is_dir():
        return "directory"
    return "file"


def _inventory(policy: ComputerPolicy, target: Path, raw: str) -> tuple[str, int, int]:
    """(kind, entries inside, bytes). Refuses a folder holding anything the file tools may not touch."""
    kind = _kind(target)
    if kind != "directory":
        return kind, 0, 0 if kind == "symlink" else target.stat().st_size
    entries = size = 0
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        for name in (*dirnames, *filenames):
            child = Path(dirpath) / name
            entries += 1
            if policy.is_untouchable(child):
                rel = child.relative_to(target)
                raise PolicyViolation(f"{raw} contains {rel}, which ContextBridge may not touch; nothing was deleted.")
            if entries > policy.max_delete_entries:
                raise FileOperationError(
                    f"{raw} holds more than {policy.max_delete_entries} entries (filesystem.max_delete_entries); "
                    "nothing was deleted."
                )
            if name in filenames:
                try:
                    size += child.lstat().st_size
                except OSError:
                    pass
    return kind, entries, size


def _force_remove(func, path, _exc) -> None:
    """Retry once after clearing a read-only bit (Windows refuses to delete read-only files)."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _remove_tree(path: Path) -> None:
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_force_remove)
    else:  # pragma: no cover - exercised on 3.11
        shutil.rmtree(path, onerror=_force_remove)


def delete_file(policy: ComputerPolicy, path: str, *, recursive: bool = False) -> dict[str, Any]:
    if not policy.can_delete:
        raise PolicyViolation("Deleting is disabled on this computer.")
    target = policy.resolve(path, write=True, follow_symlinks=False)
    if not os.path.lexists(target):
        raise FileNotFoundError(f"No such file or directory: {path}")
    policy.guard_move(target)  # never a root, never a folder holding protected paths
    kind, entries, size = _inventory(policy, target, path)
    if kind == "directory" and entries and not recursive:
        raise FileOperationError(
            f"{path} is a folder with {entries} entries; pass recursive=true to delete it and everything in it."
        )
    result: dict[str, Any] = {"path": str(target), "type": kind, "entries": entries, "bytes": size}

    if policy.delete_mode == "permanent":
        mark_started(path=str(target), mode="permanent", entries=entries)
        if kind == "directory":
            _remove_tree(target)
        else:
            target.unlink()
        return {**result, "mode": "permanent", "restorable": False}

    root = policy.writable_root_for(target)
    if root is None:  # resolve(write=True) guarantees one; never act on an unexpected path
        raise PolicyViolation(f"{path} is outside the writable roots of this computer.")
    trash = root / TRASH_DIRNAME
    trash_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{secrets.token_hex(4)}"
    holder = trash / trash_id
    manifest = trash / f"{trash_id}.json"
    mark_started(path=str(target), mode="trash", entries=entries, trash_id=trash_id)
    trash.mkdir(mode=0o700, exist_ok=True)
    holder.mkdir(mode=0o700)
    manifest.write_text(
        json.dumps(
            {
                "trash_id": trash_id,
                "original_path": str(target),
                "name": target.name,
                "type": kind,
                "entries": entries,
                "bytes": size,
                "deleted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    try:
        shutil.move(str(target), str(holder / target.name))
    except BaseException:
        manifest.unlink(missing_ok=True)
        shutil.rmtree(holder, ignore_errors=True)
        raise
    return {**result, "mode": "trash", "trash_id": trash_id, "restorable": True}


def _manifests(policy: ComputerPolicy) -> list[tuple[Path, dict[str, Any]]]:
    found = []
    for root in policy.writable_roots:
        trash = root / TRASH_DIRNAME
        if not trash.is_dir():
            continue
        for manifest in trash.glob("*.json"):
            if not _TRASH_ID.match(manifest.stem):
                continue
            try:
                record = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(record, dict) or not isinstance(record.get("original_path"), str):
                continue
            # The filesystem route's manifests carry less: derive what they leave out.
            record = {"trash_id": manifest.stem, "name": Path(record["original_path"]).name, **record}
            if os.path.lexists(trash / manifest.stem / record["name"]):
                found.append((trash, record))
    return found


def list_deleted(policy: ComputerPolicy, *, limit: int = 50) -> dict[str, Any]:
    if policy.delete_mode != "trash":
        raise PolicyViolation("This computer deletes permanently or not at all; there is no trash.")
    mark_started()
    rows = sorted((record for _, record in _manifests(policy)), key=lambda r: r.get("trash_id", ""), reverse=True)
    limit = max(1, min(int(limit), 500))
    items = [
        {
            **{k: r.get(k) for k in ("trash_id", "original_path", "type", "entries", "bytes", "deleted_at")},
            "original_exists": os.path.lexists(str(r.get("original_path", ""))),
        }
        for r in rows[:limit]
    ]
    return {"items": items, "total": len(rows), "truncated": len(rows) > limit}


def restore_deleted(policy: ComputerPolicy, trash_id: str) -> dict[str, Any]:
    if policy.delete_mode != "trash":
        raise PolicyViolation("This computer deletes permanently or not at all; there is no trash.")
    if not isinstance(trash_id, str) or not _TRASH_ID.match(trash_id):
        raise FileOperationError(f"{trash_id!r} is not a trash id; see list_deleted.")
    match = next(((trash, r) for trash, r in _manifests(policy) if r.get("trash_id") == trash_id), None)
    if match is None:
        raise FileNotFoundError(f"Nothing in the trash has id {trash_id}; see list_deleted.")
    trash, record = match
    original = str(record["original_path"])
    destination = policy.resolve(original, write=True, follow_symlinks=False)  # still allowed today?
    if os.path.lexists(destination):
        raise FileOperationError(f"{original} exists again; move it aside before restoring.")
    if not destination.parent.is_dir():
        raise FileOperationError(f"The folder {destination.parent} no longer exists; create or restore it first.")
    item = trash / trash_id / str(record["name"])
    mark_started(path=str(destination), trash_id=trash_id)
    shutil.move(str(item), str(destination))
    (trash / f"{trash_id}.json").unlink(missing_ok=True)
    shutil.rmtree(trash / trash_id, ignore_errors=True)
    return {"path": str(destination), "trash_id": trash_id, "type": record.get("type"), "restored": True}
