"""Process hardening shared by every ContextBridge server."""

from __future__ import annotations

import ctypes
import os
import stat
import sys
from pathlib import Path
from typing import TextIO

_PR_SET_DUMPABLE = 4


def protect_process_secrets() -> bool:
    """Stop other processes of the same user reading this process's environment and memory.

    The route tokens arrive in the environment, and ``/proc/<pid>/environ`` shows a
    process's starting environment to anything running as the same user. A command
    as ordinary as ``ps e`` prints it, so stripping the tokens from child processes
    is not enough. Marking the process non-dumpable (``prctl(PR_SET_DUMPABLE, 0)``)
    makes the kernel hand ``/proc/<pid>/environ``, ``mem``, and friends to root only.

    Linux only; returns whether the protection is in place. Side effects: the process
    writes no core dumps, and attaching a debugger or profiler to it needs root.
    Programs it starts are unaffected (the flag resets on exec).
    """
    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def open_private_log(path: str | Path) -> TextIO:
    """Open ``path`` for appending text, readable and writable by this user only (mode 0600).

    Audit logs hold commands and paths verbatim, so they are created 0600, and an
    existing log is tightened to 0600 as well. A symlink or a non-regular file is
    refused. On Windows the mode only controls the read-only flag; privacy there comes
    from the directory the log lives in (the user's profile by default).
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not hasattr(os, "O_NOFOLLOW") and p.is_symlink():  # Windows: nothing to pass os.open
        raise OSError(f"audit log is a symlink: {p}")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(p, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"audit log is not a regular file: {p}")
        # The mode passed to os.open only applies when the file is created.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:  # Windows before Python 3.13; there the mode only sets the read-only flag
            os.chmod(p, 0o600)
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "a", buffering=1, encoding="utf-8")
