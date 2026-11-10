"""Process hardening shared by every ContextBridge server."""

from __future__ import annotations

import ctypes
import sys

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
