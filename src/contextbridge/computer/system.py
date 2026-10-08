"""Host description for the computer route."""

from __future__ import annotations

import getpass
import os
import platform
import shutil
import socket
import sys
import time
from typing import Any

import psutil

from .policy import ComputerPolicy


def system_info(policy: ComputerPolicy) -> dict[str, Any]:
    memory = psutil.virtual_memory()
    disks = []
    for root in policy.roots:
        try:
            usage = shutil.disk_usage(root)
        except OSError:
            continue
        disks.append({"root": str(root), "total_bytes": usage.total, "free_bytes": usage.free})
    try:
        user = getpass.getuser()
    except Exception:  # getuser raises varied errors when no login name is available
        user = None
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "user": user,
        "cpu_count": os.cpu_count(),
        "memory_total_bytes": memory.total,
        "memory_available_bytes": memory.available,
        "uptime_seconds": round(time.time() - psutil.boot_time()),
        "disks": disks,
        "policy": policy.summary(),
    }
