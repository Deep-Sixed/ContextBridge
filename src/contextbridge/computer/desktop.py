"""Opt-in desktop discovery, separate from filesystem and process permissions.

No capture, input injection, focus changes, or desktop operation occurs here.
The caller must explicitly grant desktop discovery before calling this module.
"""
from __future__ import annotations

import os
import shutil
import subprocess


class DesktopUnavailable(RuntimeError):
    """No supported interactive desktop is available."""


def _linux_windows() -> list[dict[str, str]]:
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        raise DesktopUnavailable("no graphical desktop session")
    if not shutil.which("wmctrl"):
        raise DesktopUnavailable("wmctrl is not installed")
    try:
        result = subprocess.run(
            ["wmctrl", "-l"], capture_output=True, text=True, timeout=3,
            check=True, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DesktopUnavailable("window inventory unavailable") from exc
    windows = []
    for line in result.stdout.splitlines()[:200]:
        columns = line.split(None, 3)
        if len(columns) == 4 and columns[0].startswith("0x"):
            windows.append({"id": columns[0], "title": columns[3][:256]})
    return windows


def _windows_windows() -> list[dict[str, str]]:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    if not user32.GetProcessWindowStation():
        raise DesktopUnavailable("interactive window station unavailable")
    windows: list[dict[str, str]] = []
    CALLBACK = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @CALLBACK
    def callback(hwnd: int, _param: int) -> bool:
        if len(windows) >= 200:
            return False
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buffer = ctypes.create_unicode_buffer(min(length + 1, 257))
        user32.GetWindowTextW(hwnd, buffer, len(buffer))
        if buffer.value:
            windows.append({"id": str(hwnd), "title": buffer.value[:256]})
        return True

    user32.EnumWindows(callback, 0)
    return windows


def list_windows(*, authorized: bool = False) -> dict:
    """Return bounded window metadata only after explicit host authorization."""
    if authorized is not True:
        raise PermissionError("desktop discovery is disabled")
    windows = _windows_windows() if os.name == "nt" else _linux_windows()
    return {"windows": windows, "count": len(windows)}
