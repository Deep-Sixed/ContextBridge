"""Desktop capability is intentionally opt-in and read-only in Phase 2a."""
from unittest.mock import patch

import pytest

from contextbridge.computer.desktop import DesktopUnavailable, list_windows


def test_default_denied_without_touching_desktop():
    with patch("contextbridge.computer.desktop._linux_windows") as inspect:
        with pytest.raises(PermissionError, match="disabled"):
            list_windows()
        inspect.assert_not_called()


def test_authorized_linux_window_inventory():
    with patch("contextbridge.computer.desktop.os.name", "posix"):
        with patch("contextbridge.computer.desktop._linux_windows", return_value=[{"id": "0x1", "title": "Editor"}]):
            assert list_windows(authorized=True) == {
                "windows": [{"id": "0x1", "title": "Editor"}],
                "count": 1,
            }


def test_headless_linux_refuses_capture(monkeypatch):
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    with patch("contextbridge.computer.desktop.os.name", "posix"):
        with pytest.raises(DesktopUnavailable, match="no graphical"):
            list_windows(authorized=True)


def test_linux_parser_caps_results(monkeypatch):
    from contextbridge.computer import desktop
    monkeypatch.setenv("DISPLAY", ":1")
    fake = type("Run", (), {"stdout": "0x01  0 host Example Window\ninvalid line\n"})()
    with patch.object(desktop.shutil, "which", return_value="/usr/bin/wmctrl"):
        with patch.object(desktop.subprocess, "run", return_value=fake) as run:
            assert desktop._linux_windows() == [{"id": "0x01", "title": "Example Window"}]
            assert run.call_args.args[0] == ["wmctrl", "-l"]
