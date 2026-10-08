from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from contextbridge.computer.policy import ComputerPolicy, load_policy


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A readable root containing a writable subdirectory and some denied files."""
    root = tmp_path / "root"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "notes.md").write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("def main():\n    return 'hello'\n", encoding="utf-8")
    (root / ".ssh").mkdir()
    (root / ".ssh" / "id_ed25519").write_text("PRIVATE", encoding="utf-8")
    (root / ".env").write_text("SECRET=1\n", encoding="utf-8")
    (root / "work").mkdir()
    (tmp_path / "outside.txt").write_text("outside\n", encoding="utf-8")
    return root


@pytest.fixture
def make_policy(workspace: Path):
    def _make(**overrides: Any) -> ComputerPolicy:
        cfg: dict[str, Any] = {
            "filesystem": {"roots": [str(workspace)], "writable_roots": [str(workspace / "work")]},
            "commands": {"mode": "allowlist", "allow": ["echo", "ls", "sleep", "cat", "env"]},
            "processes": {"list": True, "allow_kill": False},
        }
        for section, values in overrides.items():
            cfg.setdefault(section, {}).update(values)
        return load_policy(cfg)

    return _make


@pytest.fixture
def policy(make_policy) -> ComputerPolicy:
    return make_policy()
