"""Path planning for opt-in, immutable fleet installations.

This module intentionally does not switch running services. Use it to validate
candidate paths before implementing the deployment transaction in fleet.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath

_SHA = re.compile(r"[0-9a-f]{40}\Z")


@dataclass(frozen=True)
class VersionPaths:
    current_checkout: str
    target_checkout: str
    previous_checkout: str


def version_paths(current_checkout: str, version_root: str, target_sha: str, *, windows: bool) -> VersionPaths:
    """Return paths without modifying either the filesystem or the fleet file.

    version_root is the parent of the `version` directory, e.g. C:/Omnilink
    or /home/jarvis/omnilink. Never derive it by trusting an arbitrary
    checkout path, and never accept a non-commit ref in a directory name.
    """
    if not _SHA.fullmatch(target_sha):
        raise ValueError("target must be a complete, lowercase 40-character commit SHA")
    if not current_checkout or not version_root:
        raise ValueError("current checkout and version root are required")

    path_type = PureWindowsPath if windows else PurePosixPath
    current = path_type(current_checkout)
    root = path_type(version_root)
    if not current.is_absolute() or not root.is_absolute():
        raise ValueError("checkout and version root must be absolute paths")

    target = root / "version" / target_sha
    if target == current:
        return VersionPaths(str(current), str(target), str(current))
    return VersionPaths(str(current), str(target), str(current))
