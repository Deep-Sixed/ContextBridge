"""Read-only project-to-host-to-repository registry.

A registry is user-configured metadata. It does not grant filesystem access,
GitHub authentication, remote device permissions, or execution capabilities.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class RegistryError(ValueError):
    pass


def load_registry(path: str | Path) -> dict:
    """Load bounded metadata, rejecting ambiguous mappings and unsafe URLs."""
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != {"projects"}:
        raise RegistryError("registry requires only a projects list")
    raw = payload["projects"]
    if not isinstance(raw, list) or len(raw) > 500:
        raise RegistryError("projects must be a list of at most 500 entries")
    projects = []
    names = set()
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != {"name", "host", "path", "github"}:
            raise RegistryError("each project requires name, host, path and github")
        name, host, location, github = (entry[k] for k in ("name", "host", "path", "github"))
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise RegistryError("invalid project name")
        if not isinstance(host, str) or not _NAME.fullmatch(host):
            raise RegistryError("invalid host")
        if not isinstance(location, str) or not location.strip() or "\x00" in location:
            raise RegistryError("invalid location")
        if not isinstance(github, str) or not _REPO.fullmatch(github):
            raise RegistryError("github must be owner/repository")
        if name.casefold() in names:
            raise RegistryError("duplicate project name")
        names.add(name.casefold())
        projects.append({"name": name, "host": host, "path": location, "github": github})
    return {"projects": projects, "count": len(projects), "authoritative": False}
