"""Shared helpers for tests that run real processes, on Linux and Windows."""

from __future__ import annotations

import os
import shlex
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import anyio
import pytest
from fastmcp import Client
from fastmcp.client.auth import BearerAuth

REPO = Path(__file__).resolve().parents[1]
IS_WINDOWS = os.name == "nt"
PY = Path(sys.executable).stem  # the allowlist name of this interpreter ("python" in CI and venvs)

# Variables Windows programs (including Python's ssl and random) need to start at all.
_WINDOWS_ENV = (
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "USERNAME",
    "USERDOMAIN",
)


def symlink_or_skip(link: Path, target: Path) -> Path:
    """Create a symlink, or skip when the OS will not let this user create one (Windows without the privilege)."""
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"cannot create symlinks here: {exc}")
    return link


def cmdline(*args: str) -> str:
    """A command line that splits back into ``args`` on this platform."""
    return subprocess.list2cmdline(args) if IS_WINDOWS else shlex.join(args)


def python_cmd(code: str) -> str:
    """A command running ``code`` with this interpreter, by its allowlist name."""
    return cmdline(PY, "-c", code)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def isolated_env(**extra: str) -> dict[str, str]:
    """Minimal environment: this Python, the OS's own binaries, and nothing else (no Node, no npx)."""
    python_dir = str(Path(sys.executable).parent)
    if IS_WINDOWS:
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        env = {k: os.environ[k] for k in _WINDOWS_ENV if k in os.environ}
        env["PATH"] = os.pathsep.join([python_dir, os.path.join(system_root, "System32"), system_root])
    else:
        env = {"PATH": os.pathsep.join([python_dir, "/usr/bin", "/bin"]), "HOME": os.environ.get("HOME", "/tmp")}
        env["LANG"] = "C.UTF-8"
    env["PYTHONPATH"] = str(REPO / "src")
    env.update(extra)
    return env


@contextmanager
def serve(module: str, config: Path, port: int, env: dict[str, str]) -> Iterator[str]:
    proc = subprocess.Popen(
        [sys.executable, "-m", module, "--config", str(config)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 60
        while True:
            if proc.poll() is not None:
                raise AssertionError(f"{module} exited early:\n{proc.stderr.read()}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise AssertionError(f"{module} did not start listening on {port}") from None
                time.sleep(0.1)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def call(url: str, token: str | None, fn):
    async def inner():
        async with Client(url, auth=BearerAuth(token) if token else None) as client:
            return await fn(client)

    return anyio.run(inner)


def cli(module: str, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", module, *args], env=env, capture_output=True, text=True, timeout=120, check=False
    )
