"""Behaviour that only a real Windows machine can show. Runs on the Windows CI job (Thanatos stand-in)."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import psutil
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from helpers import python_cmd

from contextbridge.computer import commands, files
from contextbridge.computer.policy import PolicyViolation
from contextbridge.computer.proctree import ProcessTree
from contextbridge.remote.agent import Identity

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows only")

_SPAWN_AND_EXIT = (
    "import subprocess, sys; "
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
    "print(p.pid, flush=True)"
)


def _gone(pid: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not psutil.pid_exists(pid):
            return True
        try:
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return True
        except psutil.NoSuchProcess:
            return True
        time.sleep(0.1)
    return False


def test_processes_are_contained_in_a_job(tmp_path):
    tree = ProcessTree(
        [sys.executable, "-c", "print('x')"],
        cwd=tmp_path,
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert tree.contained is True
        out, _ = tree.proc.communicate(timeout=30)
        assert out.strip() == b"x"
    finally:
        tree.release()


def test_commands_leave_nothing_running(policy):
    """On Windows the job closes with the command, so a background child cannot outlive it."""
    result = commands.run_command(policy, python_cmd(_SPAWN_AND_EXIT))
    assert result["exit_code"] == 0
    assert _gone(int(result["stdout"].split()[0])), "a background child outlived its command"


def test_batch_files_are_refused_in_allowlist_mode(make_policy, tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "deploy.bat").write_text("@echo deployed\r\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    policy = make_policy(commands={"allow": ["deploy"]})
    with pytest.raises(PolicyViolation, match=r"\.exe or \.com"):
        commands.run_command(policy, "deploy")


def test_programs_in_the_working_directory_are_not_found(make_policy, workspace):
    """CreateProcess would search the cwd first; ContextBridge resolves on PATH only."""
    planted = workspace / "work" / "whoami.exe"
    planted.write_bytes(b"MZ")  # not a real program; it must never be chosen
    policy = make_policy(commands={"allow": ["whoami"]})
    result = commands.run_command(policy, "whoami", cwd=str(workspace / "work"))
    assert result["exit_code"] == 0 and result["stdout"].strip()


def test_alternate_data_streams_and_device_names_are_refused(policy, workspace):
    notes = workspace / "docs" / "notes.md"
    with open(f"{notes}:secret", "w", encoding="utf-8") as fh:
        fh.write("hidden stream")
    for raw in ("docs/notes.md:secret", "docs/notes.md::$DATA", "docs/CON", "docs/nul.txt", ".env.", ".env "):
        with pytest.raises(PolicyViolation):
            files.read_file(policy, raw)
    assert files.read_file(policy, "docs/notes.md")["content"].startswith("alpha")


def test_deny_patterns_ignore_case(policy):
    for raw in (".SSH/id_ed25519", ".Env"):
        with pytest.raises(PolicyViolation):
            files.read_file(policy, raw)


def test_powershell_commands_and_utf8_output(make_policy):
    policy = make_policy(commands={"mode": "unrestricted", "shell": "powershell"})
    result = commands.run_command(policy, "Write-Output 'héllo wörld'; exit 3")
    assert result["stdout"].strip() == "héllo wörld"
    assert result["exit_code"] == 3


def test_cmd_shell(make_policy):
    policy = make_policy(commands={"mode": "unrestricted", "shell": "cmd"})
    result = commands.run_command(policy, "echo one& echo two")
    assert result["stdout"].split() == ["one", "two"]


def test_identity_file_is_restricted_to_the_user(tmp_path):
    path = tmp_path / "state" / "identity.json"
    Identity("dev_1", "thanatos", "gw_1", Ed25519PrivateKey.generate()).save(path)
    acl = subprocess.run(["icacls", str(path)], capture_output=True, text=True, check=True).stdout
    assert "(I)" not in acl, acl  # nothing inherited from the folder
    assert "NT AUTHORITY\\SYSTEM" in acl, acl
    assert "BUILTIN\\Users" not in acl, acl
    assert Identity.load(path).device_id == "dev_1"


def test_critical_windows_processes_cannot_be_killed():
    lsass = next(p for p in psutil.process_iter(["name"]) if (p.info["name"] or "").lower() == "lsass.exe")
    with pytest.raises(PolicyViolation, match="critical"):
        commands.kill_process(lsass.pid)
