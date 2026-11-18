"""Behaviour that only a real Windows machine can show. Runs on the Windows CI job (Thanatos stand-in)."""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from helpers import REPO, python_cmd

from contextbridge.computer import commands, files
from contextbridge.computer.policy import PolicyViolation, load_policy
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


def _short_name(path: Path) -> str | None:
    buf = ctypes.create_unicode_buffer(1024)
    if not 0 < ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, len(buf)) < len(buf):
        return None
    alias = os.path.basename(buf.value)
    return alias if alias.lower() != path.name.lower() else None


def _short_alias(path: Path, fallback: str) -> str:
    """``path``'s 8.3 name; set with fsutil (needs admin) when the volume generated none."""
    alias = _short_name(path)
    if alias is None:
        subprocess.run(["fsutil", "file", "setshortname", str(path), fallback], capture_output=True)
        alias = _short_name(path)
    if alias is None:
        pytest.skip(f"cannot give {path.name} an 8.3 short name on this volume")
    return alias


def test_moves_by_short_name_cannot_reach_hidden_or_denied_files(workspace):
    state = workspace / "work" / "statefolder"
    state.mkdir()
    registry = state / "devices.json"
    registry.write_text("{}", encoding="utf-8")
    secret = workspace / "work" / ".env"
    secret.write_text("SECRET=1\n", encoding="utf-8")
    state_alias = _short_alias(state, "STATEF~1")
    registry_alias = _short_alias(registry, "DEVICE~1.JSO")
    secret_alias = _short_alias(secret, "ENV~1")
    policy = load_policy(
        {"filesystem": {"roots": [str(workspace)], "writable_roots": [str(workspace / "work")]}},
        hidden=(registry,),
    )
    with pytest.raises(PolicyViolation, match="denied"):
        files.move_file(policy, f"work/statefolder/{registry_alias}", "work/moved.json")
    with pytest.raises(PolicyViolation, match="protected"):
        files.move_file(policy, f"work/{state_alias}", "work/moved")
    with pytest.raises(PolicyViolation, match="denied"):
        files.move_file(policy, f"work/{secret_alias}", "work/moved.txt")
    assert registry.read_text(encoding="utf-8") == "{}"
    assert secret.read_text(encoding="utf-8") == "SECRET=1\n"


def test_moves_by_short_name_report_the_real_name(policy, workspace):
    plain = workspace / "work" / "longfilename.txt"
    plain.write_text("x", encoding="utf-8")
    alias = _short_alias(plain, "LONGFI~1.TXT")
    result = files.move_file(policy, f"work/{alias}", "work/renamed.txt")
    assert Path(result["source"]).name == "longfilename.txt"
    assert (workspace / "work" / "renamed.txt").read_text(encoding="utf-8") == "x"


def test_moving_a_junction_moves_the_link_not_its_target(policy, workspace):
    target = workspace / "work" / "target"
    target.mkdir()
    (target / "f.txt").write_text("x", encoding="utf-8")
    junction = workspace / "work" / "junction"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(target)], check=True, capture_output=True)
    files.move_file(policy, "work/junction", "work/moved")
    assert not os.path.lexists(junction)
    assert (target / "f.txt").read_text(encoding="utf-8") == "x"
    assert (workspace / "work" / "moved" / "f.txt").read_text(encoding="utf-8") == "x"


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


@pytest.mark.parametrize("trigger", [[], ["-AtLogOn"]], ids=["at-startup", "at-logon"])
def test_agent_task_relaunches_an_agent_that_exits(trigger):
    # Task Scheduler's restart-on-failure ignores a program that exits; only a repeating trigger brings it back.
    script = REPO / "scripts" / "install-agent.ps1"
    config = REPO / "configs" / "agent.windows.yaml"
    plan = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script),
         "-Config", str(config), "-Python", sys.executable, "-DryRun", *trigger],
        capture_output=True, text=True, timeout=120, check=True,
    ).stdout
    assert re.search(r"^Repeat\s*:\s*PT1M\s*$", plan, re.MULTILINE), plan


@pytest.mark.parametrize("preset", ["ReadOnly", "Full"])
def test_bootstrap_writes_a_config_the_agent_loads(tmp_path, preset):
    # The one-step installer generates agent.yaml itself; both presets must load and keep their promised limits.
    from contextbridge.remote.agent import load_agent_config

    script = REPO / "scripts" / "bootstrap-agent.ps1"
    plan = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script),
         "-GatewayUrl", "wss://agents.example.com", "-Name", "p70", "-Policy", preset,
         "-InstallDir", str(tmp_path / "cb"), "-DryRun"],
        capture_output=True, text=True, timeout=120, check=True,
    ).stdout
    assert "--- agent.yaml ---" in plan, plan
    configs = tmp_path / "configs"
    configs.mkdir()
    config_file = configs / "agent.yaml"
    config_file.write_text(plan.split("--- agent.yaml ---", 1)[1].lstrip(), encoding="utf-8")
    config = load_agent_config(config_file)
    assert config.name == "p70"
    assert config.gateway_url == "wss://agents.example.com"
    assert config.identity_path.resolve() == (tmp_path / "state" / "agent-identity.json").resolve()
    summary = config.policy.summary()
    if preset == "ReadOnly":
        assert summary["writable_roots"] == []
        assert summary["command_mode"] == "allowlist"
        assert summary["allow_kill"] is False
    else:
        assert summary["command_mode"] == "unrestricted"
        assert summary["allow_kill"] is True


def _bootstrap_dry_run(install_dir, *args):
    script = REPO / "scripts" / "bootstrap-agent.ps1"
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script),
         "-InstallDir", str(install_dir), "-DryRun", *args],
        capture_output=True, text=True, timeout=120,
    )


def _write_existing_install(install_dir, *, enrolled):
    (install_dir / "configs").mkdir(parents=True)
    (install_dir / "configs" / "agent.yaml").write_text(
        "# hand-written\r\nname: p70\r\n\r\ngateway:   # the VPS\r\n  url: wss://agents.example.net\r\n"
        "identity: ../state/agent-identity.json\r\naudit_log: ../audit/agent.audit.jsonl\r\n",
        encoding="utf-8",
    )
    if enrolled:
        (install_dir / "state").mkdir()
        (install_dir / "state" / "agent-identity.json").write_text("{}", encoding="utf-8")


def test_bootstrap_policy_rewrite_keeps_name_and_gateway(tmp_path):
    # Switching an enrolled machine's preset must not rename it after the computer: the identity is for the old name.
    _write_existing_install(tmp_path / "cb", enrolled=True)
    result = _bootstrap_dry_run(tmp_path / "cb", "-Policy", "Full", "-ForceConfig")
    assert result.returncode == 0, result.stderr
    config = result.stdout.split("--- agent.yaml ---", 1)[1]
    assert re.search(r"^name: p70$", config, re.MULTILINE), config
    assert re.search(r"^  url: wss://agents\.example\.net$", config, re.MULTILINE), config
    assert "mode: unrestricted" in config


def test_bootstrap_refuses_to_rename_an_enrolled_machine(tmp_path):
    _write_existing_install(tmp_path / "cb", enrolled=True)
    result = _bootstrap_dry_run(tmp_path / "cb", "-Policy", "Full", "-ForceConfig", "-Name", "laptop")
    assert result.returncode != 0
    assert "enrolled as 'p70'" in result.stdout + result.stderr


def test_bootstrap_custom_config_path_keeps_existing_enrollment(tmp_path):
    # A machine may run an existing config outside the install checkout.
    install_dir = tmp_path / "cb"
    external_dir = tmp_path / "agent-state"
    external_dir.mkdir()
    (external_dir / "identity.json").write_text("{}", encoding="utf-8")
    (external_dir / "agent.yaml").write_text(
        "name: p70\ngateway:\n  url: wss://agents.example.net\n"
        "identity: identity.json\naudit_log: audit.jsonl\n",
        encoding="utf-8",
    )
    result = _bootstrap_dry_run(
        install_dir, "-ConfigPath", str(external_dir / "agent.yaml")
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"keep {external_dir / 'agent.yaml'}" in result.stdout
    assert "already enrolled" in result.stdout
    assert "enroll as" not in result.stdout


def test_bootstrap_custom_config_path_rewrite_keeps_identity_location(tmp_path):
    install_dir = tmp_path / "cb"
    external_dir = tmp_path / "agent-state"
    external_dir.mkdir()
    (external_dir / "identity.json").write_text("{}", encoding="utf-8")
    (external_dir / "agent.yaml").write_text(
        "name: p70\ngateway:\n  url: wss://agents.example.net\n"
        "identity: identity.json\naudit_log: audit.jsonl\n",
        encoding="utf-8",
    )
    result = _bootstrap_dry_run(
        install_dir, "-ConfigPath", str(external_dir / "agent.yaml"),
        "-ForceConfig", "-Policy", "Full",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "already enrolled" in result.stdout
    config = result.stdout.split("--- agent.yaml ---", 1)[1]
    assert "name: p70" in config
    assert "wss://agents.example.net" in config
    assert (external_dir / "identity.json").as_posix() in config.replace("\\\\", "/")


def test_bootstrap_custom_config_path_new_install_keeps_state_in_install_dir(tmp_path):
    install_dir = tmp_path / "cb"
    external_dir = tmp_path / "custom"
    result = _bootstrap_dry_run(
        install_dir, "-ConfigPath", str(external_dir / "agent.yaml"),
        "-GatewayUrl", "wss://agents.example.net", "-Name", "p70",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    config = result.stdout.split("--- agent.yaml ---", 1)[1]
    assert (install_dir / "state" / "agent-identity.json").as_posix() in config.replace("\\\\", "/")
    assert (install_dir / "audit" / "agent.audit.jsonl").as_posix() in config.replace("\\\\", "/")


def test_permanently_deleting_a_junction_removes_the_link_not_its_target(make_policy, workspace):
    from contextbridge.computer.trash import delete_file

    policy = make_policy(filesystem={"delete": "permanent"})
    target = workspace / "work" / "target"
    target.mkdir()
    (target / "f.txt").write_text("x", encoding="utf-8")
    junction = workspace / "work" / "junction"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(target)], check=True, capture_output=True)
    result = delete_file(policy, "work/junction")
    assert result["type"] == "symlink" and result["entries"] == 0
    assert not os.path.lexists(junction)
    assert (target / "f.txt").read_text(encoding="utf-8") == "x"
