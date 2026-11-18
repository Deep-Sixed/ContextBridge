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


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                   cwd=cwd, check=True, capture_output=True)


@pytest.mark.parametrize("edited", [False, True], ids=["example-untouched", "edited-by-older-install"])
def test_bootstrap_moves_an_older_install_config_off_the_tracked_example(tmp_path, edited):
    # The repository ships configs/agent.yaml as an example. An older installer wrote the machine's config over it,
    # so upgrades collided with the tracked file; the installer now keeps it in configs/agent.local.yaml instead.
    install = tmp_path / "cb"
    (install / "configs").mkdir(parents=True)
    example = install / "configs" / "agent.yaml"
    example.write_text("name: example\ngateway:\n  url: wss://example.invalid\n", encoding="utf-8")
    _git(install, "init", "-q")
    _git(install, "add", "configs/agent.yaml")
    _git(install, "commit", "-q", "-m", "example")
    if edited:
        example.write_text("name: p70\ngateway:\n  url: wss://agents.example.net\n", encoding="utf-8")
    result = _bootstrap_dry_run(install, "-Policy", "Full", "-ForceConfig")
    assert result.returncode == 0, result.stderr
    plan = result.stdout
    config = plan.split("--- agent.yaml ---", 1)[1]
    if edited:
        assert re.search(r"^Migrate\s*:\s*move .*agent\.yaml to .*agent\.local\.yaml", plan, re.MULTILINE), plan
        assert re.search(r"^name: p70$", config, re.MULTILINE), config
    else:
        # The untouched example is not this machine's config: nothing to move, and its name is not reused.
        assert re.search(r"^Migrate\s*:\s*none", plan, re.MULTILINE), plan
        assert not re.search(r"^name: example$", config, re.MULTILINE), config
    assert re.search(r"^Config\s*:\s*write .*agent\.local\.yaml", plan, re.MULTILINE), plan
    assert example.exists(), "a dry run must not move anything"


@pytest.fixture
def logon_task():
    # A throwaway scheduled task that starts at sign-in, as install-agent.ps1 -AtLogOn registers one.
    name = f"ContextBridge test {os.getpid()}"
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "$u = [Security.Principal.WindowsIdentity]::GetCurrent().Name; "
         "Register-ScheduledTask -TaskName $env:CB_TASK -Force "
         "-Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c exit 0') "
         "-Trigger (New-ScheduledTaskTrigger -AtLogOn -User $u) "
         "-Principal (New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive) | Out-Null"],
        env={**os.environ, "CB_TASK": name}, check=True, capture_output=True, timeout=120,
    )
    yield name
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "Unregister-ScheduledTask -TaskName $env:CB_TASK -Confirm:$false"],
        env={**os.environ, "CB_TASK": name}, capture_output=True, timeout=120,
    )


def test_bootstrap_rerun_keeps_the_existing_task_trigger(tmp_path, logon_task):
    # Re-running without -AtLogOn must not move an at-sign-in agent to a boot task, which has no desktop session;
    # -AtStartup switches it on purpose.
    install = tmp_path / "cb"
    _write_existing_install(install, enrolled=True)
    kept = _bootstrap_dry_run(install, "-TaskName", logon_task)
    assert kept.returncode == 0, kept.stderr
    assert re.search(r"^Trigger\s*:\s*AtLogOn \(kept from the existing task\)", kept.stdout, re.MULTILINE), kept.stdout
    assert re.search(r"^RunLevel\s*:\s*Limited \(kept from the existing task\)", kept.stdout, re.MULTILINE), kept.stdout
    # Run as people run it, through powershell -File, where -AtLogOn:$false would arrive as the text "$false".
    switched = _bootstrap_dry_run(install, "-TaskName", logon_task, "-AtStartup")
    assert switched.returncode == 0, switched.stderr
    assert re.search(r"^Trigger\s*:\s*AtStartup\s*$", switched.stdout, re.MULTILINE), switched.stdout
    assert re.search(r"^RunLevel\s*:\s*Limited \(kept from the existing task\)", switched.stdout, re.MULTILINE)
    both = _bootstrap_dry_run(install, "-TaskName", logon_task, "-AtStartup", "-AtLogOn")
    assert both.returncode != 0 and "not both" in both.stdout + both.stderr


def test_bootstrap_prefers_an_existing_local_config(tmp_path):
    install = tmp_path / "cb"
    _write_existing_install(install, enrolled=True)
    (install / "configs" / "agent.local.yaml").write_text(
        "name: p70\ngateway:\n  url: wss://agents.example.org\n", encoding="utf-8")
    result = _bootstrap_dry_run(install, "-Policy", "Full", "-ForceConfig")
    assert result.returncode == 0, result.stderr
    assert re.search(r"^Migrate\s*:\s*none", result.stdout, re.MULTILINE), result.stdout
    assert "wss://agents.example.org" in result.stdout.split("--- agent.yaml ---", 1)[1]


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


def test_doctor_finds_and_reads_a_real_agent_task(tmp_path):
    # The doctor's PowerShell query against Task Scheduler, on a task registered the way install-agent.ps1 does.
    from contextbridge import doctor

    name = f"ContextBridge doctor test {os.getpid()}"
    config = tmp_path / "my agent.yaml"
    script = (
        "$u = [Security.Principal.WindowsIdentity]::GetCurrent().Name; "
        "$a = New-ScheduledTaskAction -Execute $env:CB_EXE -Argument ('-m contextbridge.remote.agent run --config \"' + $env:CB_CONFIG + '\"'); "
        "$t1 = New-ScheduledTaskTrigger -AtLogOn -User $u; "
        "$t2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(1) -RepetitionInterval (New-TimeSpan -Minutes 1); "
        "$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew "
        "-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; "
        "Register-ScheduledTask -TaskName $env:CB_TASK -Force -Action $a -Trigger $t1, $t2 -Settings $s "
        "-Principal (New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive) | Out-Null"
    )
    env = {**os.environ, "CB_TASK": name, "CB_EXE": sys.executable, "CB_CONFIG": str(config)}
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], env=env, check=True, capture_output=True, timeout=120)
    try:
        (task,) = [t for t in doctor.windows_tasks() if t.name == name]
        assert Path(task.config) == config  # the quoted path with a space survives
        assert task.details["multiple"] == "IgnoreNew" and task.details["limit"] == "PT0S"
        (finding,) = doctor.task_findings(task, config)
        assert finding.status == "ok", finding
    finally:
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                        "Unregister-ScheduledTask -TaskName $env:CB_TASK -Confirm:$false"], env=env, capture_output=True, timeout=120)


def test_bootstrap_activates_in_the_browser_when_given_a_server_and_no_code(tmp_path):
    result = _bootstrap_dry_run(
        tmp_path / "cb", "-GatewayUrl", "wss://agents.example.com", "-Server", "https://mcp.example.com/", "-Name", "p70"
    )
    assert result.returncode == 0, result.stderr
    assert "activate 'p70' by browser approval at https://mcp.example.com/activate" in result.stdout
    coded = _bootstrap_dry_run(
        tmp_path / "cb2", "-GatewayUrl", "wss://agents.example.com", "-Server", "https://mcp.example.com",
        "-Code", "ABCD-EFGH-IJKL-MNOP", "-Name", "p70",
    )
    assert "enroll as 'p70'" in coded.stdout  # a pairing code, when given, still wins
    plain = _bootstrap_dry_run(tmp_path / "cb3", "-GatewayUrl", "wss://agents.example.com", "-Server", "http://x", "-Name", "p70")
    assert plain.returncode != 0 and "https" in plain.stderr


def test_served_windows_installers_parse(tmp_path):
    # The gateway serves these with its addresses filled in; both must at least be valid PowerShell / batch.
    from contextbridge.oauth.activation import ActivationBroker

    broker = ActivationBroker.__new__(ActivationBroker)
    broker.public_url, broker.agents_url = "https://mcp.example.com", "wss://agents.example.com"
    script = tmp_path / "remote-windows.ps1"
    script.write_text(broker.installer_text("remote-windows.ps1"), encoding="utf-8")
    # -Command does not pass trailing arguments in $args, so the path goes into the command itself.
    quoted = "'" + str(script).replace("'", "''") + "'"
    check = (
        f"$e = $null; [void][Management.Automation.Language.Parser]::ParseFile({quoted}, [ref]$null, [ref]$e); "
        "if ($e) { $e | ForEach-Object { $_.Message }; exit 1 }"
    )
    parsed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", check],
        capture_output=True, text=True, timeout=120,
    )
    assert parsed.returncode == 0, parsed.stdout + parsed.stderr
    cmd = broker.installer_text("ContextBridgeSetup.cmd")
    assert "\r\n" in cmd and "https://mcp.example.com/install/remote-windows.ps1" in cmd
