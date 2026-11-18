"""contextbridge-doctor: each check against real configs, identities and audit logs, and canned task/unit data."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from contextbridge import doctor as D
from contextbridge.doctor import Doctor, Startup, clock_finding, connection_findings, read_audit, task_findings
from contextbridge.remote.agent import Identity, single_agent_instance

NOW = datetime(2026, 11, 18, 15, 0, tzinfo=timezone.utc)


def make_agent(tmp_path: Path, *, name: str = "box", enrolled: bool = True) -> Path:
    (tmp_path / "ws").mkdir(exist_ok=True)
    cfg = {
        "name": name,
        "gateway": {"url": "wss://agents.example.test"},
        "identity": "state/identity.json",
        "audit_log": "audit.jsonl",
        "filesystem": {"roots": [str(tmp_path / "ws")]},
        "commands": {"mode": "allowlist", "allow": ["date"]},
    }
    path = tmp_path / "agent.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    if enrolled:
        Identity("dev_1", name, "gw_1", Ed25519PrivateKey.generate()).save(tmp_path / "state" / "identity.json")
    return path


def audit(tmp_path: Path, *events: tuple[int, str, str | None]) -> None:
    """events: (minutes before NOW, event, reason)"""
    with (tmp_path / "audit.jsonl").open("a", encoding="utf-8") as fh:
        for minutes, event, reason in events:
            entry = {"ts": (NOW - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"), "route": "agent", "event": event}
            if reason:
                entry["reason"] = reason
            fh.write(json.dumps(entry) + "\n")


def run_doctor(config: Path | None, startups: list[Startup] | None = None) -> Doctor:
    d = Doctor(str(config) if config else None, offline=True, startups=startups or [], now=lambda: NOW)
    d.examine()
    return d


def by_check(d: Doctor, check: str) -> list[D.Finding]:
    return [f for f in d.findings if f.check == check]


def test_healthy_running_agent(tmp_path):
    config = make_agent(tmp_path)
    audit(tmp_path, (90, "agent_started", None), (89, "gateway_connected", None))
    with single_agent_instance(tmp_path / "state" / "identity.json"):  # stands in for the running agent
        d = run_doctor(config)
    assert [f.status for f in by_check(d, "identity")] == ["ok"]
    assert by_check(d, "process")[0].status == "ok"
    assert by_check(d, "connection")[0].summary.startswith("connected to the gateway since")
    assert d.status == "warn"  # only: no startup task or unit in this test


def test_lock_probe_releases_the_lock(tmp_path):
    config = make_agent(tmp_path)
    d = run_doctor(config)
    assert by_check(d, "process")[0].status == "fail"
    with single_agent_instance(tmp_path / "state" / "identity.json"):  # the doctor let go of it
        pass


def test_broken_config_stops_with_its_error(tmp_path):
    config = make_agent(tmp_path)
    config.write_text("name: box\ngateway: {url: 'ws://192.0.2.1:8792'}\nidentity: x\naudit_log: y\n", encoding="utf-8")
    d = run_doctor(config)
    (finding,) = by_check(d, "config")
    assert finding.status == "fail" and "wss://" in finding.summary
    assert not by_check(d, "identity")


def test_missing_config(tmp_path):
    d = run_doctor(tmp_path / "nope.yaml")
    assert by_check(d, "config")[0].summary.endswith("does not exist")


@pytest.mark.parametrize("enrolled, renamed, message", [(False, False, "enroll this device"), (True, True, "belongs to 'box'")])
def test_identity_problems(tmp_path, enrolled, renamed, message):
    config = make_agent(tmp_path, enrolled=enrolled)
    if renamed:
        config.write_text(config.read_text(encoding="utf-8").replace("name: box", "name: other"), encoding="utf-8")
    d = run_doctor(config)
    assert any(f.status == "fail" and message in (f.summary + (f.fix or "")) for f in by_check(d, "identity"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_identity_readable_by_others_warns(tmp_path):
    config = make_agent(tmp_path)
    (tmp_path / "state" / "identity.json").chmod(0o644)
    assert any(f.status == "warn" for f in by_check(run_doctor(config), "identity"))


def test_config_is_found_through_the_startup_definition(tmp_path):
    config = make_agent(tmp_path)
    unit = Startup("systemd-user", "cb.service", [sys.executable, "-m", "contextbridge.remote.agent", "run", "--config", str(config)],
                   {"ActiveState": "active", "UnitFileState": "enabled", "Restart": "always", "NRestarts": "0"})
    d = run_doctor(None, [unit])
    assert by_check(d, "config")[0].status == "ok"


def test_two_agents_need_config(tmp_path):
    a = Startup("windows-task", "A", ["py", "run", "--config", "C:/a.yaml"])
    b = Startup("windows-task", "B", ["py", "run", "--config", "C:/b.yaml"])
    d = run_doctor(None, [a, b])
    assert "pass --config" in (by_check(d, "config")[0].fix or "")


# ------------------------------------------------------------------------------------- connection history


def test_currently_disconnected_is_a_failure(tmp_path):
    make_agent(tmp_path)
    audit(tmp_path, (60, "gateway_connected", None), (5, "gateway_disconnected", None), (4, "gateway_unreachable", "OSError: [Errno 101] Network is unreachable"))
    events = read_audit(tmp_path / "audit.jsonl", NOW - timedelta(hours=24))
    (now_state, _history) = connection_findings(events, True, NOW)
    assert now_state.status == "fail" and "Network is unreachable" in now_state.summary


def test_frequent_reconnects_are_unstable(tmp_path):
    make_agent(tmp_path)
    audit(tmp_path, (600, "agent_started", None), *[(500 - 20 * i, e, r) for i in range(12) for e, r in
          (("gateway_unreachable", "ConnectionClosedError: no close frame"), ("gateway_connected", None))])
    findings = connection_findings(read_audit(tmp_path / "audit.jsonl", NOW - timedelta(hours=24)), True, NOW)
    unstable = findings[-1]
    assert unstable.status == "warn" and "11 reconnects" in unstable.summary and "ConnectionClosedError x12" in unstable.summary


def test_old_events_and_garbage_are_ignored(tmp_path):
    make_agent(tmp_path)
    audit(tmp_path, (60 * 30, "gateway_connected", None))
    with (tmp_path / "audit.jsonl").open("a", encoding="utf-8") as fh:
        fh.write("not json\n{\"ts\": \"bad\"}\n")
    assert read_audit(tmp_path / "audit.jsonl", NOW - timedelta(hours=24)) == []


# --------------------------------------------------------------------------------------- startup definitions


def good_task(exe: str, **overrides) -> Startup:
    details = {
        "state": "Running", "logon": "Interactive", "runlevel": "Limited", "multiple": "IgnoreNew", "limit": "PT0S",
        "no_start_on_battery": False, "stop_on_battery": False,
        "triggers": [{"kind": "MSFT_TaskLogonTrigger", "enabled": True, "repeat": ""},
                     {"kind": "MSFT_TaskTimeTrigger", "enabled": True, "repeat": "PT1M"}],
    }
    details.update(overrides)
    return Startup("windows-task", "ContextBridge Agent",
                   [exe, *D.split_windows_command('-m contextbridge.remote.agent run --config "C:\\x y\\agent.yaml" --log-file "C:\\l.log"')], details)


def test_task_installed_by_the_installer_passes():
    task = good_task(sys.executable)
    assert task.config == "C:\\x y\\agent.yaml" and task.log_file == "C:\\l.log"
    (finding,) = task_findings(task, None)
    assert finding.status == "ok" and "TaskLogon, TaskTime" not in finding.summary and "Logon, Time" in finding.summary


@pytest.mark.parametrize(
    "overrides, status, words",
    [
        ({"state": "Disabled"}, "fail", "disabled"),
        ({"limit": "PT72H"}, "fail", "run-time limit"),
        ({"multiple": "Parallel"}, "warn", "multiple instances"),
        ({"stop_on_battery": True}, "warn", "battery"),
        ({"triggers": [{"kind": "MSFT_TaskLogonTrigger", "enabled": True, "repeat": ""}]}, "warn", "no repeating trigger"),
        ({"triggers": [{"kind": "MSFT_TaskTimeTrigger", "enabled": True, "repeat": "PT1M"}]}, "warn", "no sign-in or boot trigger"),
    ],
)
def test_task_problems(overrides, status, words):
    findings = task_findings(good_task(sys.executable, **overrides), None)
    assert any(f.status == status and words in f.summary for f in findings)


def test_task_pointing_at_a_missing_python():
    assert any("does not exist" in f.summary for f in task_findings(good_task("C:/gone/pythonw.exe"), None))


def test_exec_start_parsing():
    show = "{ path=/v/bin/contextbridge-agent ; argv[]=/v/bin/contextbridge-agent run --config /c/agent.yaml ; ignore_errors=no ; pid=7 }"
    assert D.parse_exec_start(show) == ["/v/bin/contextbridge-agent", "run", "--config", "/c/agent.yaml"]


def test_unit_problems(monkeypatch):
    monkeypatch.setenv("USER", "jarvis")
    lingers = lambda *a, **k: subprocess.CompletedProcess(a, 0, "Linger=no\n", "")  # noqa: E731
    unit = Startup("systemd-user", "cb.service", ["/gone/contextbridge-agent", "run", "--config", "/c.yaml"],
                   {"ActiveState": "failed", "SubState": "failed", "UnitFileState": "disabled", "Restart": "no"})
    summaries = " | ".join(f.summary for f in D.unit_findings(unit, None, lingers))
    for words in ("is disabled", "is failed", "Restart=no", "does not exist", "lingering is off"):
        assert words in summaries


def test_systemd_discovery_reads_unit_files(tmp_path, monkeypatch):
    units = tmp_path / "systemd" / "user"
    units.mkdir(parents=True)
    (units / "cb.service").write_text("[Service]\nExecStart=/v/bin/contextbridge-agent run --config /c/a.yaml\n", encoding="utf-8")
    (units / "other.service").write_text("[Service]\nExecStart=/usr/bin/true\n", encoding="utf-8")
    monkeypatch.setattr(D, "_unit_dirs", lambda user: [units] if user else [])
    show = "ExecStart={ path=/v/bin/contextbridge-agent ; argv[]=/v/bin/contextbridge-agent run --config /c/a.yaml ; }\nActiveState=active\n"
    (found,) = D.systemd_units(lambda *a, **k: subprocess.CompletedProcess(a, 0, show, ""))
    assert found.name == "cb.service" and found.config == "/c/a.yaml" and found.details["ActiveState"] == "active"


# --------------------------------------------------------------------------------------------------- other


def test_clock_skew():
    assert clock_finding(NOW - timedelta(seconds=3), NOW).status == "ok"
    assert clock_finding(NOW - timedelta(minutes=5), NOW).status == "warn"
    assert clock_finding(None, NOW).status == "info"


def test_last_error_from_the_log_file():
    lines = ["[agent] box connecting to wss://x", '[agent audit] {"event":"gateway_connected"}',
             "Traceback (most recent call last):", '  File "x.py", line 1', "ValueError: bad thing", "[agent] box connecting to wss://x"]
    assert D.last_error(lines) == "ValueError: bad thing"
    assert D.last_error([*lines, "[agent] stopped: device revoked"]) == "[agent] stopped: device revoked"


def test_cli_json(tmp_path, capsys, monkeypatch):
    config = make_agent(tmp_path)
    monkeypatch.setattr(D, "discover", lambda run: [])
    with pytest.raises(SystemExit) as exit_info:
        D.main(["--config", str(config), "--offline", "--json"])
    report = json.loads(capsys.readouterr().out)
    assert exit_info.value.code == 1  # no agent running
    assert report["device"] == "box" and report["status"] == "fail"
    assert {f["check"] for f in report["findings"]} >= {"install", "config", "identity", "process", "network"}
    assert "private_key" not in json.dumps(report)
