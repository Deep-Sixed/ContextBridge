"""contextbridge-update-fleet: config, change classification, and each device's update path against a fake gateway."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import anyio
import pytest

from contextbridge import fleet
from contextbridge.fleet import Change, Device, DeviceUpdate, FleetError, Gateway, device_command, load_fleet, read_token

GW = Gateway("/opt/contextbridge/app", "/opt/contextbridge/venv", "contextbridge", "contextbridge")
OLD, NEW = "a" * 40, "b" * 40


def test_load_fleet(tmp_path):
    path = tmp_path / "fleet.yaml"
    path.write_text(
        "gateway: {checkout: /opt/app, venv: /opt/venv, service: cb, user: cb,"
        " local_agents: [{venv: /opt/agent/venv, service: cb-agent}]}\n"
        "devices:\n"
        "  friday: {checkout: /home/j/cb, python: /home/j/cb/.venv/bin/python, systemd_user_unit: cb.service}\n"
        "  p70: {checkout: 'C:/ContextBridge', python: 'C:/ContextBridge/.venv/Scripts/python.exe',"
        " windows_task: ContextBridge Agent}\n",
        encoding="utf-8",
    )
    f = load_fleet(path)
    assert f.gateway.local_agents[0].service == "cb-agent"
    assert [d.name for d in f.devices] == ["friday", "p70"]  # file order is update order
    assert f.devices[1].windows_task == "ContextBridge Agent"


@pytest.mark.parametrize(
    "devices, message",
    [
        ("friday: {checkout: /x, python: /x/py}", "exactly one of"),
        ("friday: {checkout: /x, python: /x/py, systemd_user_unit: a, windows_task: b}", "exactly one of"),
        ("friday: {python: /x/py, systemd_user_unit: a}", "'checkout' is required"),
    ],
)
def test_load_fleet_rejects_bad_devices(tmp_path, devices, message):
    path = tmp_path / "fleet.yaml"
    path.write_text(f"gateway: {{checkout: /a, venv: /v, service: s, user: u}}\ndevices:\n  {devices}\n", encoding="utf-8")
    with pytest.raises(FleetError, match=message):
        load_fleet(path)


def test_read_token_from_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv(fleet.TOKEN_ENV, raising=False)
    env = tmp_path / "gateway.env"
    env.write_text(f"OTHER=1\n{fleet.TOKEN_ENV}=\"abc123\"\n", encoding="utf-8")
    assert read_token(str(env)) == "abc123"
    monkeypatch.setenv(fleet.TOKEN_ENV, "from-env")
    assert read_token(str(env)) == "from-env"


def test_change_classification():
    assert not Change(["README.md", "scripts/bootstrap-agent.ps1", "tests/test_x.py"]).code
    assert Change(["src/contextbridge/remote/agent.py"]).code
    deps = Change(["pyproject.toml"])
    assert deps.code and deps.deps


def test_device_command_quotes_for_each_shell():
    steps = [["git", "-C", "C:/it's here", "rev-parse", "HEAD"], ["py", "-c", "print(1)"]]
    windows = device_command(True, steps)
    assert "& 'git' '-C' 'C:/it''s here' 'rev-parse' 'HEAD'; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" in windows
    assert device_command(False, steps) == "git -C 'C:/it'\"'\"'s here' rev-parse HEAD && py -c 'print(1)'"


class FakeGateway:
    """Answers run_command and list_devices the way the gateway does, and records every command."""

    def __init__(self, device: Device, *, windows: bool, location: str):
        self.device, self.windows, self.location = device, windows, location
        self.head = OLD
        self.commands: list[str] = []
        self.reconnected = False

    def row(self) -> dict[str, Any]:
        since = datetime.now(timezone.utc) + (timedelta(seconds=30) if self.reconnected else -timedelta(hours=1))
        return {
            "device": self.device.name,
            "online": True,
            "connected_since": since.isoformat().replace("+00:00", "Z"),
            "info": {"platform": "Windows 11" if self.windows else "Linux 7.0"},
        }

    async def __call__(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == fleet.LIST_DEVICES_TOOL:
            return {"devices": [self.row()]}
        command = args["command"]
        self.commands.append(command)
        out = ""
        if "rev-parse" in command:
            out = self.head
        elif "merge" in command:
            self.head = NEW
        elif "contextbridge.__file__" in command:
            out = self.location
        elif "systemd-run" in command:
            self.reconnected = True
        elif command.startswith("Stop-ScheduledTask"):
            self.reconnected = True
            raise RuntimeError("connection lost")  # the agent that ran it is gone
        return {"exit_code": 0, "stdout": out, "stderr": ""}


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(fleet, "POLL_SECONDS", 0)


def run_update(fake: FakeGateway, files: list[str], monkeypatch, dry_run: bool = False) -> None:
    monkeypatch.setattr(fleet, "diff_files", lambda gw, old, new: Change(files if old != new else []))

    async def go() -> None:
        await DeviceUpdate(fake, fake.device, fake.row(), GW, NEW, dry_run=dry_run).run()

    anyio.run(go)


FRIDAY = Device("friday", "/home/j/cb", "/home/j/cb/.venv/bin/python", systemd_user_unit="cb.service")
P70 = Device("p70", "C:/ContextBridge", "C:/ContextBridge/.venv/Scripts/python.exe", windows_task="ContextBridge Agent")
THANATOS = Device("thanatos", "C:/cb", "C:/cb/.venv-std/Scripts/python.exe", windows_task="ContextBridge Agent Omnilink")


def test_linux_code_change_reinstalls_and_hands_the_restart_to_systemd(monkeypatch):
    fake = FakeGateway(FRIDAY, windows=False, location="/home/j/cb/.venv/lib/python3.14/site-packages/contextbridge/__init__.py")
    run_update(fake, ["src/contextbridge/remote/agent.py"], monkeypatch)
    joined = "\n".join(fake.commands)
    assert "merge --ff-only --quiet " + NEW in joined
    assert "-m pip install --quiet --disable-pip-version-check --no-deps /home/j/cb" in joined
    assert "systemd-run --user --collect --quiet --on-active=3 systemctl --user restart cb.service" in joined
    assert fake.head == NEW


def test_docs_only_change_moves_the_checkout_without_a_restart(monkeypatch):
    fake = FakeGateway(P70, windows=True, location="C:\\ContextBridge\\src\\contextbridge\\__init__.py")
    run_update(fake, ["README.md", "scripts/bootstrap-agent.ps1"], monkeypatch)
    assert fake.head == NEW
    assert not any("pip" in c or "Stop-ScheduledTask" in c for c in fake.commands)


def test_windows_editable_install_restarts_through_its_task_without_reinstalling(monkeypatch):
    fake = FakeGateway(P70, windows=True, location="C:\\ContextBridge\\src\\contextbridge\\__init__.py")
    run_update(fake, ["src/contextbridge/computer/files.py"], monkeypatch)
    assert not any("pip" in c for c in fake.commands)
    assert any(c.startswith("Stop-ScheduledTask -TaskName 'ContextBridge Agent'") for c in fake.commands)
    assert fake.head == NEW


def test_venv_inside_the_checkout_is_not_mistaken_for_an_editable_install(monkeypatch):
    fake = FakeGateway(THANATOS, windows=True, location="C:\\cb\\.venv-std\\Lib\\site-packages\\contextbridge\\__init__.py")
    run_update(fake, ["src/contextbridge/computer/files.py"], monkeypatch)
    assert any("'pip' 'install'" in c and "'--no-deps'" in c for c in fake.commands)


def test_dependency_change_on_windows_stops_before_touching_the_device(monkeypatch):
    fake = FakeGateway(P70, windows=True, location="C:\\ContextBridge\\src\\contextbridge\\__init__.py")
    with pytest.raises(FleetError, match="upgrade it by hand"):
        run_update(fake, ["pyproject.toml"], monkeypatch)
    assert fake.head == OLD and not any("merge" in c for c in fake.commands)


def test_dry_run_changes_nothing(monkeypatch):
    fake = FakeGateway(FRIDAY, windows=False, location="")
    run_update(fake, ["src/contextbridge/remote/agent.py"], monkeypatch, dry_run=True)
    assert fake.head == OLD
    assert all("rev-parse" in c for c in fake.commands)


def test_local_edits_to_tracked_files_stop_the_update(monkeypatch):
    fake = FakeGateway(FRIDAY, windows=False, location="")
    original = fake.__call__

    async def dirty(tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "run_command" and "status --porcelain" in args["command"]:
            return {"exit_code": 0, "stdout": " M configs/agent.yaml", "stderr": ""}
        return await original(tool, args)

    monkeypatch.setattr(fleet, "diff_files", lambda gw, old, new: Change(["src/x.py"]))
    with pytest.raises(FleetError, match="local changes"):
        anyio.run(lambda: DeviceUpdate(dirty, FRIDAY, fake.row(), GW, NEW, dry_run=False).run())
    assert fake.head == OLD


def test_offline_device_is_refused():
    row = {"device": "friday", "online": False, "info": {"platform": "Linux"}}
    with pytest.raises(FleetError, match="offline"):
        anyio.run(lambda: DeviceUpdate(None, FRIDAY, row, GW, NEW, dry_run=False).run())  # type: ignore[arg-type]
