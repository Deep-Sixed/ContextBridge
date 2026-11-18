"""Update the gateway and every agent to one git revision, in order, stopping at the first failure.

Run it on the gateway host as root. It updates the gateway (and any agents on the same host) directly, then
reaches each remote agent through the gateway's own local MCP endpoint, the same way the failover drill does:

    contextbridge-update-fleet --config /opt/contextbridge/config/computer.yaml \\
        --fleet /opt/contextbridge/config/fleet.yaml --env-file /etc/contextbridge/gateway.env
    contextbridge-update-fleet ... --dry-run        # show what would change, change nothing

For each machine it moves the checkout forward to the target commit (fast-forward only) and then does only what
the change needs:

- no change under ``src/`` or to ``pyproject.toml``: nothing else; the running code is already identical;
- a code change: reinstall the package (skipped for editable installs, which run from the checkout), then restart
  the agent or gateway and wait until it is back;
- a dependency change (``requires-python``, ``dependencies``, ``optional-dependencies`` or the build requirements
  in ``pyproject.toml``; other edits there, such as a new command, are ordinary code changes) on a Windows agent:
  stop and say so, because new dependencies cannot be installed under a running agent there; upgrade that
  machine by hand (``scripts/bootstrap-agent.ps1``).

A remote agent cannot restart itself from a command it is running, because its commands die with it. On Linux the
restart is handed to the user's systemd (``systemd-run``); on Windows the agent's scheduled task is stopped and its
every-minute trigger, which ``install-agent.ps1`` registers, starts it again. The fleet file names each machine's
checkout, Python, and service, because every machine here was installed a little differently:

    gateway:
      checkout: /opt/contextbridge/app        # git checkout the gateway is installed from
      venv: /opt/contextbridge/venv
      service: contextbridge                  # systemd unit
      user: contextbridge                     # owner of the checkout and venv
      local_agents:                           # agents on the gateway host, installed from the same checkout
        - {venv: /opt/omnilink-agent/venv, service: contextbridge-agent-omnilink}
    devices:                                  # updated in this order; devices not listed are left alone
      friday:
        checkout: /home/jarvis/contextbridge-agent
        python: /home/jarvis/contextbridge-agent/.venv/bin/python
        systemd_user_unit: contextbridge-agent.service
      p70:
        checkout: C:/ContextBridge
        python: C:/ContextBridge/.venv/Scripts/python.exe
        windows_task: ContextBridge Agent

Exit status: 0 all up to date, 1 a step failed (later machines were not touched), 2 could not start.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
import tomllib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anyio
import yaml

from .computer.server import LIST_DEVICES_TOOL, TOKEN_ENV
from .failover import DEFAULT_URL, _url_from_config

CALL_TIMEOUT_SECONDS = 660
RECONNECT_SECONDS = 180
POLL_SECONDS = 5


class FleetError(Exception):
    """A step failed; the message says which machine and what to do."""


# ----------------------------------------------------------------------------------------------------- config


@dataclass
class LocalAgent:
    venv: str
    service: str


@dataclass
class Gateway:
    checkout: str
    venv: str
    service: str
    user: str
    local_agents: list[LocalAgent] = field(default_factory=list)


@dataclass
class Device:
    name: str
    checkout: str
    python: str
    systemd_user_unit: str | None = None
    windows_task: str | None = None


@dataclass
class Fleet:
    gateway: Gateway
    devices: list[Device]


def _need(section: dict[str, Any], key: str, where: str) -> str:
    value = section.get(key)
    if not isinstance(value, str) or not value.strip():
        raise FleetError(f"{where}: '{key}' is required")
    return value.strip()


def load_fleet(path: str | Path) -> Fleet:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    gw = data.get("gateway")
    if not isinstance(gw, dict):
        raise FleetError(f"{path}: a 'gateway' section is required")
    local = []
    for i, entry in enumerate(gw.get("local_agents") or []):
        where = f"{path}: gateway.local_agents[{i}]"
        if not isinstance(entry, dict):
            raise FleetError(f"{where} must be a mapping")
        local.append(LocalAgent(_need(entry, "venv", where), _need(entry, "service", where)))
    gateway = Gateway(
        _need(gw, "checkout", f"{path}: gateway"),
        _need(gw, "venv", f"{path}: gateway"),
        _need(gw, "service", f"{path}: gateway"),
        _need(gw, "user", f"{path}: gateway"),
        local,
    )
    devices = []
    for name, entry in (data.get("devices") or {}).items():
        where = f"{path}: devices.{name}"
        if not isinstance(entry, dict):
            raise FleetError(f"{where} must be a mapping")
        unit, task = entry.get("systemd_user_unit"), entry.get("windows_task")
        if bool(unit) == bool(task):
            raise FleetError(f"{where}: set exactly one of 'systemd_user_unit' or 'windows_task'")
        devices.append(
            Device(str(name), _need(entry, "checkout", where), _need(entry, "python", where), unit or None, task or None)
        )
    return Fleet(gateway, devices)


def read_token(env_file: str | None) -> str:
    token = os.environ.get(TOKEN_ENV, "")
    if token or not env_file:
        return token
    for line in Path(env_file).read_text(encoding="utf-8").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key.strip() == TOKEN_ENV:
            return value.strip().strip('"').strip("'")
    return ""


# ---------------------------------------------------------------------------------------------------- changes


@dataclass
class Change:
    files: list[str]
    # Whether the dependencies themselves changed; None means "assume they did if pyproject.toml changed".
    dependencies_changed: bool | None = None

    @property
    def code(self) -> bool:
        return any(f.startswith("src/") for f in self.files) or "pyproject.toml" in self.files

    @property
    def deps(self) -> bool:
        if "pyproject.toml" not in self.files:
            return False
        return True if self.dependencies_changed is None else self.dependencies_changed

    def describe(self) -> str:
        if not self.files:
            return "no changes"
        if self.deps:
            return f"{len(self.files)} file(s), including dependency changes in pyproject.toml"
        if "pyproject.toml" in self.files:
            return f"{len(self.files)} file(s), including pyproject.toml (dependencies unchanged)"
        if self.code:
            return f"{len(self.files)} file(s), including the package code"
        return f"{len(self.files)} file(s), none of them package code (no restart needed)"


def say(message: str) -> None:
    print(message, flush=True)


# ------------------------------------------------------------------------------------------- gateway (local)


def _run(argv: list[str], *, user: str | None = None, cwd: str | None = None, check: bool = True) -> str:
    if user:
        argv = ["runuser", "-u", user, "--", *argv]
    proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise FleetError(f"`{shlex.join(argv)}` failed ({proc.returncode}): {(proc.stderr or proc.stdout).strip()[:500]}")
    return proc.stdout.strip()


def resolve_target(gw: Gateway, revision: str) -> str:
    _run(["git", "-C", gw.checkout, "fetch", "--quiet", "--tags", "origin"], user=gw.user)
    for ref in (f"origin/{revision}", revision):
        proc = subprocess.run(
            ["runuser", "-u", gw.user, "--", "git", "-C", gw.checkout, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    raise FleetError(f"revision '{revision}' not found in {gw.checkout}")


def diff_files(gw: Gateway, old: str, new: str) -> Change:
    if old == new:
        return Change([])
    ancestor = subprocess.run(
        ["runuser", "-u", gw.user, "--", "git", "-C", gw.checkout, "merge-base", "--is-ancestor", old, new],
        capture_output=True, check=False,
    )
    if ancestor.returncode != 0:
        raise FleetError(f"{old[:7]} is not an ancestor of {new[:7]}: that checkout has diverged; update it by hand")
    out = _run(["git", "-C", gw.checkout, "diff", "--name-only", old, new], user=gw.user)
    files = [line for line in out.splitlines() if line]
    deps = None
    if "pyproject.toml" in files:
        deps = dependency_spec(_show(gw, old, "pyproject.toml")) != dependency_spec(_show(gw, new, "pyproject.toml"))
    return Change(files, deps)


def _show(gw: Gateway, commit: str, path: str) -> str | None:
    proc = subprocess.run(
        ["runuser", "-u", gw.user, "--", "git", "-C", gw.checkout, "show", f"{commit}:{path}"],
        capture_output=True, text=True, check=False,
    )
    return proc.stdout if proc.returncode == 0 else None


def dependency_spec(pyproject: str | None) -> object:
    """The parts of pyproject.toml that decide what pip installs besides this package itself.

    A file that is missing or does not parse gets a value equal to nothing, so it counts as a dependency change.
    """
    if pyproject is None:
        return object()
    try:
        data = tomllib.loads(pyproject)
    except tomllib.TOMLDecodeError:
        return object()
    project = data.get("project", {})
    return (
        project.get("requires-python"),
        project.get("dependencies"),
        project.get("optional-dependencies"),
        data.get("build-system", {}).get("requires"),
    )


def update_gateway(gw: Gateway, target: str, *, dry_run: bool) -> bool:
    """Bring the gateway host to ``target``. Returns True when the gateway was restarted."""
    old = _run(["git", "-C", gw.checkout, "rev-parse", "HEAD"], user=gw.user)
    change = diff_files(gw, old, target)
    say(f"==> gateway: {old[:7]} -> {target[:7]}: {change.describe()}")
    if dry_run or not change.files:
        return False
    dirty = _run(["git", "-C", gw.checkout, "status", "--porcelain", "--untracked-files=no"], user=gw.user)
    if dirty:
        raise FleetError(f"gateway: {gw.checkout} has local changes to tracked files; commit or discard them first")
    _run(["git", "-C", gw.checkout, "merge", "--ff-only", "--quiet", target], user=gw.user)
    if not change.code:
        return False
    say("    reinstalling the gateway package")
    _run([f"{gw.venv}/bin/pip", "install", "--quiet", "--disable-pip-version-check", gw.checkout], user=gw.user)
    for agent in gw.local_agents:
        say(f"    reinstalling {agent.service}")
        _run([f"{agent.venv}/bin/pip", "install", "--quiet", "--disable-pip-version-check", gw.checkout])
    say(f"    restarting {gw.service} (every agent reconnects within a minute)")
    _run(["systemctl", "restart", gw.service])
    for agent in gw.local_agents:
        _run(["systemctl", "restart", agent.service])
    time.sleep(3)
    for unit in [gw.service, *(a.service for a in gw.local_agents)]:
        if subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode != 0:
            raise FleetError(f"gateway: {unit} did not stay up after the restart; see `journalctl -u {unit} -n 50`")
    return True


# ------------------------------------------------------------------------------------------ devices (remote)

Call = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def device_command(windows: bool, steps: list[list[str]]) -> str:
    """One command line running ``steps`` in order and stopping at the first failure."""
    if windows:
        parts = []
        for argv in steps:
            exe, *args = argv
            parts.append("& " + " ".join(_ps_quote(a) for a in [exe, *args]) + "; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")
        return " ".join(parts)
    return " && ".join(shlex.join(argv) for argv in steps)


def _connected_since(row: dict[str, Any]) -> datetime | None:
    value = row.get("connected_since")
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


class DeviceUpdate:
    def __init__(self, call: Call, device: Device, row: dict[str, Any], gw: Gateway, target: str, *, dry_run: bool):
        self.call, self.device, self.row, self.gw, self.target, self.dry_run = call, device, row, gw, target, dry_run
        self.windows = str((row.get("info") or {}).get("platform", "")).lower().startswith("windows")

    async def run_command(self, steps: list[list[str]], *, timeout: int = 600) -> str:
        result = await self.call(
            "run_command",
            {"device": self.device.name, "command": device_command(self.windows, steps), "timeout_seconds": timeout},
        )
        if result.get("exit_code") != 0:
            detail = (result.get("stderr") or result.get("stdout") or "").strip()[:500]
            raise FleetError(f"{self.device.name}: command failed ({result.get('exit_code')}): {detail}")
        return str(result.get("stdout") or "").strip()

    async def run(self) -> None:
        d = self.device
        if not self.row.get("online"):
            raise FleetError(f"{d.name}: offline; start its agent and run this again")
        git = ["git", "-C", d.checkout]
        head = await self.run_command([[*git, "rev-parse", "HEAD"]])
        head = head.splitlines()[-1].strip()
        change = diff_files(self.gw, head, self.target)
        say(f"==> {d.name}: {head[:7]} -> {self.target[:7]}: {change.describe()}")
        if change.deps and self.windows:
            raise FleetError(
                f"{d.name}: the dependencies in pyproject.toml changed, and they cannot be installed under a running Windows "
                "agent; upgrade it by hand with scripts/bootstrap-agent.ps1"
            )
        if self.dry_run or not change.files:
            return
        if await self.run_command([[*git, "status", "--porcelain", "--untracked-files=no"]]):
            raise FleetError(f"{d.name}: {d.checkout} has local changes to tracked files; commit or discard them first")
        await self.run_command([[*git, "fetch", "--quiet", "origin"], [*git, "merge", "--ff-only", "--quiet", self.target]])
        if not change.code:
            return
        location = await self.run_command([[d.python, "-c", "import contextbridge; print(contextbridge.__file__)"]])
        # Editable installs import from <checkout>/src; a venv inside the checkout must not count as one.
        editable = (Path(d.checkout).as_posix().rstrip("/") + "/src/").lower() in location.replace("\\", "/").lower()
        if editable and not change.deps:
            say("    editable install: the checkout is the code, nothing to reinstall")
        else:
            say("    reinstalling the package")
            pip = [d.python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check"]
            await self.run_command([[*pip, *([] if change.deps else ["--no-deps"]), d.checkout]])
        await self.restart()

    async def restart(self) -> None:
        d = self.device
        before = _connected_since(self.row) or datetime.now(timezone.utc)
        if d.systemd_user_unit:
            say(f"    restarting {d.systemd_user_unit}")
            await self.run_command(
                [["systemd-run", "--user", "--collect", "--quiet", "--on-active=3", "systemctl", "--user", "restart",
                  d.systemd_user_unit]]
            )
        else:
            task = d.windows_task or ""
            check = (
                f"$t = Get-ScheduledTask -TaskName {_ps_quote(task)}; "
                "if (-not ($t.Triggers | Where-Object { $_.Repetition.Interval })) { exit 3 }"
            )
            result = await self.call("run_command", {"device": d.name, "command": check, "timeout_seconds": 60})
            if result.get("exit_code") != 0:
                raise FleetError(
                    f"{d.name}: task '{task}' has no repeating trigger to start the agent again after a stop; "
                    "reinstall it with scripts/install-agent.ps1 or restart it by hand"
                )
            say(f"    restarting task '{task}' (its every-minute trigger starts it again)")
            try:  # This call ends the agent that runs it, so its reply never arrives.
                await self.call(
                    "run_command",
                    {"device": d.name, "command": f"Stop-ScheduledTask -TaskName {_ps_quote(task)}", "timeout_seconds": 30},
                )
            except Exception:  # noqa: BLE001 -- the expected way for this call to end
                pass
        await wait_for_reconnect(self.call, d.name, after=before)
        head = (await self.run_command([["git", "-C", d.checkout, "rev-parse", "HEAD"]])).splitlines()[-1].strip()
        if head != self.target:
            raise FleetError(f"{d.name}: back online but at {head[:7]}, not {self.target[:7]}")


async def list_devices(call: Call) -> dict[str, dict[str, Any]]:
    return {row["device"]: row for row in (await call(LIST_DEVICES_TOOL, {}))["devices"]}


async def wait_for_reconnect(call: Call, name: str, *, after: datetime, seconds: int = RECONNECT_SECONDS) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        await anyio.sleep(POLL_SECONDS)
        try:
            row = (await list_devices(call)).get(name) or {}
        except Exception:  # noqa: BLE001 -- the gateway may be mid-restart
            continue
        since = _connected_since(row)
        if row.get("online") and since and since > after:
            say(f"    {name} is back (connected {since.strftime('%H:%M:%S')} UTC)")
            return
    raise FleetError(f"{name}: did not reconnect within {seconds} seconds")


# ------------------------------------------------------------------------------------------------------ main


async def update_fleet(url: str, token: str, fleet: Fleet, revision: str, *, dry_run: bool, only: list[str] | None) -> None:
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth

    target = resolve_target(fleet.gateway, revision)
    say(f"Target: {revision} = {target[:7]}{' (dry run: nothing will change)' if dry_run else ''}")
    restarted_at = datetime.now(timezone.utc)
    restarted = update_gateway(fleet.gateway, target, dry_run=dry_run)
    devices = [d for d in fleet.devices if not only or d.name in only]

    async def open_client() -> Any:
        client = Client(url, auth=BearerAuth(token), timeout=CALL_TIMEOUT_SECONDS)
        await client.__aenter__()
        return client

    client = None
    deadline = time.monotonic() + RECONNECT_SECONDS
    while client is None:  # after a gateway restart, wait for it to answer again
        try:
            client = await open_client()
        except Exception as exc:  # noqa: BLE001
            if time.monotonic() > deadline:
                raise FleetError(f"gateway: not answering at {url}: {exc}") from exc
            await anyio.sleep(POLL_SECONDS)
    try:

        async def call(tool: str, args: dict[str, Any]) -> dict[str, Any]:
            try:
                return (await client.call_tool(tool, args)).structured_content or {}
            except Exception as exc:  # noqa: BLE001 -- refusals and dropped calls become a reported failure
                where = args.get("device", "gateway")
                raise FleetError(f"{where}: {tool} failed: {type(exc).__name__}: {exc}"[:600]) from exc

        if restarted:
            for d in devices:
                await wait_for_reconnect(call, d.name, after=restarted_at)
        rows = await list_devices(call)
        for d in devices:
            if d.name not in rows:
                raise FleetError(f"{d.name}: not enrolled on this gateway")
            await DeviceUpdate(call, d, rows[d.name], fleet.gateway, target, dry_run=dry_run).run()
    finally:
        await client.__aexit__(None, None, None)
    say("Dry run complete: nothing was changed." if dry_run else f"Done: every machine is at {target[:7]}.")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Update the ContextBridge gateway and its agents to one git revision.")
    ap.add_argument("--fleet", required=True, help="fleet file naming each machine's checkout, Python and service")
    target = ap.add_mutually_exclusive_group()
    target.add_argument("--config", help="gateway config (reads serve.host and serve.port)")
    target.add_argument("--url", help=f"computer MCP endpoint (default {DEFAULT_URL})")
    ap.add_argument("--env-file", help=f"file holding {TOKEN_ENV}=... when it is not in the environment")
    ap.add_argument("--revision", default="main", help="branch, tag, or commit to update to (default: main)")
    ap.add_argument("--device", action="append", help="update only this remote device (repeatable); the gateway always")
    ap.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    args = ap.parse_args(argv)

    try:
        fleet = load_fleet(args.fleet)
        token = read_token(args.env_file)
    except (OSError, FleetError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    if not token:
        print(f"error: {TOKEN_ENV} is not set; pass --env-file with the gateway's environment file", file=sys.stderr)
        sys.exit(2)
    url = _url_from_config(args.config) if args.config else (args.url or DEFAULT_URL)
    try:
        anyio.run(lambda: update_fleet(url, token, fleet, args.revision, dry_run=args.dry_run, only=args.device))
    except FleetError as exc:
        print(f"FAILED: {exc}\nMachines after this one were not touched.", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
