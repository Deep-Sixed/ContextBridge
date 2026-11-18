"""contextbridge-doctor: find out what is wrong with the ContextBridge agent on this machine, changing nothing.

Run it on the machine itself, as the user the agent runs as. It needs no working gateway connection, so it
still helps when the agent is offline, which is when it is needed most:

    contextbridge-doctor                       # finds the agent's startup task or unit and its config
    contextbridge-doctor --config agent.yaml   # or name the config
    contextbridge-doctor --json                # machine-readable, for health reports
    contextbridge-doctor --offline             # skip the network checks

It checks, in order: this Python and package; the startup definition (Windows scheduled task or systemd unit)
and the config it starts the agent with; the config itself; the enrollment identity; whether an agent is
running; what the agent's audit log says about its connection; and DNS, TCP, TLS and the clock against the
gateway. Each finding says what is wrong and what fixes it.

It only reads. The single exception: to see whether an agent is running it briefly tries the agent's own
single-instance lock (the ``.run.lock`` file beside the identity), and releases it at once. It never contacts
the gateway as the device, so it cannot disturb the running agent's session, and it never prints the key.

Exit status: 0 nothing failed (warnings are allowed), 1 at least one check failed, 2 it could not run.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import platform
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import __version__

OK, INFO, WARN, FAIL = "ok", "info", "warn", "fail"
RANK = {OK: 0, INFO: 0, WARN: 1, FAIL: 2}
AGENT_COMMAND = re.compile(r"contextbridge(\.remote\.agent|-agent)", re.IGNORECASE)
AUDIT_TAIL_BYTES = 4 * 1024 * 1024
WINDOW = timedelta(hours=24)
UNSTABLE_RECONNECTS = 10  # reconnects in WINDOW before the connection counts as unstable
CLOCK_SKEW_WARN_SECONDS = 60
CERT_WARN_DAYS = 14
NET_TIMEOUT = 10.0

Runner = Callable[..., subprocess.CompletedProcess]


@dataclass
class Finding:
    check: str
    status: str
    summary: str
    fix: str | None = None


@dataclass
class Startup:
    """How this machine starts the agent: a Windows scheduled task or a systemd unit."""

    kind: str  # "windows-task" | "systemd-user" | "systemd-system"
    name: str
    command: list[str]
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def config(self) -> str | None:
        return _option(self.command, "--config")

    @property
    def log_file(self) -> str | None:
        return _option(self.command, "--log-file")


def _option(argv: list[str], name: str) -> str | None:
    for i, arg in enumerate(argv):
        if arg == name and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1]
    return None


def split_windows_command(text: str) -> list[str]:
    """Split a Windows command line the way the agent's argument parser receives it (quotes group, no escapes)."""
    return [m.group(1) if m.group(1) is not None else m.group(2) for m in re.finditer(r'"([^"]*)"|(\S+)', text or "")]


def _same_path(a: str | Path, b: str | Path) -> bool:
    def norm(p: str | Path) -> str:
        try:
            resolved = Path(p).expanduser().resolve()
        except OSError:
            resolved = Path(p)
        text = str(resolved).replace("\\", "/")
        return text.lower() if os.name == "nt" else text

    return norm(a) == norm(b)


# ------------------------------------------------------------------------------------------ startup discovery

_WINDOWS_TASKS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$rows = foreach ($t in Get-ScheduledTask) {
  $a = $t.Actions | Select-Object -First 1
  if ("$($a.Execute) $($a.Arguments)" -notmatch 'contextbridge(\.remote\.agent|-agent)') { continue }
  $i = $t | Get-ScheduledTaskInfo
  [pscustomobject]@{
    name = $t.TaskName; path = $t.TaskPath; state = "$($t.State)"
    execute = $a.Execute; arguments = $a.Arguments; workdir = $a.WorkingDirectory
    user = $t.Principal.UserId; logon = "$($t.Principal.LogonType)"; runlevel = "$($t.Principal.RunLevel)"
    triggers = @($t.Triggers | ForEach-Object { [pscustomobject]@{
      kind = $_.CimClass.CimClassName; enabled = [bool]$_.Enabled; repeat = "$($_.Repetition.Interval)" } })
    multiple = "$($t.Settings.MultipleInstances)"; limit = "$($t.Settings.ExecutionTimeLimit)"
    no_start_on_battery = [bool]$t.Settings.DisallowStartIfOnBatteries
    stop_on_battery = [bool]$t.Settings.StopIfGoingOnBatteries
    last_result = $i.LastTaskResult; last_run = "$($i.LastRunTime)"
  }
}
ConvertTo-Json -InputObject @($rows) -Depth 4 -Compress
"""


def windows_tasks(run: Runner = subprocess.run) -> list[Startup]:
    encoded = base64.b64encode(_WINDOWS_TASKS.encode("utf-16-le")).decode()
    proc = run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, timeout=60, check=False,
    )
    try:
        rows = json.loads(proc.stdout or "[]")
    except ValueError:
        return []
    if isinstance(rows, dict):
        rows = [rows]
    return [
        Startup("windows-task", row["name"], [row.get("execute") or "", *split_windows_command(row.get("arguments") or "")], row)
        for row in rows
    ]


def _unit_dirs(user: bool) -> list[Path]:
    if user:
        config_home = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        return [config_home / "systemd" / "user", Path("/etc/systemd/user")]
    return [Path("/etc/systemd/system"), Path("/usr/lib/systemd/system"), Path("/lib/systemd/system")]


def parse_exec_start(value: str) -> list[str]:
    """`systemctl show -p ExecStart` prints `{ path=... ; argv[]=prog arg ... ; ignore_errors=no ; ... }`."""
    match = re.search(r"argv\[\]=(.*?) ;", value)
    text = match.group(1) if match else value
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def systemd_units(run: Runner = subprocess.run) -> list[Startup]:
    found = []
    for user in (True, False):
        for directory in _unit_dirs(user):
            for unit in sorted(directory.glob("*.service")) if directory.is_dir() else []:
                try:
                    text = unit.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if not any(line.startswith("ExecStart") and AGENT_COMMAND.search(line) for line in text.splitlines()):
                    continue
                scope = ["--user"] if user else []
                props = ["ExecStart", "ActiveState", "SubState", "UnitFileState", "Restart", "RestartUSec", "NRestarts", "User"]
                proc = run(
                    ["systemctl", *scope, "show", unit.name, *[f"-p{p}" for p in props]],
                    capture_output=True, text=True, timeout=30, check=False,
                )
                details = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
                details["fragment"] = str(unit)
                command = parse_exec_start(details.get("ExecStart", ""))
                if not command:
                    exec_line = next(line for line in text.splitlines() if line.startswith("ExecStart"))
                    command = shlex.split(exec_line.split("=", 1)[1])
                found.append(Startup("systemd-user" if user else "systemd-system", unit.name, command, details))
    return found


def discover(run: Runner = subprocess.run) -> list[Startup]:
    if os.name == "nt":
        return windows_tasks(run)
    if sys.platform.startswith("linux"):
        return systemd_units(run)
    return []


# ---------------------------------------------------------------------------------------------- the checks


def task_findings(task: Startup, config_path: Path | None) -> list[Finding]:
    """What a Windows scheduled task needs so the agent starts, stays up, and comes back (see install-agent.ps1)."""
    d, name, out = task.details, f"task '{task.name}'", []
    reinstall = "re-run scripts/install-agent.ps1 (or bootstrap-agent.ps1), which registers the task correctly"
    if d.get("state") == "Disabled":
        out.append(Finding("startup", FAIL, f"{name} is disabled, so the agent never starts", "enable it: Enable-ScheduledTask -TaskName '" + task.name + "'"))
    exe = task.command[0] if task.command else ""
    if not exe or not Path(exe).exists():
        out.append(Finding("startup", FAIL, f"{name} starts {exe or 'nothing'}, which does not exist", reinstall))
    kinds = [t.get("kind", "") for t in d.get("triggers") or [] if t.get("enabled", True)]
    if not any(k in ("MSFT_TaskLogonTrigger", "MSFT_TaskBootTrigger") for k in kinds):
        out.append(Finding("startup", WARN, f"{name} has no sign-in or boot trigger, so the agent does not start after a restart", reinstall))
    if not any(t.get("repeat") for t in d.get("triggers") or [] if t.get("enabled", True)):
        out.append(Finding("startup", WARN, f"{name} has no repeating trigger, so an agent that exits stays down until the next sign-in or boot", reinstall))
    if d.get("multiple") and d["multiple"] != "IgnoreNew":
        out.append(Finding("startup", WARN, f"{name} allows multiple instances ({d['multiple']}); a second agent would fight the first for the connection", reinstall))
    if d.get("limit") not in (None, "", "PT0S"):
        out.append(Finding("startup", FAIL, f"{name} has a run-time limit of {d['limit']}; Windows stops the agent when it is reached", reinstall))
    if d.get("no_start_on_battery") or d.get("stop_on_battery"):
        out.append(Finding("startup", WARN, f"{name} does not run on battery power", reinstall))
    if config_path is not None and task.config and not _same_path(task.config, config_path):
        out.append(Finding("startup", WARN, f"{name} starts the agent with {task.config}, not {config_path}", "check the right config; pass --config to see the one the task uses"))
    if not out:
        trig = ", ".join(k.removeprefix("MSFT_Task").removesuffix("Trigger") for k in kinds)
        out.append(Finding("startup", OK, f"{name}: {d.get('state', '?')}, triggers {trig}, {d.get('logon', '?')}/{d.get('runlevel', '?')}"))
    return out


def unit_findings(unit: Startup, config_path: Path | None, run: Runner = subprocess.run) -> list[Finding]:
    d, name, out = unit.details, f"unit {unit.name}", []
    scope = "--user " if unit.kind == "systemd-user" else ""
    if d.get("UnitFileState") not in ("enabled", "enabled-runtime", "static", "linked", "alias", None):
        out.append(Finding("startup", FAIL, f"{name} is {d.get('UnitFileState')}, so the agent does not start at boot", f"systemctl {scope}enable {unit.name}"))
    if d.get("ActiveState") and d["ActiveState"] != "active":
        out.append(Finding("startup", FAIL, f"{name} is {d['ActiveState']} ({d.get('SubState', '')})", f"journalctl {scope}-u {unit.name} -n 50 shows why; then systemctl {scope}restart {unit.name}"))
    if d.get("Restart") in (None, "", "no"):
        out.append(Finding("startup", WARN, f"{name} has Restart={d.get('Restart') or 'no'}, so an agent that exits stays down", "set Restart=always and RestartSec=10 in the unit"))
    exe = unit.command[0] if unit.command else ""
    if not exe or not Path(exe).exists():
        out.append(Finding("startup", FAIL, f"{name} starts {exe or 'nothing'}, which does not exist", "point ExecStart at the agent's venv, then systemctl daemon-reload"))
    if unit.kind == "systemd-user":
        user = os.environ.get("USER") or ""
        proc = run(["loginctl", "show-user", user, "-pLinger"], capture_output=True, text=True, timeout=15, check=False) if user else None
        if proc is not None and proc.stdout.strip() == "Linger=no":
            out.append(Finding("startup", WARN, f"{name} is a user unit and lingering is off, so the agent only runs while {user} is logged in", f"loginctl enable-linger {user}"))
    if config_path is not None and unit.config and not _same_path(unit.config, config_path):
        out.append(Finding("startup", WARN, f"{name} starts the agent with {unit.config}, not {config_path}", "check the right config; pass --config to see the one the unit uses"))
    if not out:
        out.append(Finding("startup", OK, f"{name}: {d.get('ActiveState', '?')}, {d.get('UnitFileState', '?')}, Restart={d.get('Restart')}, restarts so far: {d.get('NRestarts', '?')}"))
    return out


def agent_running(identity_path: Path) -> bool | None:
    """True if an agent holds its single-instance lock, False if not, None if it cannot tell."""
    from .remote.agent import FatalAgentError, single_agent_instance

    lock = identity_path.with_name(identity_path.name + ".run.lock")
    if not lock.parent.is_dir():
        return None
    try:
        with single_agent_instance(identity_path):
            return False
    except FatalAgentError:
        return True
    except OSError:
        return None


def read_audit(path: Path, since: datetime) -> list[dict[str, Any]]:
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - AUDIT_TAIL_BYTES))
            data = fh.read()
    except OSError:
        return []
    events = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        try:
            entry = json.loads(line)
            when = datetime.fromisoformat(str(entry["ts"]).replace("Z", "+00:00"))
        except (ValueError, KeyError, TypeError):
            continue
        if when >= since and entry.get("event") in ("agent_started", "gateway_connected", "gateway_disconnected", "gateway_unreachable"):
            entry["_when"] = when
            events.append(entry)
    return events


def connection_findings(events: list[dict[str, Any]], running: bool | None, now: datetime) -> list[Finding]:
    if not events:
        status = WARN if running else INFO
        return [Finding("connection", status, "the audit log has no connection events in the last 24 hours")]
    out = []
    last = next((e for e in reversed(events) if e["event"] in ("gateway_connected", "gateway_disconnected", "gateway_unreachable")), None)
    if running and last is not None:
        ago = int((now - last["_when"]).total_seconds())
        if last["event"] == "gateway_connected":
            out.append(Finding("connection", OK, f"connected to the gateway since {last['_when']:%m-%d %H:%M:%S} UTC"))
        else:
            reason = last.get("reason") or "the session ended"
            out.append(Finding("connection", FAIL, f"not connected: the last connection event ({ago}s ago) was {last['event']}: {reason}",
                               "see the network checks below; the agent keeps retrying by itself"))
    connects = sum(1 for e in events if e["event"] == "gateway_connected")
    starts = sum(1 for e in events if e["event"] == "agent_started")
    failures = Counter((e.get("reason") or "?").split(":")[0] for e in events if e["event"] == "gateway_unreachable")
    reconnects = max(0, connects - starts)
    top = ", ".join(f"{reason} x{count}" for reason, count in failures.most_common(3))
    summary = f"{connects} connections in 24h ({starts} agent starts, {reconnects} reconnects)" + (f"; failures: {top}" if top else "")
    if reconnects >= UNSTABLE_RECONNECTS:
        out.append(Finding("connection", WARN, "connection is unstable: " + summary,
                           "the gateway log names the side that gave up; frequent 'stopped answering' usually means the network drops idle connections or the machine sleeps"))
    else:
        out.append(Finding("connection", OK if reconnects < 3 else INFO, summary))
    return out


def network_findings(url: str, ssl_context: ssl.SSLContext | None, now: Callable[[], datetime]) -> list[Finding]:
    parts = urlsplit(url)
    host, port = parts.hostname or "", parts.port or (443 if parts.scheme == "wss" else 80)
    out = []
    try:
        addresses = sorted({info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except OSError as exc:
        return [Finding("network", FAIL, f"cannot resolve {host}: {exc}", "check DNS on this machine (nslookup " + host + ")")]
    out.append(Finding("network", OK, f"{host} resolves to {', '.join(addresses[:4])}"))
    try:
        sock = socket.create_connection((host, port), timeout=NET_TIMEOUT)
    except OSError as exc:
        return [*out, Finding("network", FAIL, f"cannot open TCP {host}:{port}: {exc}", "a firewall, proxy, or the gateway itself is blocking it")]
    with contextlib.closing(sock):
        if ssl_context is None:
            out.append(Finding("network", OK, f"TCP {host}:{port} answers (no TLS: the gateway is on this machine)"))
            return out
        try:
            tls = ssl_context.wrap_socket(sock, server_hostname=host if ssl_context.check_hostname else None)
        except ssl.SSLCertVerificationError as exc:
            hint = "the machine's clock may be wrong" if "not yet valid" in str(exc) or "expired" in str(exc) else "the certificate is not trusted here"
            return [*out, Finding("network", FAIL, f"TLS to {host} failed: {exc.verify_message or exc}", hint)]
        except (OSError, ssl.SSLError) as exc:
            return [*out, Finding("network", FAIL, f"TLS to {host} failed: {exc}", "something between this machine and the gateway is intercepting or blocking TLS")]
        with contextlib.closing(tls):
            cert = tls.getpeercert() or {}
            expires = cert.get("notAfter")
            if expires:
                days = int((datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), timezone.utc) - now()).total_seconds() // 86400)
                status = OK if days > CERT_WARN_DAYS else WARN
                out.append(Finding("network", status, f"TLS to {host}:{port} works; certificate valid for {days} more days"))
            else:
                out.append(Finding("network", OK, f"TLS to {host}:{port} works"))
            out.append(clock_finding(_http_date(tls, host), now()))
    return out


def _http_date(tls: ssl.SSLSocket, host: str) -> datetime | None:
    try:
        tls.settimeout(NET_TIMEOUT)
        tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: contextbridge-doctor\r\nConnection: close\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 65536:
            chunk = tls.recv(4096)
            if not chunk:
                break
            head += chunk
    except OSError:
        return None
    for line in head.decode("latin-1").split("\r\n")[1:]:
        if line.lower().startswith("date:"):
            with contextlib.suppress(TypeError, ValueError):
                return parsedate_to_datetime(line.split(":", 1)[1].strip())
    return None


def clock_finding(server_time: datetime | None, local: datetime) -> Finding:
    if server_time is None:
        return Finding("clock", INFO, "the gateway sent no Date header, so the clock was not compared")
    skew = (local - server_time).total_seconds()
    if abs(skew) > CLOCK_SKEW_WARN_SECONDS:
        return Finding("clock", WARN, f"this machine's clock is {skew:+.0f}s off the gateway's", "turn on automatic time sync (w32tm /resync, or timedatectl set-ntp true)")
    return Finding("clock", OK, f"clock within {abs(skew):.0f}s of the gateway")


# --------------------------------------------------------------------------------------------------- doctor


class Doctor:
    def __init__(self, config: str | None, *, offline: bool = False, run: Runner = subprocess.run,
                 startups: list[Startup] | None = None, now: Callable[[], datetime] | None = None) -> None:
        self.config_arg = config
        self.offline = offline
        self.run = run
        self.startups = startups
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.findings: list[Finding] = []
        self.device: str | None = None

    def add(self, *findings: Finding) -> None:
        self.findings.extend(findings)

    def examine(self) -> list[Finding]:
        from .remote.agent import FatalAgentError, Identity, load_agent_config

        self.add(Finding("install", OK if sys.version_info >= (3, 11) else FAIL,
                         f"Python {platform.python_version()} at {sys.executable}; contextbridge {__version__} from {Path(__file__).parent}"))

        startups = self.startups if self.startups is not None else discover(self.run)
        config_path: Path | None = Path(self.config_arg).expanduser().resolve() if self.config_arg else None
        if config_path is None:
            configs = {s.config for s in startups if s.config}
            if len(configs) == 1:
                config_path = Path(configs.pop()).expanduser().resolve()
            elif len(configs) > 1:
                self.add(Finding("config", FAIL, f"several agents are set up here ({', '.join(sorted(configs))})", "pass --config to pick one"))
                return self.findings
        if not startups:
            self.add(Finding("startup", WARN, "no scheduled task or systemd unit starts a ContextBridge agent here, so it will not start on its own",
                             "Windows: scripts/install-agent.ps1; Linux: a systemd unit running contextbridge-agent run --config ..."))
        for startup in startups:
            if config_path is None or not startup.config or _same_path(startup.config, config_path) or len(startups) == 1:
                self.add(*(task_findings(startup, config_path) if startup.kind == "windows-task" else unit_findings(startup, config_path, self.run)))
        if config_path is None:
            self.add(Finding("config", FAIL, "no agent config found", "pass --config PATH"))
            return self.findings

        try:
            config = load_agent_config(config_path)
        except FileNotFoundError:
            self.add(Finding("config", FAIL, f"{config_path} does not exist", "restore it from its .bak, or re-run the installer"))
            return self.findings
        except Exception as exc:  # noqa: BLE001 -- PolicyError, YAML errors, bad values: all mean the agent will not start
            self.add(Finding("config", FAIL, f"{config_path} does not load: {exc}", "fix the line it names, or restore the config from its .bak"))
            return self.findings
        self.device = config.name
        self.add(Finding("config", OK, f"{config_path}: device '{config.name}', gateway {config.gateway_url}, commands {config.policy.command_mode}"))

        try:
            identity = Identity.load(config.identity_path)
        except FatalAgentError as exc:
            self.add(Finding("identity", FAIL, str(exc), "enroll this device: contextbridge-admin pair on the gateway, then contextbridge-agent enroll --config ... --code ..."))
            identity = None
        if identity is not None:
            if identity.name != config.name:
                self.add(Finding("identity", FAIL, f"the identity belongs to '{identity.name}' but the config names '{config.name}'", "put the enrolled name back in the config"))
            else:
                self.add(Finding("identity", OK, f"enrolled as '{identity.name}' ({identity.device_id})"))
            if os.name != "nt" and config.identity_path.stat().st_mode & 0o077:
                self.add(Finding("identity", WARN, f"{config.identity_path} is readable by other users", f"chmod 600 {config.identity_path}"))

        running = agent_running(config.identity_path)
        if running is True:
            self.add(Finding("process", OK, "an agent is running with this identity"))
        elif running is False:
            self.add(Finding("process", FAIL, "no agent is running with this identity",
                             "start it through its task or unit; the log file it names says why it stopped"))
            self.add(*self._last_stop(startups))
        else:
            self.add(Finding("process", INFO, "could not tell whether an agent is running"))

        self.add(*connection_findings(read_audit(config.audit_path, self.now() - WINDOW), running, self.now()))

        if self.offline:
            self.add(Finding("network", INFO, "network checks skipped (--offline)"))
        else:
            try:
                context = config.ssl_context()
            except (OSError, ssl.SSLError) as exc:
                self.add(Finding("network", FAIL, f"cannot set up TLS from the config: {exc}", "check gateway.ca_file"))
            else:
                self.add(*network_findings(config.gateway_url, context, self.now))
        return self.findings

    def _last_stop(self, startups: list[Startup]) -> Iterator[Finding]:
        for startup in startups:
            log = startup.log_file
            if not log:
                continue
            with contextlib.suppress(OSError):
                lines = Path(log).read_text(encoding="utf-8", errors="replace").splitlines()[-400:]
                last = last_error(lines)
                if last:
                    yield Finding("process", INFO, f"last error in {log}: {last[:300]}")

    @property
    def status(self) -> str:
        worst = max((RANK[f.status] for f in self.findings), default=0)
        return {0: OK, 1: WARN, 2: FAIL}[worst]


def last_error(lines: list[str]) -> str | None:
    """The agent's own stop message, or the last line of a traceback or SystemExit, from its --log-file."""
    for line in reversed(lines):
        text = line.rstrip()
        if not text or text.startswith("[agent audit]") or text[0].isspace() or text.startswith("Traceback"):
            continue
        if text.startswith("[agent] ") and "stopped" not in text:
            continue  # "connecting to ...", warnings
        return text
    return None


MARK = {OK: "ok  ", INFO: "info", WARN: "WARN", FAIL: "FAIL"}


def render(doctor: Doctor) -> str:
    lines = [f"ContextBridge doctor on {socket.gethostname()} ({platform.system()} {platform.release()})"]
    for f in doctor.findings:
        lines.append(f"[{MARK[f.status]}] {f.check:<10} {f.summary}")
        if f.fix and f.status in (WARN, FAIL):
            lines.append(f"{'':18}fix: {f.fix}")
    counts = Counter(f.status for f in doctor.findings)
    lines.append(f"\n{doctor.status.upper()}: {counts[FAIL]} failed, {counts[WARN]} warnings")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Diagnose the ContextBridge agent on this machine. Changes nothing.")
    ap.add_argument("--config", help="agent config (default: the one its scheduled task or systemd unit uses)")
    ap.add_argument("--offline", action="store_true", help="skip the DNS, TCP, TLS and clock checks")
    ap.add_argument("--json", action="store_true", help="print the findings as JSON")
    args = ap.parse_args(argv)
    started = time.monotonic()
    doctor = Doctor(args.config, offline=args.offline)
    try:
        doctor.examine()
    except Exception as exc:  # noqa: BLE001 -- the doctor itself must not die with a traceback
        print(f"contextbridge-doctor could not finish: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
    if args.json:
        print(json.dumps({
            "host": socket.gethostname(), "platform": f"{platform.system()} {platform.release()}", "device": doctor.device,
            "version": __version__, "status": doctor.status, "seconds": round(time.monotonic() - started, 2),
            "findings": [asdict(f) for f in doctor.findings],
        }, indent=2))
    else:
        print(render(doctor))
    sys.exit(1 if doctor.status == FAIL else 0)


if __name__ == "__main__":
    main()
