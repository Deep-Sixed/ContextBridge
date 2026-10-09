"""Failover drill: prove ContextBridge serves every device with Desktop Commander stopped.

Run it on the gateway host after stopping Desktop Commander (its MCP server, its
remote agent, and anything launched through ``npx``):

    export CONTEXTBRIDGE_COMPUTER_TOKEN=...          # the local listener's token
    contextbridge-failover --config configs/computer.yaml            # read-only probes
    contextbridge-failover --config configs/computer.yaml --write    # plus a write round trip

It checks, and prints PASS / FAIL / SKIP for each item:

1. **Desktop Commander is not running** on this machine (no process whose
   command line names it).
2. **The gateway answers** over MCP with the computer tool surface.
3. **Every device** (``local`` and each enrolled agent, or those named with
   ``--device``) is online and serves its tools: system info, directory
   listing, file search, a file read, a harmless command run both directly and
   as a session, and process listing. ``--write`` adds create, write, edit,
   move, read-back, metadata, and content search under
   ``<first writable root>/.contextbridge-failover/``.

Nothing is deleted, no process is killed, and with ``--write`` only that probe
directory is touched. Exit status: 0 ready, 1 not ready, 2 could not run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import anyio
import yaml

from .computer.server import (
    KNOWLEDGE_TOKEN_ENV,
    LIST_DEVICES_TOOL,
    LOCAL_DEVICE,
    SERVER_TOOLS,
    TOKEN_ENV,
)

DEFAULT_URL = "http://127.0.0.1:8791/mcp"
PROBE_DIR = ".contextbridge-failover"
# Substrings of a command line that identify Desktop Commander: its npm scope and package
# names (MCP server and remote agent), as launched by npx, node, or an installed binary.
DC_MARKERS = ("@wonderwhy-er", "desktop-commander", "desktopcommander", "claude-server-commander")
# Commands that only report on the machine; the drill runs the first one the device allows.
PROBE_COMMANDS = ("hostname", "whoami", "uname", "pwd", "date")
CALL_TIMEOUT_SECONDS = 60
SMALL_FILE_BYTES = 64 * 1024

PASS, FAIL, SKIP = "pass", "fail", "skip"


@dataclass(frozen=True)
class Parity:
    """How ContextBridge covers one Desktop Commander tool."""

    kind: str  # "same": same tool; "equivalent": other tools do it; "omitted": deliberately not a tool; "gap"
    tools: tuple[str, ...] = ()
    note: str = ""


# Every tool Desktop Commander exposes (local MCP server and Remote: the 31 in
# docs/desktop-commander-inventory.pdf) and its ContextBridge counterpart. The failover
# acceptance test exercises every tool named here on a local and a remote device.
DESKTOP_COMMANDER_PARITY: dict[str, Parity] = {
    # filesystem
    "read_file": Parity("same", ("read_file",), "offset, negative offset (tail), and length"),
    "read_multiple_files": Parity("equivalent", ("read_file",), "one read_file call per file"),
    "write_file": Parity("same", ("write_file",), "atomic rewrite or append"),
    "edit_block": Parity("same", ("edit_block",), "exact replacement; refuses an unexpected match count"),
    "create_directory": Parity("same", ("create_directory",)),
    "list_directory": Parity("same", ("list_directory",), "recursive to depth 5"),
    "move_file": Parity("same", ("move_file",)),
    "get_file_info": Parity("same", ("get_file_info",)),
    # search
    "start_search": Parity("equivalent", ("search_files", "search_code"), "synchronous, capped by result count and time"),
    "get_more_search_results": Parity("equivalent", ("search_files", "search_code"), "raise max_results or narrow the path"),
    "stop_search": Parity("omitted", (), "searches finish within max_search_seconds; nothing runs in the background"),
    "list_searches": Parity("omitted", (), "no background searches exist"),
    # terminal
    "start_process": Parity("same", ("start_process", "run_command"), "run_command for one-shot commands"),
    "read_process_output": Parity("same", ("read_process_output",)),
    "interact_with_process": Parity("same", ("interact_with_process",)),
    "force_terminate": Parity("same", ("force_terminate",), "kills the whole process tree"),
    "list_sessions": Parity("same", ("list_sessions",)),
    # processes
    "list_processes": Parity("same", ("list_processes",)),
    "kill_process": Parity("same", ("kill_process",), "only where the device's policy sets allow_kill"),
    # documents
    "write_pdf": Parity("gap", (), "no PDF, Excel, or Word tools; text formats are read and edited as text"),
    # remote devices
    "list_devices": Parity("same", ("list_devices",), "online state, last seen, tools, and policy"),
    "ping": Parity("equivalent", ("list_devices",), "online state from heartbeats"),
    "shutdown": Parity("omitted", (), "on the host: contextbridge-admin revoke, or stop the agent's service"),
    "who_am_i": Parity("gap", (), "the caller's client id is recorded in the audit log, not returned"),
    # configuration
    "get_config": Parity("equivalent", ("get_system_info", "list_devices"), "each device's policy summary"),
    "set_config_value": Parity("omitted", (), "policy changes only on the host, so a client cannot widen its own access"),
    # monitoring
    "get_usage_stats": Parity("omitted", (), "the host's JSONL audit log records every call"),
    "get_recent_tool_calls": Parity("omitted", (), "the host's JSONL audit log records every call"),
    "get_tool_result": Parity("omitted", (), "calls complete within call_timeout_seconds; none is left pending"),
    "list_remote_tool_calls": Parity("omitted", (), "calls complete within call_timeout_seconds; none is left pending"),
    "give_feedback_to_desktop_commander": Parity("omitted", (), "Desktop Commander product feedback"),
}


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""


@dataclass
class DeviceReport:
    device: str
    online: bool
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.online and all(c.status != FAIL for c in self.checks)


@dataclass
class Report:
    url: str
    desktop_commander: Check
    gateway: Check
    devices: list[DeviceReport] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return (
            self.desktop_commander.status == PASS
            and self.gateway.status == PASS
            and bool(self.devices)
            and all(d.ok for d in self.devices)
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ready"] = self.ready
        for device, report in zip(data["devices"], self.devices):
            device["ok"] = report.ok
        return data


# --------------------------------------------------------- Desktop Commander


def desktop_commander_processes(*, exclude: set[int] | None = None) -> list[dict[str, Any]]:
    """Running processes whose name or command line identifies Desktop Commander."""
    import psutil

    skip = {os.getpid(), *(exclude or set())}
    found = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if proc.info["pid"] in skip:
                continue
            argv = proc.info.get("cmdline") or []
            text = " ".join([proc.info.get("name") or "", *argv]).lower()
        except (psutil.Error, OSError):
            continue
        if any(marker in text for marker in DC_MARKERS):
            found.append({"pid": proc.info["pid"], "name": proc.info.get("name"), "cmdline": " ".join(argv)[:200]})
    return found


def check_desktop_commander() -> Check:
    running = desktop_commander_processes()
    if not running:
        return Check("desktop_commander", PASS, "not running")
    listed = "; ".join(f"pid {p['pid']}: {p['cmdline'] or p['name']}" for p in running)
    return Check("desktop_commander", FAIL, f"still running ({listed}); stop it for a real failover test")


# ------------------------------------------------------------------- probes


def _join(root: str, *parts: str) -> str:
    sep = "\\" if "\\" in root and "/" not in root else "/"
    return sep.join([root.rstrip("\\/"), *parts])


def pick_probe_command(policy: dict[str, Any]) -> str | None:
    """A harmless command this device's policy allows, or None if it runs no commands."""
    mode = policy.get("command_mode")
    if mode == "unrestricted":
        return PROBE_COMMANDS[0]
    if mode != "allowlist":
        return None
    allowed = {Path(name).stem.lower() for name in policy.get("command_allowlist") or []}
    return next((c for c in PROBE_COMMANDS if c in allowed), None)


class DeviceProbe:
    """Runs one device's checks through the MCP client, recording each outcome."""

    def __init__(self, client: Any, row: dict[str, Any], *, write: bool, command: str | None) -> None:
        self.client = client
        self.name = row["device"]
        self.tools = set(row.get("tools") or [])
        self.policy = row.get("policy") or {}
        self.write = write
        self.command = command if command is not None else pick_probe_command(self.policy)
        self.report = DeviceReport(self.name, bool(row.get("online")))

    async def call(self, tool: str, **args: Any) -> dict[str, Any]:
        with anyio.fail_after(CALL_TIMEOUT_SECONDS):
            result = await self.client.call_tool(tool, {**args, "device": self.name})
        return result.structured_content or {}

    async def check(self, name: str, tool: str, run: Callable[[], Awaitable[str]], *, why_skipped: str = "") -> None:
        if tool not in self.tools:
            self.report.checks.append(Check(name, SKIP, why_skipped or f"{tool} is not enabled on this device"))
            return
        try:
            detail = await run()
        except Exception as exc:  # noqa: BLE001 -- every failure is a finding, never a crash of the drill
            self.report.checks.append(Check(name, FAIL, f"{type(exc).__name__}: {exc}"[:300]))
            return
        self.report.checks.append(Check(name, PASS, detail))

    async def run(self) -> DeviceReport:
        if not self.report.online:
            self.report.checks.append(Check("online", FAIL, "device is offline"))
            return self.report
        roots = self.policy.get("readable_roots") or []
        root = roots[0] if roots else "."
        listing: list[dict[str, Any]] = []

        async def system_info() -> str:
            info = await self.call("get_system_info")
            return f"{info.get('hostname', '?')} ({info.get('os', '?')} {info.get('os_release', '')})".strip()

        async def list_directory() -> str:
            result = await self.call("list_directory", path=root)
            listing.extend(result.get("entries") or [])
            return f"{len(listing)} entries in {root}"

        async def search_files() -> str:
            result = await self.call("search_files", path=root, pattern="*", max_results=5)
            return f"{len(result.get('matches') or [])} matches"

        async def read_file() -> str:
            candidates = [e for e in listing if e.get("type") == "file" and (e.get("size") or 0) <= SMALL_FILE_BYTES]
            errors = []
            for entry in candidates[:5]:
                try:
                    result = await self.call("read_file", path=_join(root, entry["path"]), length=5)
                except Exception as exc:  # noqa: BLE001 -- binary or unreadable: try the next file
                    errors.append(f"{entry['path']}: {exc}")
                    continue
                return f"read {entry['path']} ({len(result.get('content', ''))} chars)"
            if errors:
                raise RuntimeError("; ".join(errors))
            return "no small file at the top of the first root to read"

        async def run_command() -> str:
            result = await self.call("run_command", command=self.command, timeout_seconds=30)
            if result.get("exit_code") != 0:
                raise RuntimeError(f"exit {result.get('exit_code')}: {result.get('stderr', '')[:120]}")
            return f"{self.command} → {result.get('stdout', '').strip()[:60]!r}"

        async def session() -> str:
            started = await self.call("start_process", command=self.command, wait_seconds=2)
            session_id = started["session_id"]
            output = started.get("output", "")
            more = await self.call("read_process_output", session_id=session_id, wait_seconds=2)
            output += more.get("output", "")
            listed = await self.call("list_sessions")
            if session_id not in {s.get("session_id") for s in listed.get("sessions") or []}:
                raise RuntimeError(f"session {session_id} missing from list_sessions")
            await self.call("force_terminate", session_id=session_id)
            if not output.strip():
                raise RuntimeError("session produced no output")
            return f"session {session_id}: {output.strip()[:60]!r}"

        async def list_processes() -> str:
            result = await self.call("list_processes", limit=5)
            return f"{result.get('matched', '?')} processes"

        await self.check("system_info", "get_system_info", system_info)
        await self.check("list_directory", "list_directory", list_directory)
        await self.check("search_files", "search_files", search_files)
        await self.check("read_file", "read_file", read_file)
        no_command = "the device's command policy allows none of: " + ", ".join(PROBE_COMMANDS)
        if self.command is None:
            self.report.checks.append(Check("run_command", SKIP, no_command))
            self.report.checks.append(Check("session", SKIP, no_command))
        else:
            await self.check("run_command", "run_command", run_command)
            await self.check("session", "start_process", session)
        await self.check("list_processes", "list_processes", list_processes)
        if self.write:
            await self.write_round_trip()
        return self.report

    async def write_round_trip(self) -> None:
        writable = self.policy.get("writable_roots") or []
        if not writable:
            self.report.checks.append(Check("write_round_trip", SKIP, "the device has no writable roots"))
            return
        folder = _join(writable[0], PROBE_DIR)
        probe = _join(folder, "probe.txt")
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        async def round_trip() -> str:
            await self.call("create_directory", path=folder)
            await self.call("write_file", path=probe, content=f"contextbridge failover probe {stamp}\nstatus: pending\n")
            await self.call("edit_block", path=probe, old_string="status: pending", new_string="status: verified")
            moved = _join(folder, f"probe.moved-{int(time.time())}.txt")
            await self.call("move_file", source=probe, destination=moved)
            await self.call("move_file", source=moved, destination=probe)
            content = (await self.call("read_file", path=probe)).get("content", "")
            if f"probe {stamp}" not in content or "status: verified" not in content:
                raise RuntimeError(f"read back unexpected content: {content[:120]!r}")
            info = await self.call("get_file_info", path=probe)
            hits = await self.call("search_code", path=folder, pattern="status: verified")
            if not hits.get("matches"):
                raise RuntimeError("search_code did not find the edited text")
            return f"{probe} ({info.get('size', '?')} bytes)"

        await self.check("write_round_trip", "write_file", round_trip)


# ------------------------------------------------------------------ drill


async def run_drill(
    url: str, token: str, *, devices: list[str] | None = None, write: bool = False, command: str | None = None
) -> Report:
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth

    report = Report(url=url, desktop_commander=check_desktop_commander(), gateway=Check("gateway", FAIL))
    try:
        async with Client(url, auth=BearerAuth(token), timeout=CALL_TIMEOUT_SECONDS) as client:
            tools = {t.name for t in await client.list_tools()}
            unknown = tools - SERVER_TOOLS
            if LIST_DEVICES_TOOL not in tools or unknown:
                report.gateway.detail = f"not a ContextBridge computer endpoint (tools: {sorted(tools)[:8]})"
                return report
            listed = (await client.call_tool(LIST_DEVICES_TOOL, {})).structured_content["devices"]
            server = getattr(getattr(client, "initialize_result", None), "serverInfo", None)
            name = f"{server.name} {server.version}" if server else "ContextBridge"
            report.gateway = Check("gateway", PASS, f"{name}: {len(tools)} tools, {len(listed)} device(s)")
            rows = {row["device"]: row for row in listed}
            for wanted in devices or []:
                if wanted not in rows:
                    report.devices.append(DeviceReport(wanted, False, [Check("online", FAIL, "not enrolled")]))
            selected = [rows[d] for d in (devices or sorted(rows, key=lambda d: (d != LOCAL_DEVICE, d))) if d in rows]
            for row in selected:
                report.devices.append(await DeviceProbe(client, row, write=write, command=command).run())
    except Exception as exc:  # noqa: BLE001 -- unreachable, refused, or dropped: a finding, never a crash
        lost = "connection lost during the checks: " if report.gateway.status == PASS else ""
        report.gateway = Check("gateway", FAIL, f"{lost}{type(exc).__name__}: {exc}"[:300])
    return report


def render(report: Report) -> str:
    marks = {PASS: "PASS", FAIL: "FAIL", SKIP: "skip"}
    lines = [f"ContextBridge failover check: {report.url}", ""]

    def row(label: str, check: Check, indent: str = "") -> None:
        lines.append(f"{indent}{marks[check.status]:<5} {label:<18} {check.detail}")

    row("Desktop Commander", report.desktop_commander)
    row("gateway", report.gateway)
    for device in report.devices:
        lines.append("")
        lines.append(f"device {device.device}: {'online' if device.online else 'OFFLINE'}")
        for check in device.checks:
            row(check.name, check, "  ")
    lines.append("")
    names = ", ".join(d.device for d in report.devices) or "no devices"
    if report.ready:
        lines.append(f"READY: ContextBridge serves {names} with Desktop Commander stopped.")
    else:
        lines.append("NOT READY: fix the FAIL lines above and run the drill again.")
    return "\n".join(lines)


def _url_from_config(path: str) -> str:
    cfg = yaml.safe_load(Path(path).expanduser().read_text(encoding="utf-8")) or {}
    serve = cfg.get("serve") or {}
    host = str(serve.get("host", "127.0.0.1"))
    host = f"[{host}]" if ":" in host else host
    return f"http://{host}:{serve.get('port', 8791)}/mcp"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(
        description="Check that ContextBridge serves every device with Desktop Commander stopped."
    )
    target = ap.add_mutually_exclusive_group()
    target.add_argument("--config", help="gateway config (reads serve.host and serve.port)")
    target.add_argument("--url", help=f"computer MCP endpoint (default {DEFAULT_URL})")
    ap.add_argument("--device", action="append", help="check only this device (repeatable); default: all")
    ap.add_argument("--write", action="store_true", help=f"also write, edit, and move a file under {PROBE_DIR}/")
    ap.add_argument("--command", help="probe command to run instead of the first allowed of: " + ", ".join(PROBE_COMMANDS))
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    args = ap.parse_args(argv)

    token = os.environ.get(TOKEN_ENV, "")
    if not token:
        print(f"{TOKEN_ENV} must be set to the computer route's token.", file=sys.stderr)
        sys.exit(2)
    if token == os.environ.get(KNOWLEDGE_TOKEN_ENV):
        print(f"{TOKEN_ENV} equals {KNOWLEDGE_TOKEN_ENV}; use the computer route's own token.", file=sys.stderr)
        sys.exit(2)
    url = _url_from_config(args.config) if args.config else (args.url or DEFAULT_URL)
    report = anyio.run(
        lambda: run_drill(url, token, devices=args.device, write=args.write, command=args.command)
    )
    print(json.dumps(report.to_dict(), indent=2) if args.json else render(report))
    sys.exit(0 if report.ready else 1)


if __name__ == "__main__":
    main()
