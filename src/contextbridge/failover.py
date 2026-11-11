"""Failover drill: prove ContextBridge serves every device with its own gateway and agents.

Run it on the gateway host, with the gateway and each remote agent running:

    export CONTEXTBRIDGE_COMPUTER_TOKEN=...          # the local listener's token
    contextbridge-failover --config configs/computer.yaml            # read-only probes
    contextbridge-failover --config configs/computer.yaml --write    # plus a write round trip

It checks, and prints PASS / FAIL / SKIP for each item:

1. **The gateway answers** over MCP with the computer tool surface.
2. **Every device** (``local`` and each enrolled agent, or those named with
   ``--device``) is online and serves its tools: system info, directory
   listing, file search, a file read, a harmless command run both directly and
   as a session, and process listing. ``--write`` adds create, write, edit,
   move, read-back, metadata, and content search; Word, PDF, and Excel files
   written and read back; and a delete that is then restored from the trash
   (where the device keeps one), all under
   ``<first writable root>/.contextbridge-failover/``.

No process is killed, and with ``--write`` only that probe directory is touched:
the one file the drill deletes is its own, and it is restored where the device
keeps a trash. Exit status: 0 ready, 1 not ready, 2 could not run.
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
    LIST_DEVICES_TOOL,
    LOCAL_DEVICE,
    SERVER_TOOLS,
    TOKEN_ENV,
)

DEFAULT_URL = "http://127.0.0.1:8791/mcp"
PROBE_DIR = ".contextbridge-failover"
# Commands that only report on the machine; the drill runs the first one the device allows.
PROBE_COMMANDS = ("hostname", "whoami", "uname", "pwd", "date")
CALL_TIMEOUT_SECONDS = 60
SMALL_FILE_BYTES = 64 * 1024

PASS, FAIL, SKIP = "pass", "fail", "skip"


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
    gateway: Check
    devices: list[DeviceReport] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.gateway.status == PASS and bool(self.devices) and all(d.ok for d in self.devices)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ready"] = self.ready
        for device, report in zip(data["devices"], self.devices):
            device["ok"] = report.ok
        return data


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

        async def documents() -> str:
            await self.call("create_directory", path=folder)
            text = f"# ContextBridge failover probe\n\nWritten {stamp}."
            for name in ("probe.docx", "probe.pdf"):
                await self.call("write_document", path=_join(folder, name), content=text)
                found = await self.call("read_document", path=_join(folder, name), find=stamp)
                if not found.get("matches"):
                    raise RuntimeError(f"{name} did not read back")
            sheet = _join(folder, "probe.xlsx")
            await self.call("write_spreadsheet", path=sheet, rows=[["probe", stamp]])
            rows = (await self.call("read_document", path=sheet)).get("rows")
            if rows != [["probe", stamp]]:
                raise RuntimeError(f"probe.xlsx read back {rows!r}")
            return "probe.docx, probe.pdf, probe.xlsx written and read back"

        async def delete() -> str:
            await self.call("create_directory", path=folder)
            victim = _join(folder, "delete-me.txt")
            await self.call("write_file", path=victim, content=f"deleted by the failover drill {stamp}\n")
            deleted = await self.call("delete_file", path=victim)
            if not deleted.get("restorable"):
                return "deleted permanently (the device keeps no trash)"
            listed = await self.call("list_deleted", limit=500)
            if deleted["trash_id"] not in {item.get("trash_id") for item in listed.get("items") or []}:
                raise RuntimeError(f"{deleted['trash_id']} missing from list_deleted")
            await self.call("restore_deleted", trash_id=deleted["trash_id"])
            content = (await self.call("read_file", path=victim)).get("content", "")
            if stamp not in content:
                raise RuntimeError("the restored file has different content")
            return f"deleted to the trash and restored ({deleted['trash_id']})"

        await self.check("documents", "write_document", documents)
        await self.check("delete", "delete_file", delete)


# ------------------------------------------------------------------ drill


async def run_drill(
    url: str, token: str, *, devices: list[str] | None = None, write: bool = False, command: str | None = None
) -> Report:
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth

    report = Report(url=url, gateway=Check("gateway", FAIL))
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

    row("gateway", report.gateway)
    for device in report.devices:
        lines.append("")
        lines.append(f"device {device.device}: {'online' if device.online else 'OFFLINE'}")
        for check in device.checks:
            row(check.name, check, "  ")
    lines.append("")
    names = ", ".join(d.device for d in report.devices) or "no devices"
    if report.ready:
        lines.append(f"READY: ContextBridge serves {names}.")
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
    ap = argparse.ArgumentParser(description="Check that ContextBridge serves every device.")
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
    url = _url_from_config(args.config) if args.config else (args.url or DEFAULT_URL)
    report = anyio.run(
        lambda: run_drill(url, token, devices=args.device, write=args.write, command=args.command)
    )
    print(json.dumps(report.to_dict(), indent=2) if args.json else render(report))
    sys.exit(0 if report.ready else 1)


if __name__ == "__main__":
    main()
