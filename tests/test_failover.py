"""Phase 6: failover acceptance. ContextBridge serves both machines on its own.

The acceptance criterion from docs/capability-roadmap.pdf: "ContextBridge operates
against Friday and Thanatos using only its own agents, permissions, transport, and
tools, with no third-party remote-access service."

The whole deployment -- the computer gateway with its agent and OAuth
listeners, and a remote agent standing in for Thanatos -- runs from the shipped
entry points inside a jail:

* tripwire ``npx`` and ``node`` programs come first on PATH and record any call;
* ``failover_jail/sitecustomize.py`` refuses and records every network destination
  off this machine, so no hosted relay, registry, or update check can be reached.

The test then proves, on both devices: the failover drill passes, every computer
tool the deployment enables works, an OAuth (ChatGPT/Claude-style) client works, the agent and OAuth tokens survive a gateway restart,
and nothing ever touched a tripwire or the network.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import anyio
import httpx
import pytest
import yaml
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.exceptions import ToolError
from helpers import (
    IS_WINDOWS,
    PY,
    cli,
    free_port,
    isolated_env,
    python_cmd,
    read_log,
    serve,
    spawn_logged,
)
from test_oauth import PASSPHRASE, REDIRECT, form_fields, next_code, pkce

from contextbridge.computer.server import SCOPE_READ, SERVER_TOOLS
from contextbridge.failover import (
    PROBE_COMMANDS,
    _join,
    pick_probe_command,
    render,
    run_drill,
)
from contextbridge.oauth.store import OAuthStore

JAIL_DIR = Path(__file__).with_name("failover_jail")
COMPUTER_TOKEN = "computer-" + "f" * 40
TRIPWIRES = ("npx", "node")
THANATOS = "thanatos"
# Computer tools the deployment below leaves off, and why. Every other tool must
# work on both devices.
NOT_EXERCISED = {
    "list_windows": "needs a graphical session; the device policies leave desktop observation off",
    "media_inventory": "the device policies leave media discovery off",
}


# ------------------------------------------------------------------ the jail


@dataclass
class Jail:
    env: dict[str, str]
    tripwire_dir: Path
    tripwire_log: Path
    network_log: Path

    def hits(self) -> str:
        return read_log(self.tripwire_log) + read_log(self.network_log)


def build_jail(tmp_path: Path) -> Jail:
    """An environment without Node or npx, in which only this machine is reachable."""
    tripwire_dir = tmp_path / "tripwire-bin"
    tripwire_dir.mkdir()
    tripwire_log = tmp_path / "tripwire.log"
    for name in TRIPWIRES:
        if IS_WINDOWS:
            script = tripwire_dir / f"{name}.cmd"
            # Text mode writes CRLF on Windows, as cmd.exe expects.
            script.write_text(f'@echo off\necho {name} %*>>"{tripwire_log}"\nexit /b 97\n', encoding="utf-8")
        else:
            script = tripwire_dir / name
            script.write_text(f'#!/bin/sh\necho "{name} $*" >> "{tripwire_log}"\nexit 97\n', encoding="utf-8")
            script.chmod(0o755)

    home = tmp_path / "home"
    home.mkdir()

    network_log = tmp_path / "network-jail.log"
    env = isolated_env()
    env["PATH"] = os.pathsep.join([str(tripwire_dir), env["PATH"]])
    env["PYTHONPATH"] = os.pathsep.join([str(JAIL_DIR), env["PYTHONPATH"]])
    env["CONTEXTBRIDGE_JAIL_LOG"] = str(network_log)
    env["HOME"] = str(home)
    if IS_WINDOWS:
        env["USERPROFILE"] = str(home)
    return Jail(env, tripwire_dir, tripwire_log, network_log)


@pytest.fixture
def jail(tmp_path):
    return build_jail(tmp_path)


def test_the_jail_is_armed(jail):
    """The jail must actually catch what it claims to, or the failover test proves nothing."""
    npx = shutil.which("npx", path=jail.env["PATH"])
    assert npx and Path(npx).parent == jail.tripwire_dir
    assert subprocess.run([npx, "--version"], env=jail.env, capture_output=True, check=False).returncode == 97
    assert "npx --version" in read_log(jail.tripwire_log)

    probe = (
        "import socket\n"
        "socket.getaddrinfo('localhost', 80)\n"
        "socket.getaddrinfo('127.0.0.1', 80)\n"
        "for target in (lambda: socket.getaddrinfo('relay.example.com', 443),\n"
        "               lambda: socket.socket().connect(('192.0.2.10', 443))):\n"
        "    try:\n"
        "        target()\n"
        "    except OSError as exc:\n"
        "        print('refused', type(exc).__name__)\n"
    )
    run = subprocess.run(
        [sys.executable, "-c", probe], env=jail.env, capture_output=True, text=True, timeout=60, check=False
    )
    assert run.stdout.split("\n")[:2] == ["refused gaierror", "refused ConnectionRefusedError"], run.stderr
    logged = read_log(jail.network_log)
    assert "relay.example.com" in logged and "192.0.2.10" in logged and "localhost" not in logged


# ------------------------------------------------------------- drill units


def test_probe_command_comes_from_the_device_policy():
    assert pick_probe_command({"command_mode": "allowlist", "command_allowlist": ["git", "whoami.exe"]}) == "whoami"
    assert pick_probe_command({"command_mode": "allowlist", "command_allowlist": ["git"]}) is None
    assert pick_probe_command({"command_mode": "unrestricted"}) == PROBE_COMMANDS[0]
    assert pick_probe_command({"command_mode": "disabled"}) is None


def test_probe_paths_keep_the_device_separator():
    assert _join("/home/c/work", ".contextbridge-failover", "probe.txt") == "/home/c/work/.contextbridge-failover/probe.txt"
    assert _join("C:\\Users\\c\\work\\", "x", "probe.txt") == "C:\\Users\\c\\work\\x\\probe.txt"


def test_drill_reports_an_unreachable_gateway_instead_of_crashing():
    report = anyio.run(lambda: run_drill(f"http://127.0.0.1:{free_port()}/mcp", "x" * 40))
    assert report.gateway.status == "fail" and report.gateway.detail
    assert report.ready is False and "NOT READY" in render(report)


def test_tools_left_out_of_the_failover_run_are_real_tools():
    assert set(NOT_EXERCISED) <= SERVER_TOOLS


# ------------------------------------------------------------- deployment


def make_workspace(root: Path, label: str) -> Path:
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "notes.md").write_bytes(b"alpha\nbeta\ngamma\n")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_bytes(f"def main():\n    return '{label}'\n".encode())
    (root / ".ssh").mkdir()
    (root / ".ssh" / "id_ed25519").write_bytes(b"PRIVATE")
    (root / "work").mkdir()
    (root / "README.txt").write_bytes(f"{label} workspace\n".encode())
    return root


def device_policy(root: Path) -> dict:
    return {
        "filesystem": {"roots": [str(root)], "writable_roots": [str(root / "work")]},
        "commands": {"mode": "allowlist", "allow": [PY, "hostname"], "max_timeout_seconds": 60},
        "processes": {"list": True, "allow_kill": True},
    }


def wait_port(port: int, log: Path, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            if time.monotonic() > deadline:
                raise AssertionError(f"port {port} never opened:\n{read_log(log)}") from None
            time.sleep(0.1)


def run_async(fn, *args):
    return anyio.run(fn, *args)


async def with_client(url: str, token: str, fn):
    async with Client(url, auth=BearerAuth(token), timeout=120) as client:
        return await fn(client)


async def wait_online(client, device: str, timeout: float = 60) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        devices = (await client.call_tool("list_devices", {})).structured_content["devices"]
        row = next((d for d in devices if d["device"] == device), None)
        if row and row["online"]:
            return row
        await anyio.sleep(0.25)
    raise AssertionError(f"{device} never came online")


def drill_cli(env: dict, url: str, *args: str) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, "-m", "contextbridge.failover", "--url", url, "--json", *args],
        env={**env, "CONTEXTBRIDGE_COMPUTER_TOKEN": COMPUTER_TOKEN},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    try:
        return proc.returncode, json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise AssertionError(f"drill printed no report (exit {proc.returncode}):\n{proc.stdout}\n{proc.stderr}") from None


def failed_checks(report: dict) -> list[str]:
    gateway = report["gateway"]
    bad = [f"{gateway['name']}: {gateway['detail']}"] if gateway["status"] == "fail" else []
    for device in report["devices"]:
        bad += [f"{device['device']}/{c['name']}: {c['detail']}" for c in device["checks"] if c["status"] == "fail"]
    return bad


# ---------------------------------------------- every tool, on each device


async def exercise_tools(client, device: str, used: dict[str, set[str]]) -> None:
    """Use, on ``device``, every computer tool the deployment enables, recording each in ``used``."""
    seen = used.setdefault(device, set())

    async def call(tool: str, **args):
        result = await client.call_tool(tool, {**args, "device": device})
        seen.add(tool)
        return result.structured_content

    # read_file: ranges, tails, and several files
    assert (await call("read_file", path="docs/notes.md", offset=1, length=1))["content"] == "beta\n"
    assert (await call("read_file", path="docs/notes.md", offset=-1))["content"] == "gamma\n"
    assert "def main" in (await call("read_file", path="src/app.py"))["content"]
    # create_directory / write_file / edit_block / move_file / get_file_info / list_directory
    await call("create_directory", path="work/failover/nested")
    await call("write_file", path="work/failover/nested/log.txt", content="dup\n")
    await call("write_file", path="work/failover/nested/log.txt", content="dup\n", mode="append")
    with pytest.raises(ToolError, match="found 2"):  # ambiguity detection: two matches, one expected
        await client.call_tool(
            "edit_block",
            {"path": "work/failover/nested/log.txt", "old_string": "dup", "new_string": "x", "device": device},
        )
    await call("edit_block", path="work/failover/nested/log.txt", old_string="dup", new_string="done", expected_replacements=2)
    await call("move_file", source="work/failover/nested/log.txt", destination="work/failover/log.txt")
    assert (await call("get_file_info", path="work/failover/log.txt"))["size"] == len("done\ndone\n")
    listing = await call("list_directory", path="work", depth=3)
    assert {e["path"].replace("\\", "/") for e in listing["entries"]} >= {"failover/log.txt", "failover/nested"}
    # search_files / search_code: names and contents, bounded
    names = await call("search_files", path=".", pattern="*.md")
    assert [m["path"].replace("\\", "/").endswith("/docs/notes.md") for m in names["matches"]] == [True]
    code = await call("search_code", path=".", pattern="def main", file_pattern="*.py")
    assert [m["path"].replace("\\", "/").endswith("src/app.py") for m in code["matches"]] == [True]
    # the deny list still holds
    with pytest.raises(ToolError, match="denied"):
        await client.call_tool("read_file", {"path": ".ssh/id_ed25519", "device": device})
    # start_process / interact_with_process / read_process_output / list_sessions / force_terminate: a REPL
    repl = python_cmd("import sys\nfor line in sys.stdin:\n    print(eval(line), flush=True)")
    sid = (await call("start_process", command=repl, wait_seconds=0.5))["session_id"]
    reply = await call("interact_with_process", session_id=sid, input="6*7", wait_seconds=5)
    output = reply["output"]
    for _ in range(20):
        if "42" in output:
            break
        output += (await call("read_process_output", session_id=sid, wait_seconds=0.5))["output"]
    assert "42" in output
    assert sid in {s["session_id"] for s in (await call("list_sessions"))["sessions"]}
    assert (await call("force_terminate", session_id=sid))["running"] is False
    # run_command: one-shot, with exit status and output
    ran = await call("run_command", command=python_cmd("print('failover ok')"))
    assert ran["exit_code"] == 0 and ran["stdout"].strip() == "failover ok"
    # list_processes / kill_process
    victim = await call("start_process", command=python_cmd("import time; time.sleep(300)"), wait_seconds=0.2)
    processes = await call("list_processes", name_filter="time.sleep(300)", limit=50)
    assert victim["pid"] in {p["pid"] for p in processes["processes"]}
    await call("kill_process", pid=victim["pid"], force=True)
    for _ in range(40):
        status = await call("read_process_output", session_id=victim["session_id"], wait_seconds=0.25)
        if not status["running"]:
            break
    assert status["running"] is False
    await call("force_terminate", session_id=victim["session_id"])
    # documents: PDF, Word, and Excel
    await call("write_document", path="work/failover/report.pdf", content="# Failover\n\nThe gateway is serving.")
    await call("write_document", path="work/failover/appendix.pdf", content="Appendix")
    merged = await call("edit_pdf", path="work/failover/report.pdf", insert_pdf="work/failover/appendix.pdf")
    assert merged["pages_after"] == 2
    assert (await call("read_document", path="work/failover/report.pdf", find="serving"))["matches"][0]["page"] == 1
    await call("write_document", path="work/failover/memo.docx", content="Status: pending")
    await call("edit_document", path="work/failover/memo.docx", old_text="pending", new_text="done")
    assert "Status: done" in (await call("read_document", path="work/failover/memo.docx"))["content"]
    await call("write_spreadsheet", path="work/failover/sheet.xlsx", rows=[["device", device]])
    assert (await call("read_document", path="work/failover/sheet.xlsx"))["rows"] == [["device", device]]
    # the roadmap's native delete, with undo
    deleted = await call("delete_file", path="work/failover/memo.docx")
    assert deleted["trash_id"] in {i["trash_id"] for i in (await call("list_deleted"))["items"]}
    await call("restore_deleted", trash_id=deleted["trash_id"])
    assert "Status: done" in (await call("read_document", path="work/failover/memo.docx"))["content"]
    # get_system_info: the device's policy
    assert (await call("get_system_info"))["policy"]["command_mode"] == "allowlist"
    # list_devices
    devices = (await client.call_tool("list_devices", {})).structured_content["devices"]
    seen.add("list_devices")
    assert {d["device"]: d["online"] for d in devices}[device] is True


# ------------------------------------------------------------------ OAuth


def oauth_login(public: str, store: OAuthStore, *, scopes: list[str], devices: list[str]) -> str:
    """What Claude or ChatGPT does when it connects: register, authorize, owner consent, token."""
    with httpx.Client(base_url=public, timeout=30) as http:
        client_id = http.post(
            "/register",
            json={"redirect_uris": [REDIRECT], "client_name": "Claude", "token_endpoint_auth_method": "none"},
        ).json()["client_id"]
        verifier, challenge = pkce()
        consent = http.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "failover",
                "resource": public + "/mcp",
            },
        ).headers["location"]
        page = http.get(consent)
        approved = http.post(
            "/consent",
            data={
                **form_fields(page.text),
                "scope": scopes,
                "device": devices,
                "passphrase": PASSPHRASE,
                "totp": next_code(store),
                "action": "approve",
            },
        )
        assert approved.status_code == 302, approved.text
        code = parse_qs(urlsplit(approved.headers["location"]).query)["code"][0]
        tokens = http.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": public + "/mcp",
            },
        )
        assert tokens.status_code == 200, tokens.text
        return tokens.json()["access_token"]


# -------------------------------------------------------------- acceptance


def test_failover(tmp_path, jail):
    friday = make_workspace(tmp_path / "friday", "friday")
    thanatos = make_workspace(tmp_path / "thanatos", THANATOS)
    local_port, agent_port, remote_port = (free_port() for _ in range(3))
    public = f"http://127.0.0.1:{remote_port}"

    gateway_dir = tmp_path / "gateway"
    gateway_dir.mkdir()
    gateway_config = gateway_dir / "computer.yaml"
    gateway_config.write_text(
        yaml.safe_dump(
            {
                "serve": {"host": "127.0.0.1", "port": local_port, "audit_log": "audit/gateway.jsonl"},
                **device_policy(friday),
                "agents": {
                    "enabled": True,
                    "host": "127.0.0.1",
                    "port": agent_port,
                    "tls_cert": "state/tls/gateway.crt",
                    "tls_key": "state/tls/gateway.key",
                    "registry": "state/devices.json",
                    "heartbeat_seconds": 2,
                    "call_timeout_seconds": 60,
                },
                "remote": {
                    "enabled": True,
                    "port": remote_port,
                    "public_url": public,
                    "state": "state/oauth.json",
                    "allow_scopes": [SCOPE_READ],
                    "allow_devices": ["*"],
                    "allowed_redirect_hosts": ["claude.ai"],
                },
            }
        ),
        encoding="utf-8",
    )
    env = jail.env
    gateway_env = {**env, "CONTEXTBRIDGE_COMPUTER_TOKEN": COMPUTER_TOKEN}
    admin = ("contextbridge.remote.admin", "--config", str(gateway_config))

    agent_proc = None
    try:
        # One-time setup, all with the shipped CLIs and nothing off this machine.
        tls = cli(*admin, "tls-init", "--hostname", "localhost", "--ip", "127.0.0.1", env=env)
        assert tls.returncode == 0, tls.stderr
        fingerprint = re.search(r"fingerprint: (sha256:[0-9A-F:]+)", tls.stdout).group(1)
        pair = cli(*admin, "pair", THANATOS, env=env)
        assert pair.returncode == 0, pair.stderr
        enrollment = re.search(rf"Enrollment code for {THANATOS}: (\S+)", pair.stdout).group(1)
        owner = subprocess.run(
            [sys.executable, "-m", *admin, "owner-init", "--passphrase-stdin", "--no-confirm"],
            input=PASSPHRASE + "\n",
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert owner.returncode == 0, owner.stderr
        store = OAuthStore(gateway_dir / "state" / "oauth.json")

        agent_dir = tmp_path / "thanatos-agent"
        agent_dir.mkdir()
        agent_config = agent_dir / "agent.yaml"
        agent_config.write_text(
            yaml.safe_dump(
                {
                    "name": THANATOS,
                    "gateway": {"url": f"wss://127.0.0.1:{agent_port}", "fingerprint": fingerprint},
                    "identity": "state/identity.json",
                    "audit_log": "audit/agent.jsonl",
                    **device_policy(thanatos),
                }
            ),
            encoding="utf-8",
        )

        with serve("contextbridge.computer", gateway_config, local_port, gateway_env) as local_url:
            gateway_log = gateway_config.with_name("computer.contextbridge.computer.stderr.log")
            wait_port(remote_port, gateway_log)
            enrolled = cli(
                "contextbridge.remote.agent", "enroll", "--config", str(agent_config), "--code", enrollment, env=env
            )
            assert enrolled.returncode == 0, enrolled.stderr
            agent_proc = spawn_logged(
                [sys.executable, "-m", "contextbridge.remote.agent", "run", "--config", str(agent_config)],
                env=env,
                log=tmp_path / "agent.stderr.log",
            )
            run_async(with_client, local_url, COMPUTER_TOKEN, lambda c: wait_online(c, THANATOS))

            code, report = drill_cli(env, local_url, "--write")
            assert failed_checks(report) == [] and code == 0 and report["ready"] is True
            assert [d["device"] for d in report["devices"]] == ["local", THANATOS]
            for device in report["devices"]:
                statuses = {c["name"]: c["status"] for c in device["checks"]}
                assert set(statuses.values()) == {"pass"}, (device["device"], statuses)
                assert {"run_command", "session", "write_round_trip", "documents", "delete"} <= set(statuses)
            for root in (friday, thanatos):
                assert "status: verified" in (root / "work" / ".contextbridge-failover" / "probe.txt").read_text()

            # Every computer tool the deployment enables, on both machines.
            used: dict[str, set[str]] = {}

            async def every_tool(client):
                for device in ("local", THANATOS):
                    await exercise_tools(client, device, used)

            run_async(with_client, local_url, COMPUTER_TOKEN, every_tool)
            expected = SERVER_TOOLS - set(NOT_EXERCISED)
            for device in ("local", THANATOS):
                assert expected <= used[device], (device, expected - used[device])
            assert (thanatos / "work" / "failover" / "log.txt").read_text() == "done\ndone\n"

            # A Claude/ChatGPT-style client, approved for reading on both machines.
            access = oauth_login(public, store, scopes=[SCOPE_READ], devices=["local", THANATOS])

            async def remote_reads(client):
                texts = {}
                for device in ("local", THANATOS):
                    result = await client.call_tool("read_file", {"path": "README.txt", "device": device})
                    texts[device] = result.structured_content["content"]
                with pytest.raises(ToolError, match="computer:execute"):
                    await client.call_tool("run_command", {"command": "hostname", "device": THANATOS})
                return texts

            texts = run_async(with_client, public + "/mcp", access, remote_reads)
            assert texts == {"local": "friday workspace\n", THANATOS: "thanatos workspace\n"}

        # The gateway goes down and comes back: the agent reconnects by itself,
        # and the client's OAuth token still works.
        with serve("contextbridge.computer", gateway_config, local_port, gateway_env) as local_url:
            wait_port(remote_port, gateway_log)

            async def after_restart(client):
                await wait_online(client, THANATOS)
                result = await client.call_tool("read_file", {"path": "work/failover/log.txt", "device": THANATOS})
                return result.structured_content["content"]

            assert run_async(with_client, local_url, COMPUTER_TOKEN, after_restart) == "done\ndone\n"

            async def remote_after_restart(client):
                result = await client.call_tool("read_file", {"path": "docs/notes.md", "device": THANATOS})
                return result.structured_content["content"]

            assert run_async(with_client, public + "/mcp", access, remote_after_restart) == "alpha\nbeta\ngamma\n"
            code, report = drill_cli(env, local_url)
            assert failed_checks(report) == [] and code == 0
    finally:
        if agent_proc is not None and agent_proc.poll() is None:
            agent_proc.kill()
            agent_proc.wait()

    # Nothing reached for Node, npx, or the network.
    assert jail.hits() == "", jail.hits()

    gateway_events = [json.loads(line) for line in (gateway_dir / "audit" / "gateway.jsonl").read_text().splitlines()]
    agent_events = [json.loads(line) for line in (agent_dir / "audit" / "agent.jsonl").read_text().splitlines()]
    requested = [e for e in gateway_events if e["event"] == "requested"]
    assert {e.get("listener") for e in requested} == {"local", "remote"}
    assert {e.get("device") for e in requested} >= {"local", THANATOS}
    assert sum(1 for e in gateway_events if e["event"] == "device_connected") >= 2  # before and after the restart
    thanatos_ids = {e["request_id"] for e in requested if e.get("device") == THANATOS}
    assert thanatos_ids & {e.get("request_id") for e in agent_events}  # the same calls, audited on both machines
