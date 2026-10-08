"""ContextBridge computer route — an MCP server for policy-controlled computer access.

The tool surface is derived from the policy: write tools exist only when writable
roots are configured, command tools only when commands are enabled, and so on.
A default-deny middleware hides and rejects anything else and audits every call.
"""

from __future__ import annotations

import argparse
import atexit
import hashlib
import ipaddress
import os
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import anyio
import yaml
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import StaticTokenVerifier
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.tool import Tool
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse

from uga.audit import UgaAuditLog

from . import commands, files
from .commands import CommandError, SessionManager
from .files import FileOperationError
from .policy import ComputerPolicy, PolicyError, PolicyViolation, load_policy
from .system import system_info

TOKEN_ENV = "CONTEXTBRIDGE_COMPUTER_TOKEN"

READ_TOOLS = frozenset(
    {"list_directory", "read_file", "get_file_info", "search_files", "search_code", "get_system_info"}
)
WRITE_TOOLS = frozenset({"write_file", "edit_block", "create_directory", "move_file"})
COMMAND_TOOLS = frozenset(
    {"run_command", "start_process", "read_process_output", "interact_with_process", "force_terminate", "list_sessions"}
)

_AUDITED_ARGS = (
    "path",
    "source",
    "destination",
    "command",
    "cwd",
    "pattern",
    "file_pattern",
    "mode",
    "session_id",
    "pid",
    "force",
    "timeout_seconds",
)
_DIGESTED_ARGS = ("content", "old_string", "new_string", "input")
_MAX_AUDIT_VALUE = 1000

_READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)
_ADDITIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)
_EXECUTE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True)


def computer_tool_names(policy: ComputerPolicy) -> frozenset[str]:
    """The exact tool surface ``policy`` permits."""
    names = set(READ_TOOLS)
    if policy.can_write:
        names |= WRITE_TOOLS
    if policy.commands_enabled:
        names |= COMMAND_TOOLS
    if policy.list_processes:
        names.add("list_processes")
    if policy.allow_kill:
        names.add("kill_process")
    return frozenset(names)


def _call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run an engine function, turning expected failures into client-facing ToolErrors."""
    try:
        return fn(*args, **kwargs)
    except PolicyViolation as exc:
        raise ToolError(f"Denied by policy: {exc}") from exc
    except (FileNotFoundError, FileOperationError, CommandError, UnicodeDecodeError) as exc:
        raise ToolError(str(exc)) from exc
    except OSError as exc:
        raise ToolError(f"{type(exc).__name__}: {exc.strerror or exc}") from exc


def _audit_fields(arguments: dict[str, Any] | None) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key in _AUDITED_ARGS:
        value = (arguments or {}).get(key)
        if value is None:
            continue
        if isinstance(value, str) and len(value) > _MAX_AUDIT_VALUE:
            value = value[: _MAX_AUDIT_VALUE - 3] + "..."
        fields[key] = value
    for key in _DIGESTED_ARGS:
        value = (arguments or {}).get(key)
        if isinstance(value, str):
            data = value.encode("utf-8")
            fields[f"{key}_bytes"] = len(data)
            fields[f"{key}_sha256"] = hashlib.sha256(data).hexdigest()[:16]
    return fields


def _client_label() -> str | None:
    try:
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
    except Exception:  # no HTTP request context (stdio, in-memory)
        return None
    return getattr(token, "client_id", None) if token else None


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1000))


class ComputerPolicyMiddleware(Middleware):
    """Hide tools outside the policy surface, reject calls to them, and audit every call."""

    def __init__(self, allowed: frozenset[str], audit: UgaAuditLog) -> None:
        self._allowed = allowed
        self._audit = audit

    async def on_list_tools(self, context: MiddlewareContext[Any], call_next: Any) -> Sequence[Tool]:
        tools = await call_next(context)
        return [t for t in tools if t.name in self._allowed]

    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        started = time.monotonic()
        message_id = getattr(context.message, "id", None)
        request_id = f"mcp-{message_id}" if message_id is not None else uuid.uuid4().hex[:12]
        name = str(getattr(context.message, "name", None) or "<unknown>")
        fields = _audit_fields(getattr(context.message, "arguments", None))
        client = _client_label()
        if name not in self._allowed:
            self._audit.record(
                tool=name,
                success=False,
                detail="policy_denied",
                client_label=client,
                request_id=request_id,
                elapsed_ms=_elapsed_ms(started),
                extra=fields,
            )
            raise ToolError(f"Tool '{name}' is not permitted on this computer.")
        try:
            result = await call_next(context)
        except Exception as exc:
            cause = exc.__cause__ if isinstance(exc, ToolError) and exc.__cause__ else exc
            detail = "policy_denied" if isinstance(cause, PolicyViolation) else type(cause).__name__
            self._audit.record(
                tool=name,
                success=False,
                detail=detail,
                client_label=client,
                request_id=request_id,
                elapsed_ms=_elapsed_ms(started),
                extra={**fields, "error": str(exc)[:_MAX_AUDIT_VALUE]},
            )
            raise
        structured = getattr(result, "structured_content", None) or {}
        for key in ("exit_code", "timed_out"):
            if key in structured:
                fields[key] = structured[key]
        self._audit.record(
            tool=name,
            success=True,
            client_label=client,
            request_id=request_id,
            elapsed_ms=_elapsed_ms(started),
            extra=fields,
        )
        return result


def _instructions(policy: ComputerPolicy) -> str:
    roots = ", ".join(str(p) for p in policy.roots)
    writable = ", ".join(str(p) for p in policy.writable_roots) or "none (read-only)"
    if policy.command_mode == "allowlist":
        cmds = "allowlist only: " + ", ".join(sorted(policy.command_allow)) + " (no shell operators)"
    else:
        cmds = policy.command_mode
    return (
        "Policy-controlled access to one computer. "
        f"Readable roots: {roots}. Writable roots: {writable}. Commands: {cmds}. "
        "Relative paths resolve against the first readable root. "
        "Requests outside the policy are refused; call get_system_info to see the full policy."
    )


def create_computer_server(
    policy: ComputerPolicy,
    *,
    audit: UgaAuditLog | None = None,
    name: str = "ContextBridge Computer",
) -> FastMCP:
    audit = audit or UgaAuditLog(None, route="computer")
    allowed = computer_tool_names(policy)
    server = FastMCP(name=name, instructions=_instructions(policy))

    # ------------------------------------------------------------ read tools

    @server.tool(annotations=_READ_ONLY)
    def list_directory(path: str, depth: int = 1) -> dict[str, Any]:
        """List a directory's entries (type, size, modified time). depth 1-5 recurses into subdirectories."""
        return _call(files.list_directory, policy, path, depth=depth)

    @server.tool(annotations=_READ_ONLY)
    def read_file(path: str, offset: int = 0, length: int | None = None) -> dict[str, Any]:
        """Read a text file. offset is the 0-based first line; a negative offset reads the last N lines.
        length limits the number of lines returned. Large files are truncated at the read limit."""
        return _call(files.read_file, policy, path, offset=offset, length=length)

    @server.tool(annotations=_READ_ONLY)
    def get_file_info(path: str) -> dict[str, Any]:
        """Show size, timestamps, permissions, line count, and whether the policy allows writing."""
        return _call(files.get_file_info, policy, path)

    @server.tool(annotations=_READ_ONLY)
    def search_files(path: str, pattern: str, max_results: int | None = None) -> dict[str, Any]:
        """Find files and directories under path whose name matches a glob (*.py) or contains a substring."""
        return _call(files.search_files, policy, path, pattern, max_results=max_results)

    @server.tool(annotations=_READ_ONLY)
    def search_code(
        path: str,
        pattern: str,
        file_pattern: str | None = None,
        regex: bool = False,
        case_sensitive: bool = False,
        context_lines: int = 0,
        max_results: int | None = None,
    ) -> dict[str, Any]:
        """Search text file contents under path. Literal match unless regex is true.
        file_pattern filters file names by glob (e.g. *.py). context_lines adds up to 5 surrounding lines."""
        return _call(
            files.search_code,
            policy,
            path,
            pattern,
            file_pattern=file_pattern,
            regex=regex,
            case_sensitive=case_sensitive,
            context_lines=context_lines,
            max_results=max_results,
        )

    @server.tool(annotations=_READ_ONLY)
    def get_system_info() -> dict[str, Any]:
        """Describe this computer (OS, CPU, memory, disks) and the access policy in force."""
        return _call(system_info, policy)

    # ----------------------------------------------------------- write tools

    if policy.can_write:

        @server.tool(annotations=_WRITE)
        def write_file(path: str, content: str, mode: str = "rewrite") -> dict[str, Any]:
            """Write a text file. mode 'rewrite' replaces it atomically; 'append' adds to the end.
            The parent directory must already exist."""
            return _call(files.write_file, policy, path, content, mode=mode)

        @server.tool(annotations=_WRITE)
        def edit_block(path: str, old_string: str, new_string: str, expected_replacements: int = 1) -> dict[str, Any]:
            """Replace exact text in a file. Fails unless old_string occurs exactly expected_replacements times,
            so include enough surrounding context to make the match unique."""
            return _call(
                files.edit_block, policy, path, old_string, new_string, expected_replacements=expected_replacements
            )

        @server.tool(annotations=_ADDITIVE)
        def create_directory(path: str) -> dict[str, Any]:
            """Create a directory, including missing parents."""
            return _call(files.create_directory, policy, path)

        @server.tool(annotations=_WRITE)
        def move_file(source: str, destination: str) -> dict[str, Any]:
            """Move or rename a file or directory. The destination must not already exist."""
            return _call(files.move_file, policy, source, destination)

    # --------------------------------------------------------- command tools

    if policy.commands_enabled:
        sessions = SessionManager(policy)
        atexit.register(sessions.shutdown)

        @server.tool(annotations=_EXECUTE)
        def run_command(command: str, cwd: str | None = None, timeout_seconds: float | None = None) -> dict[str, Any]:
            """Run a command to completion and return exit code, stdout, and stderr.
            Killed with its child processes if it exceeds timeout_seconds. Use start_process for
            long-running or interactive programs."""
            return _call(commands.run_command, policy, command, cwd=cwd, timeout_seconds=timeout_seconds)

        @server.tool(annotations=_EXECUTE)
        def start_process(
            command: str, cwd: str | None = None, timeout_seconds: float | None = None, wait_seconds: float = 1.0
        ) -> dict[str, Any]:
            """Start a long-running or interactive command in the background and return its session_id
            with the first output. stdout and stderr are combined."""
            return _call(
                sessions.start, command, cwd=cwd, timeout_seconds=timeout_seconds, wait_seconds=wait_seconds
            )

        @server.tool(annotations=_READ_ONLY)
        def read_process_output(session_id: str, wait_seconds: float = 0.0) -> dict[str, Any]:
            """Return output a session produced since the last read, waiting up to wait_seconds for more."""
            return _call(sessions.read, session_id, wait_seconds=wait_seconds)

        @server.tool(annotations=_EXECUTE)
        def interact_with_process(
            session_id: str, input: str, append_newline: bool = True, wait_seconds: float = 1.0
        ) -> dict[str, Any]:
            """Send input to a running session's stdin and return the output that follows."""
            return _call(sessions.send, session_id, input, newline=append_newline, wait_seconds=wait_seconds)

        @server.tool(annotations=_WRITE)
        def force_terminate(session_id: str) -> dict[str, Any]:
            """Kill a session and its child processes, returning any remaining output."""
            return _call(sessions.terminate, session_id)

        @server.tool(annotations=_READ_ONLY)
        def list_sessions() -> dict[str, Any]:
            """List sessions started through ContextBridge with their status."""
            return {"sessions": _call(sessions.list)}

    # ------------------------------------------------------- process tools

    if policy.list_processes:

        @server.tool(annotations=_READ_ONLY)
        def list_processes(name_filter: str | None = None, limit: int = 200) -> dict[str, Any]:
            """List running processes, optionally filtered by a substring of the name or command line."""
            return _call(commands.list_processes, name_filter=name_filter, limit=max(1, min(limit, 1000)))

    if policy.allow_kill:

        @server.tool(annotations=_WRITE)
        def kill_process(pid: int, force: bool = False) -> dict[str, Any]:
            """Terminate a process by PID (force sends SIGKILL / TerminateProcess)."""
            return _call(commands.kill_process, pid, force=force)

    server.add_middleware(ComputerPolicyMiddleware(allowed, audit))

    @server.custom_route("/", methods=["GET"])
    async def root_status(_request: Request) -> JSONResponse:
        return JSONResponse({"service": name, "mcp_path": "/mcp", "tools": sorted(allowed)})

    return server


def advertised_tool_names(server: FastMCP) -> set[str]:
    async def _names() -> set[str]:
        tools = await server.list_tools(run_middleware=False)
        return {t.name for t in tools}

    return anyio.run(_names)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="ContextBridge computer route")
    ap.add_argument("--config", required=True)
    ap.add_argument("--transport", choices=("stdio", "http"), help="override serve.transport")
    args = ap.parse_args(argv)

    config_path = Path(args.config).expanduser().resolve()
    with config_path.open(encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    serve = cfg.get("serve") or {}
    transport = args.transport or serve.get("transport", "stdio")
    if transport not in ("stdio", "http"):
        raise SystemExit(f"{config_path}: serve.transport must be 'stdio' or 'http'.")

    audit_path = serve.get("audit_log")
    if audit_path:
        audit_path = Path(audit_path).expanduser()
        if not audit_path.is_absolute():
            audit_path = config_path.parent / audit_path
    try:
        policy = load_policy(cfg, protected=(config_path, audit_path or ""))
    except PolicyError as exc:
        raise SystemExit(f"{config_path}: {exc}") from None

    server = create_computer_server(
        policy,
        audit=UgaAuditLog(audit_path, route="computer"),
        name=cfg.get("name", "ContextBridge Computer"),
    )
    expected = computer_tool_names(policy)
    advertised = advertised_tool_names(server)
    if advertised != expected:
        raise SystemExit(f"Computer tool surface mismatch: expected {set(expected)!r}, got {advertised!r}")

    summary = f"{len(expected)} tools, commands={policy.command_mode}, writable={bool(policy.writable_roots)}"
    if transport == "stdio":
        print(f"[computer] serving on stdio ({summary})", file=sys.stderr, flush=True)
        server.run(transport="stdio", show_banner=False)
        return

    token = os.environ.get(TOKEN_ENV)
    if not token:
        raise SystemExit(f"{TOKEN_ENV} must be set for the HTTP computer route (fail closed).")
    if token == os.environ.get("MCP_AUTH_TOKEN"):
        raise SystemExit(f"{TOKEN_ENV} must differ from MCP_AUTH_TOKEN; knowledge and computer access are separate.")
    host = serve.get("host", "127.0.0.1")
    port = serve.get("port")
    if not port:
        raise SystemExit(f"{config_path}: serve.port is required for the HTTP transport.")
    if not _is_loopback(host) and not serve.get("allow_non_loopback", False):
        raise SystemExit(
            f"{config_path}: refusing to bind {host}; set serve.allow_non_loopback only behind an "
            "authenticated TLS front end."
        )

    server.auth = StaticTokenVerifier({token: {"client_id": "contextbridge-computer"}})
    print(f"[computer] serving on {host}:{port} ({summary})", file=sys.stderr, flush=True)
    server.run(transport="http", host=host, port=port, show_banner=False)
