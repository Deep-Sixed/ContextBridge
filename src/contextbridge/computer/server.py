"""ContextBridge computer route — an MCP server for policy-controlled computer access.

Tool calls go to a *device*: ``local`` (this machine, under this config's policy)
or a remote agent registered with the gateway. Gates applied to every call, at
the moment it executes:

1. **Token scope** — the caller's bearer token must carry the tool's scope.
2. **Device** — the device must exist, be online, be granted that scope in the
   device registry, and advertise the tool.
3. **Policy** — the device's own engine re-validates paths, commands, and limits.
   For remote devices that is the agent, under the agent's local policy.

Every call is audited as ``requested`` → ``denied``/``failed`` or
``requested`` → ``started`` → ``completed`` (see :mod:`.audit`).

The MCP endpoint serves HTTP on a loopback address only. The optional agent
listener may bind a LAN or overlay address, but only with TLS. The optional
remote listener (:mod:`contextbridge.oauth`) is a second MCP endpoint on its
own loopback port, for a TLS tunnel to expose; it accepts only OAuth tokens,
each limited to the scopes and devices the owner approved.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import os
import platform
import socket
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
import yaml
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import StaticTokenVerifier
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.tool import Tool
from mcp.types import ToolAnnotations
from starlette.middleware import Middleware as ASGIMiddleware

from .. import __version__
from ..net import HostOriginGuard, is_loopback, is_private_bind
from .audit import (
    MAX_AUDIT_VALUE,
    AuditError,
    CallAudit,
    ComputerAuditLog,
    bind_call,
    current_call,
    mark_started,
    outcome_fields,
    summarize_args,
    unbind_call,
)
from .commands import CommandError
from .dispatch import (
    COMMAND_TOOLS,
    ENGINE_TOOLS,
    PROCESS_KILL_TOOL,
    PROCESS_LIST_TOOL,
    READ_TOOLS,
    WRITE_TOOLS,
    Engine,
    InvalidArguments,
    available_tools,
    call_succeeded,
)
from .files import FileOperationError
from .policy import ComputerPolicy, PolicyError, PolicyViolation, load_policy

TOKEN_ENV = "CONTEXTBRIDGE_COMPUTER_TOKEN"
KNOWLEDGE_TOKEN_ENV = "MCP_AUTH_TOKEN"
CLIENT_ID = "contextbridge-computer"
MIN_TOKEN_LENGTH = 32
LOCAL_DEVICE = "local"
LIST_DEVICES_TOOL = "list_devices"
DEFAULT_REDIRECT_HOSTS = ("claude.ai", "claude.com", "chatgpt.com")

SCOPE_READ = "computer:read"
SCOPE_WRITE = "computer:write"
SCOPE_EXECUTE = "computer:execute"
SCOPE_PROCESS = "computer:process"
ALL_SCOPES = (SCOPE_READ, SCOPE_WRITE, SCOPE_EXECUTE, SCOPE_PROCESS)

TOOL_SCOPES: dict[str, str] = {
    **{name: SCOPE_READ for name in READ_TOOLS},
    PROCESS_LIST_TOOL: SCOPE_READ,
    LIST_DEVICES_TOOL: SCOPE_READ,
    **{name: SCOPE_WRITE for name in WRITE_TOOLS},
    **{name: SCOPE_EXECUTE for name in COMMAND_TOOLS},
    PROCESS_KILL_TOOL: SCOPE_PROCESS,
}
SERVER_TOOLS = ENGINE_TOOLS | {LIST_DEVICES_TOOL}

_READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)
_ADDITIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)
_EXECUTE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True)
_DEVICE_DOC = " device: 'local' (default) or a name from list_devices."


def computer_tool_names(policy: ComputerPolicy) -> frozenset[str]:
    """The tools ``policy`` enables on a device."""
    return available_tools(policy)


class AuthorizationError(PermissionError):
    """Raised when the caller may not use a tool."""


Authorizer = Callable[[str], str]
"""Given a tool name, return the caller's client id or raise :class:`AuthorizationError`."""

DeviceGrant = Callable[[], frozenset[str] | None]
"""The devices the current caller may reach, or None for every device."""


def all_devices() -> frozenset[str] | None:
    """The static-token grant: the owner's token reaches every device."""
    return None


def token_authorizer(tool: str) -> str:
    """Authorize ``tool`` against the bearer token of the current request."""
    try:
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
    except Exception:  # no request context at all
        token = None
    if token is None:
        raise AuthorizationError("Authentication required.")
    scope = TOOL_SCOPES.get(tool)
    if scope is None or scope not in (token.scopes or []):
        raise AuthorizationError(f"Token is not authorized for '{tool}' (needs {scope}).")
    return token.client_id


# --------------------------------------------------------------------- devices


class DeviceRouter:
    """Sends each tool call to the local engine or to a remote agent."""

    def __init__(self, local: Engine | None, hub: Any | None) -> None:
        self.local = local
        self.hub = hub

    def available_tools(self, devices: frozenset[str] | None = None) -> frozenset[str]:
        """Tools offered by online devices (only those in ``devices``, unless None)."""
        tools: set[str] = set()
        if self.local is not None and (devices is None or LOCAL_DEVICE in devices):
            tools |= self.local.tools
        if self.hub is not None:
            tools |= self.hub.online_tools(devices)
        return frozenset(tools)

    def check(self, device: str, tool: str) -> None:
        """Raise AuthorizationError (denied) or DeviceUnavailable (failed) unless the call may proceed."""
        if device == LOCAL_DEVICE:
            if self.local is None:
                raise AuthorizationError("This gateway has no local device; choose one from list_devices.")
            if tool not in self.local.tools:
                raise AuthorizationError(f"Tool '{tool}' is not permitted on this computer.")
            return
        from ..remote.hub import DeviceUnavailable
        from ..remote.registry import RegistryError

        if self.hub is None:
            raise AuthorizationError(f"Unknown device '{device}'.")
        with contextlib.suppress(RegistryError, OSError):
            self.hub.registry.refresh()  # a revocation applies to the very next call
        record = self.hub.registry.by_name(device)
        if record is None:
            raise AuthorizationError(f"Unknown device '{device}'.")
        if TOOL_SCOPES[tool] not in record.scopes:
            raise AuthorizationError(f"Device '{device}' is not authorized for '{tool}' (needs {TOOL_SCOPES[tool]}).")
        conn = self.hub.connection(device)
        if conn is None:
            raise DeviceUnavailable(f"Device '{device}' is offline.")
        if tool not in conn.tools:
            raise AuthorizationError(f"Tool '{tool}' is not enabled on device '{device}'.")

    async def call(self, device: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if device == LOCAL_DEVICE:
            return await anyio.to_thread.run_sync(self.local.execute, tool, args)
        return await self.hub.call(device, tool, args, current_call())

    def describe(self, devices: frozenset[str] | None = None) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if self.local is not None:
            rows.append(
                {
                    "device": LOCAL_DEVICE,
                    "online": True,
                    "tools": sorted(self.local.tools),
                    "policy": self.local.policy.summary(),
                    "info": {"hostname": socket.gethostname(), "platform": f"{platform.system()} {platform.release()}"},
                }
            )
        if self.hub is not None:
            rows.extend(self.hub.describe())
        return [row for row in rows if devices is None or row["device"] in devices]


def _device_errors() -> tuple[type[Exception], ...]:
    from ..remote.hub import DeviceUnavailable, RemoteFailed

    return (DeviceUnavailable, RemoteFailed)


async def _invoke(router: DeviceRouter, device: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Run a tool call, turning expected failures into client-facing ToolErrors."""
    try:
        return await router.call(device, tool, args)
    except PolicyViolation as exc:
        raise ToolError(f"Denied by policy: {exc}") from exc
    except AuditError as exc:
        raise ToolError(f"Audit log unavailable; operation refused: {exc}") from exc
    except (FileNotFoundError, FileOperationError, CommandError, UnicodeDecodeError, InvalidArguments) as exc:
        raise ToolError(str(exc)) from exc
    except _device_errors() as exc:
        raise ToolError(str(exc)) from exc
    except OSError as exc:
        raise ToolError(f"{type(exc).__name__}: {exc.strerror or exc}") from exc


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1000))


class ComputerPolicyMiddleware(Middleware):
    """Authorize and audit every call at execution time; hide tools the caller cannot use."""

    def __init__(
        self,
        router: DeviceRouter,
        audit: ComputerAuditLog,
        authorize: Authorizer,
        devices: DeviceGrant = all_devices,
        listener: str = "local",
    ) -> None:
        self._router = router
        self._audit = audit
        self._authorize = authorize
        self._devices = devices
        self._listener = listener

    def _check(self, name: str, device: str | None) -> str:
        if name not in SERVER_TOOLS:
            raise AuthorizationError(f"Tool '{name}' is not permitted on this computer.")
        client = self._authorize(name)
        if name != LIST_DEVICES_TOOL:
            target = device or LOCAL_DEVICE
            granted = self._devices()
            if granted is not None and target not in granted:
                raise AuthorizationError(f"This client is not authorized for device '{target}'.")
            self._router.check(target, name)
        return client

    async def on_list_tools(self, context: MiddlewareContext[Any], call_next: Any) -> Sequence[Tool]:
        tools = await call_next(context)
        offered = self._router.available_tools(self._devices()) | {LIST_DEVICES_TOOL}
        visible = []
        for tool in tools:
            if tool.name not in offered:
                continue
            try:
                self._authorize(tool.name)
            except AuthorizationError:
                continue
            visible.append(tool)
        return visible

    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        started = time.monotonic()
        request_id = uuid.uuid4().hex[:16]
        name = str(getattr(context.message, "name", None) or "<unknown>")
        arguments = getattr(context.message, "arguments", None) or {}
        device = arguments.get("device") if isinstance(arguments.get("device"), str) else None
        if name != LIST_DEVICES_TOOL:
            device = device or LOCAL_DEVICE
        fields = summarize_args(arguments)
        fields.pop("device", None)
        try:
            self._audit.record(
                "requested", request_id=request_id, tool=name, device=device, listener=self._listener, **fields
            )
        except AuditError as exc:
            raise ToolError(f"Audit log unavailable; refusing to run '{name}'.") from exc

        try:
            client = self._check(name, device)
        except AuthorizationError as exc:
            self._audit.record("denied", request_id=request_id, tool=name, device=device, reason=str(exc))
            raise ToolError(str(exc)) from exc
        except _device_errors() as exc:
            self._audit.record("failed", request_id=request_id, tool=name, device=device, reason=str(exc))
            raise ToolError(str(exc)) from exc

        call = CallAudit(self._audit, request_id, name, client, device=device)
        binding = bind_call(call)
        try:
            result = await call_next(context)
        except Exception as exc:
            cause = exc.__cause__ if isinstance(exc, ToolError) and exc.__cause__ else exc
            if call.started:
                event = "completed"
            elif isinstance(cause, PolicyViolation):
                event = "denied"
            else:
                event = "failed"
            call.emit(
                event,
                success=False if event == "completed" else None,
                detail=type(cause).__name__,
                reason=str(exc)[:MAX_AUDIT_VALUE],
                elapsed_ms=_elapsed_ms(started),
            )
            raise
        finally:
            unbind_call(binding)

        structured = getattr(result, "structured_content", None) or {}
        call.emit(
            "completed",
            success=call_succeeded(name, structured),
            elapsed_ms=_elapsed_ms(started),
            **outcome_fields(structured),
        )
        return result


def _instructions(policy: ComputerPolicy | None, remote: bool) -> str:
    parts = ["Policy-controlled access to computers. Every tool takes a 'device' argument (default 'local')."]
    if policy is not None:
        roots = ", ".join(str(p) for p in policy.roots)
        writable = ", ".join(str(p) for p in policy.writable_roots) or "none (read-only)"
        if policy.command_mode == "allowlist":
            cmds = "allowlist only: " + ", ".join(sorted(policy.command_allow)) + " (no shell operators)"
        else:
            cmds = policy.command_mode
        parts.append(f"On 'local': readable roots {roots}; writable roots {writable}; commands {cmds}.")
    else:
        parts.append("This gateway has no local device.")
    if remote:
        parts.append("Call list_devices to see remote computers, whether they are online, and their policies.")
    parts.append("Requests outside a device's policy are refused.")
    return " ".join(parts)


def build_router(policy: ComputerPolicy | None, *, audit: ComputerAuditLog, hub: Any | None = None) -> DeviceRouter:
    """The devices one or more MCP servers share: ``local`` under ``policy`` (if any) plus the hub's agents."""

    def report_exit(status: dict[str, Any]) -> None:
        audit.record(
            "exited",
            tool="session",
            device=LOCAL_DEVICE,
            success=status["exit_code"] == 0 and not status["timed_out"],
            **{k: status[k] for k in ("session_id", "pid", "command", "exit_code", "timed_out", "runtime_seconds")},
        )

    local = Engine(policy, on_exit=report_exit) if policy is not None else None
    return DeviceRouter(local, hub)


def create_computer_server(
    policy: ComputerPolicy | None,
    *,
    audit: ComputerAuditLog,
    authorize: Authorizer = token_authorizer,
    devices: DeviceGrant = all_devices,
    hub: Any | None = None,
    router: DeviceRouter | None = None,
    listener: str = "local",
    name: str = "ContextBridge Computer",
) -> FastMCP:
    """Build the MCP server. ``policy`` configures the ``local`` device (None for a gateway without one).

    Pass ``router`` (from :func:`build_router`) to serve the same devices, sessions included,
    from several servers; ``policy`` and ``hub`` are then taken from it.
    """
    if router is None:
        router = build_router(policy, audit=audit, hub=hub)
    policy = router.local.policy if router.local is not None else None
    server = FastMCP(name=name, version=__version__, instructions=_instructions(policy, router.hub is not None))
    run = functools.partial(_invoke, router)

    # ------------------------------------------------------------ read tools

    @server.tool(annotations=_READ_ONLY)
    async def list_devices() -> dict[str, Any]:
        """List the computers this gateway can reach, whether each is online, and what it allows."""
        mark_started()
        return {"devices": router.describe(devices())}

    @server.tool(annotations=_READ_ONLY)
    async def list_directory(path: str, depth: int = 1, device: str = LOCAL_DEVICE) -> dict[str, Any]:
        """List a directory's entries (type, size, modified time). depth 1-5 recurses into subdirectories."""
        return await run(device, "list_directory", {"path": path, "depth": depth})

    @server.tool(annotations=_READ_ONLY)
    async def read_file(
        path: str, offset: int = 0, length: int | None = None, device: str = LOCAL_DEVICE
    ) -> dict[str, Any]:
        """Read a text file. offset is the 0-based first line; a negative offset reads the last N lines.
        length limits the number of lines returned. Large files are truncated at the read limit."""
        return await run(device, "read_file", {"path": path, "offset": offset, "length": length})

    @server.tool(annotations=_READ_ONLY)
    async def get_file_info(path: str, device: str = LOCAL_DEVICE) -> dict[str, Any]:
        """Show size, timestamps, permissions, line count, and whether the policy allows writing."""
        return await run(device, "get_file_info", {"path": path})

    @server.tool(annotations=_READ_ONLY)
    async def search_files(
        path: str, pattern: str, max_results: int | None = None, device: str = LOCAL_DEVICE
    ) -> dict[str, Any]:
        """Find files and directories under path whose name matches a glob (*.py) or contains a substring."""
        return await run(device, "search_files", {"path": path, "pattern": pattern, "max_results": max_results})

    @server.tool(annotations=_READ_ONLY)
    async def search_code(
        path: str,
        pattern: str,
        file_pattern: str | None = None,
        regex: bool = False,
        case_sensitive: bool = False,
        context_lines: int = 0,
        max_results: int | None = None,
        device: str = LOCAL_DEVICE,
    ) -> dict[str, Any]:
        """Search text file contents under path. Literal match unless regex is true.
        file_pattern filters file names by glob (e.g. *.py). context_lines adds up to 5 surrounding lines."""
        args = {
            "path": path,
            "pattern": pattern,
            "file_pattern": file_pattern,
            "regex": regex,
            "case_sensitive": case_sensitive,
            "context_lines": context_lines,
            "max_results": max_results,
        }
        return await run(device, "search_code", args)

    @server.tool(annotations=_READ_ONLY)
    async def get_system_info(device: str = LOCAL_DEVICE) -> dict[str, Any]:
        """Describe a computer (OS, CPU, memory, disks) and the access policy in force."""
        return await run(device, "get_system_info", {})

    # ----------------------------------------------------------- write tools

    @server.tool(annotations=_WRITE)
    async def write_file(path: str, content: str, mode: str = "rewrite", device: str = LOCAL_DEVICE) -> dict[str, Any]:
        """Write a text file. mode 'rewrite' replaces it atomically; 'append' adds to the end.
        The parent directory must already exist."""
        return await run(device, "write_file", {"path": path, "content": content, "mode": mode})

    @server.tool(annotations=_WRITE)
    async def edit_block(
        path: str, old_string: str, new_string: str, expected_replacements: int = 1, device: str = LOCAL_DEVICE
    ) -> dict[str, Any]:
        """Replace exact text in a file. Fails unless old_string occurs exactly expected_replacements times,
        so include enough surrounding context to make the match unique."""
        args = {
            "path": path,
            "old_string": old_string,
            "new_string": new_string,
            "expected_replacements": expected_replacements,
        }
        return await run(device, "edit_block", args)

    @server.tool(annotations=_ADDITIVE)
    async def create_directory(path: str, device: str = LOCAL_DEVICE) -> dict[str, Any]:
        """Create a directory, including missing parents."""
        return await run(device, "create_directory", {"path": path})

    @server.tool(annotations=_WRITE)
    async def move_file(source: str, destination: str, device: str = LOCAL_DEVICE) -> dict[str, Any]:
        """Move or rename a file or directory. The destination must not already exist."""
        return await run(device, "move_file", {"source": source, "destination": destination})

    # --------------------------------------------------------- command tools

    @server.tool(annotations=_EXECUTE)
    async def run_command(
        command: str, cwd: str | None = None, timeout_seconds: float | None = None, device: str = LOCAL_DEVICE
    ) -> dict[str, Any]:
        """Run a command to completion and return exit code, stdout, and stderr.
        Killed with its child processes if it exceeds timeout_seconds. Use start_process for
        long-running or interactive programs."""
        return await run(device, "run_command", {"command": command, "cwd": cwd, "timeout_seconds": timeout_seconds})

    @server.tool(annotations=_EXECUTE)
    async def start_process(
        command: str,
        cwd: str | None = None,
        timeout_seconds: float | None = None,
        wait_seconds: float = 1.0,
        device: str = LOCAL_DEVICE,
    ) -> dict[str, Any]:
        """Start a long-running or interactive command in the background and return its session_id
        with the first output. stdout and stderr are combined."""
        args = {"command": command, "cwd": cwd, "timeout_seconds": timeout_seconds, "wait_seconds": wait_seconds}
        return await run(device, "start_process", args)

    @server.tool(annotations=_READ_ONLY)
    async def read_process_output(
        session_id: str, wait_seconds: float = 0.0, device: str = LOCAL_DEVICE
    ) -> dict[str, Any]:
        """Return output a session produced since the last read, waiting up to wait_seconds for more."""
        return await run(device, "read_process_output", {"session_id": session_id, "wait_seconds": wait_seconds})

    @server.tool(annotations=_EXECUTE)
    async def interact_with_process(
        session_id: str,
        input: str,
        append_newline: bool = True,
        wait_seconds: float = 1.0,
        device: str = LOCAL_DEVICE,
    ) -> dict[str, Any]:
        """Send input to a running session's stdin and return the output that follows."""
        args = {
            "session_id": session_id,
            "input": input,
            "append_newline": append_newline,
            "wait_seconds": wait_seconds,
        }
        return await run(device, "interact_with_process", args)

    @server.tool(annotations=_WRITE)
    async def force_terminate(session_id: str, device: str = LOCAL_DEVICE) -> dict[str, Any]:
        """Kill a session and its child processes, returning any remaining output."""
        return await run(device, "force_terminate", {"session_id": session_id})

    @server.tool(annotations=_READ_ONLY)
    async def list_sessions(device: str = LOCAL_DEVICE) -> dict[str, Any]:
        """List sessions started through ContextBridge on a device, with their status."""
        return await run(device, "list_sessions", {})

    # ------------------------------------------------------- process tools

    @server.tool(annotations=_READ_ONLY)
    async def list_processes(
        name_filter: str | None = None, limit: int = 200, device: str = LOCAL_DEVICE
    ) -> dict[str, Any]:
        """List running processes, optionally filtered by a substring of the name or command line."""
        return await run(device, "list_processes", {"name_filter": name_filter, "limit": limit})

    @server.tool(annotations=_WRITE)
    async def kill_process(pid: int, force: bool = False, device: str = LOCAL_DEVICE) -> dict[str, Any]:
        """Terminate a process by PID (force sends SIGKILL / TerminateProcess)."""
        return await run(device, "kill_process", {"pid": pid, "force": force})

    server.add_middleware(ComputerPolicyMiddleware(router, audit, authorize, devices, listener))
    return server


def advertised_tool_names(server: FastMCP) -> set[str]:
    async def _names() -> set[str]:
        tools = await server.list_tools(run_middleware=False)
        return {t.name for t in tools}

    return anyio.run(_names)


# ------------------------------------------------------------------ startup


def load_scopes(cfg: dict[str, Any]) -> tuple[str, ...]:
    auth = cfg.get("auth") or {}
    if not isinstance(auth, dict):
        raise PolicyError("auth must be a mapping")
    scopes = auth.get("scopes", list(ALL_SCOPES))
    if not isinstance(scopes, list) or not scopes:
        raise PolicyError("auth.scopes must be a non-empty list")
    unknown = [s for s in scopes if s not in ALL_SCOPES]
    if unknown:
        raise PolicyError(f"auth.scopes: unknown scope(s) {unknown}; valid: {list(ALL_SCOPES)}")
    return tuple(dict.fromkeys(scopes))


def _require_token() -> str:
    token = os.environ.get(TOKEN_ENV, "")
    if not token:
        raise SystemExit(f"{TOKEN_ENV} must be set (fail closed).")
    if len(token) < MIN_TOKEN_LENGTH:
        raise SystemExit(f"{TOKEN_ENV} must be at least {MIN_TOKEN_LENGTH} characters.")
    if token == os.environ.get(KNOWLEDGE_TOKEN_ENV):
        raise SystemExit(
            f"{TOKEN_ENV} must differ from {KNOWLEDGE_TOKEN_ENV}; knowledge and computer access are separate."
        )
    return token


def _path(base: Path, value: Any) -> Path | None:
    if not value:
        return None
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else base / path


def _port(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value < 65536:
        raise SystemExit(f"{where} must be a TCP port number.")
    return value


class AgentListenerConfig:
    """The ``agents`` section: where remote agents dial in."""

    def __init__(self, cfg: dict[str, Any], base: Path, where: Path) -> None:
        self.host = str(cfg.get("host", "127.0.0.1"))
        self.port = _port(cfg.get("port"), f"{where}: agents.port")
        self.tls_cert = _path(base, cfg.get("tls_cert"))
        self.tls_key = _path(base, cfg.get("tls_key"))
        self.registry = _path(base, cfg.get("registry"))
        try:
            self.heartbeat_seconds = float(cfg.get("heartbeat_seconds", 15))
            self.call_timeout_seconds = float(cfg.get("call_timeout_seconds", 660))
        except (TypeError, ValueError):
            raise SystemExit(f"{where}: agents.heartbeat_seconds and call_timeout_seconds must be numbers.") from None
        if not is_private_bind(self.host):
            raise SystemExit(
                f"{where}: agents.host must be a loopback, LAN, or overlay-network IP address; "
                f"{self.host} could be public."
            )
        if bool(self.tls_cert) != bool(self.tls_key):
            raise SystemExit(f"{where}: agents.tls_cert and agents.tls_key must be set together.")
        if not is_loopback(self.host) and not self.tls_cert:
            raise SystemExit(f"{where}: agents.tls_cert/tls_key are required when agents.host is not loopback.")
        if self.registry is None:
            raise SystemExit(f"{where}: agents.registry is required.")
        if not 1 <= self.heartbeat_seconds <= 300 or self.call_timeout_seconds <= 0:
            raise SystemExit(f"{where}: agents.heartbeat_seconds must be 1-300 and call_timeout_seconds positive.")

    def ssl_context(self):
        if self.tls_cert is None or self.tls_key is None:
            return None
        from ..remote.tls import server_context

        try:
            return server_context(self.tls_cert, self.tls_key)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"cannot load agent TLS certificate/key: {exc}") from None


def _str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        raise SystemExit(f"{where} must be a non-empty list of strings.")
    return list(dict.fromkeys(value))


class RemoteListenerConfig:
    """The ``remote`` section: an OAuth-protected MCP endpoint for ChatGPT, Claude, and other remote clients.

    It listens on loopback only; a TLS tunnel (Tailscale Funnel, Cloudflare Tunnel, a
    reverse proxy) publishes it at ``public_url``.
    """

    def __init__(self, cfg: dict[str, Any], base: Path, where: Path) -> None:
        self.host = str(cfg.get("host", "127.0.0.1"))
        self.port = _port(cfg.get("port"), f"{where}: remote.port")
        self.public_url = str(cfg.get("public_url") or "").rstrip("/")
        self.state = _path(base, cfg.get("state"))
        self.allow_scopes = _str_list(cfg.get("allow_scopes", [SCOPE_READ]), f"{where}: remote.allow_scopes")
        self.allow_devices = _str_list(cfg.get("allow_devices", [LOCAL_DEVICE]), f"{where}: remote.allow_devices")
        self.redirect_hosts = [
            h.lower()
            for h in _str_list(
                cfg.get("allowed_redirect_hosts", list(DEFAULT_REDIRECT_HOSTS)), f"{where}: remote.allowed_redirect_hosts"
            )
        ]
        minutes, days = cfg.get("access_token_minutes", 60), cfg.get("refresh_token_days", 30)
        if not is_loopback(self.host):
            raise SystemExit(
                f"{where}: remote.host must be a loopback address; publish it through a TLS tunnel, not a bind."
            )
        parts = urlsplit(self.public_url)
        if (
            not parts.hostname
            or parts.path
            or parts.query
            or parts.fragment
            or parts.username
            or not (parts.scheme == "https" or (parts.scheme == "http" and is_loopback(parts.hostname)))
        ):
            raise SystemExit(
                f"{where}: remote.public_url must be the https:// origin clients reach (no path), "
                f"e.g. https://friday.example.ts.net; got {self.public_url!r}."
            )
        if self.state is None:
            raise SystemExit(f"{where}: remote.state is required.")
        unknown = [s for s in self.allow_scopes if s not in ALL_SCOPES]
        if unknown:
            raise SystemExit(f"{where}: remote.allow_scopes: unknown scope(s) {unknown}; valid: {list(ALL_SCOPES)}")
        for value, low, high, key in ((minutes, 1, 1440, "access_token_minutes"), (days, 1, 365, "refresh_token_days")):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not low <= value <= high:
                raise SystemExit(f"{where}: remote.{key} must be a number from {low} to {high}.")
        self.access_seconds = round(minutes * 60)
        self.refresh_seconds = round(days * 86400)

    @property
    def public_host(self) -> str:
        return urlsplit(self.public_url).hostname or ""

    def http_options(self) -> dict[str, Any]:
        """Bind address plus a Host/Origin guard that also admits the public name the tunnel forwards."""
        public = urlsplit(self.public_url)
        guard = ASGIMiddleware(
            HostOriginGuard, hosts=[self.host, self.public_host], origins=[f"{public.scheme}://{public.netloc}"]
        )
        return {"host": self.host, "port": self.port, "middleware": [guard]}

    @property
    def secret_paths(self) -> list[Path]:
        """The OAuth state file and its lock and temp files: never visible to any file tool."""
        assert self.state is not None
        return [self.state, *(self.state.with_name(self.state.name + suffix) for suffix in (".lock", ".tmp"))]

    def settings(self):
        from ..oauth.provider import RemoteSettings

        return RemoteSettings(
            public_url=self.public_url,
            allow_scopes=tuple(self.allow_scopes),
            allow_devices=tuple(self.allow_devices),
            allowed_redirect_hosts=tuple(self.redirect_hosts),
            access_seconds=self.access_seconds,
            refresh_seconds=self.refresh_seconds,
        )


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="ContextBridge computer route (MCP over HTTP on loopback only)")
    ap.add_argument("--config", required=True)
    args = ap.parse_args(argv)

    token = _require_token()

    config_path = Path(args.config).expanduser().resolve()
    with config_path.open(encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    base = config_path.parent
    serve = cfg.get("serve") or {}

    host = str(serve.get("host", "127.0.0.1"))
    if not is_loopback(host):
        raise SystemExit(f"{config_path}: serve.host must be a loopback address; {host} is not.")
    port = _port(serve.get("port"), f"{config_path}: serve.port")
    audit_path = _path(base, serve.get("audit_log"))
    if audit_path is None:
        raise SystemExit(f"{config_path}: serve.audit_log is required.")

    agents_cfg = cfg.get("agents") or {}
    listener = AgentListenerConfig(agents_cfg, base, config_path) if agents_cfg.get("enabled") else None
    remote_cfg = cfg.get("remote") or {}
    remote = RemoteListenerConfig(remote_cfg, base, config_path) if remote_cfg.get("enabled") else None
    ports = [port] + ([listener.port] if listener else []) + ([remote.port] if remote else [])
    if len(set(ports)) != len(ports):
        raise SystemExit(f"{config_path}: serve.port, agents.port, and remote.port must all differ.")
    # The local device may never read the gateway's TLS key, device registry, or OAuth state,
    # nor rewrite its config.
    hidden: list[Path] = []
    protected: list[Path] = [config_path, audit_path]
    if listener is not None:
        hidden += [listener.registry, listener.registry.with_name(listener.registry.name + ".lock")]
        if listener.tls_key and listener.tls_cert:
            hidden.append(listener.tls_key)
            protected.append(listener.tls_cert)
    if remote is not None:
        hidden += remote.secret_paths

    try:
        scopes = load_scopes(cfg)
        policy = (
            load_policy(cfg, protected=tuple(protected), hidden=tuple(hidden)) if "filesystem" in cfg else None
        )
    except PolicyError as exc:
        raise SystemExit(f"{config_path}: {exc}") from None
    if policy is None and listener is None:
        raise SystemExit(f"{config_path}: configure a local device (filesystem) and/or enable agents.")
    ssl_context = listener.ssl_context() if listener else None
    try:
        audit = ComputerAuditLog(audit_path)
    except AuditError as exc:
        raise SystemExit(str(exc)) from None

    hub = None
    if listener is not None:
        from ..remote.hub import AgentHub
        from ..remote.registry import DeviceRegistry, RegistryError

        try:
            registry = DeviceRegistry(listener.registry)
            registry.refresh()
        except (RegistryError, OSError) as exc:
            raise SystemExit(str(exc)) from None
        hub = AgentHub(
            registry,
            audit,
            heartbeat_seconds=listener.heartbeat_seconds,
            call_timeout_seconds=listener.call_timeout_seconds,
        )

    name = cfg.get("name", "ContextBridge Computer")
    router = build_router(policy, audit=audit, hub=hub)
    server = create_computer_server(None, audit=audit, router=router, name=name)
    remote_server = None
    if remote is not None:
        from ..oauth.remote import create_remote_server
        from ..oauth.store import OAuthStateError, OAuthStore

        store = OAuthStore(remote.state)
        try:
            ready = store.owner_initialized()
        except OAuthStateError as exc:
            raise SystemExit(str(exc)) from None
        if not ready:
            raise SystemExit(
                f"{config_path}: remote is enabled but no owner credentials exist (fail closed). Run:\n"
                f"  contextbridge-admin --config {config_path} owner-init"
            )
        remote_server = create_remote_server(router, audit=audit, settings=remote.settings(), store=store, name=name)
    for srv in (server, remote_server):
        advertised = advertised_tool_names(srv) if srv is not None else SERVER_TOOLS
        if advertised != SERVER_TOOLS:
            raise SystemExit(f"Computer tool surface mismatch: expected {set(SERVER_TOOLS)!r}, got {advertised!r}")

    try:
        audit.record(
            "service_started",
            host=host,
            port=port,
            scopes=list(scopes),
            local_tools=sorted(available_tools(policy)) if policy else None,
            policy=policy.summary() if policy else None,
            agents=f"{'wss' if ssl_context else 'ws'}://{listener.host}:{listener.port}" if listener else None,
            remote=(
                {
                    "listen": f"http://{remote.host}:{remote.port}",
                    "public_url": remote.public_url,
                    "allow_scopes": remote.allow_scopes,
                    "allow_devices": remote.allow_devices,
                }
                if remote
                else None
            ),
        )
    except AuditError as exc:
        raise SystemExit(str(exc)) from None

    server.auth = StaticTokenVerifier({token: {"client_id": CLIENT_ID, "scopes": list(scopes)}})
    local = f"commands={policy.command_mode}, writable={policy.can_write}" if policy else "no local device"
    print(
        f"[computer] MCP on http://{host}:{port}/mcp ({local}, scopes={','.join(scopes)})",
        file=sys.stderr,
        flush=True,
    )

    if remote is not None:
        print(
            f"[computer] remote MCP on http://{remote.host}:{remote.port}/mcp for {remote.public_url}/mcp "
            f"(OAuth; scopes<={','.join(remote.allow_scopes)}, devices<={','.join(remote.allow_devices)})",
            file=sys.stderr,
            flush=True,
        )

    async def serve_all() -> None:
        if hub is not None:
            await hub.start(listener.host, listener.port, ssl_context)
            scheme = "wss" if ssl_context else "ws"
            print(f"[computer] agents on {scheme}://{listener.host}:{hub.port}", file=sys.stderr, flush=True)
        # The Host/Origin guard refuses DNS-rebinding requests (FastMCP's own is off by default or absent).
        local_options = {"host": host, "port": port, "middleware": [ASGIMiddleware(HostOriginGuard, hosts=[host])]}
        listeners = [(server, local_options)]
        if remote_server is not None:
            listeners.append((remote_server, remote.http_options()))
        running = len(listeners)
        one_stopped, all_stopped = anyio.Event(), anyio.Event()

        async def serve(srv: FastMCP, options: dict[str, Any]) -> None:
            nonlocal running
            try:
                await srv.run_async(transport="http", show_banner=False, **options)
            finally:
                running -= 1
                one_stopped.set()
                if running == 0:
                    all_stopped.set()

        async def stop_together() -> None:
            # uvicorn hands a stop signal from one server to the next, so all drain gracefully;
            # if a listener stops on its own instead, the rest follow within a few seconds.
            await one_stopped.wait()
            with anyio.move_on_after(5):
                await all_stopped.wait()
            tg.cancel_scope.cancel()

        try:
            async with anyio.create_task_group() as tg:
                for srv, options in listeners:
                    tg.start_soon(serve, srv, options)
                tg.start_soon(stop_together)
        finally:
            if hub is not None:
                with contextlib.suppress(Exception):
                    await hub.close()

    anyio.run(serve_all)
