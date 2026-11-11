"""MCP federation: tools from MCP servers the host runs, offered through ContextBridge.

A device's own config may list MCP servers (``mcp_servers``) for its engine to
start over stdio, for example ``agent-desktop mcp`` for desktop automation or a
Playwright MCP server for a browser. The engine lists their tools at startup and
offers each one under a prefixed name (``<server>_<tool>``); the gateway shows
those tools to callers with a ``device`` argument and routes calls back here.

Only the machine's own config can add a server: the gateway can call the tools a
device reports, never start a program. Each server is tied to one scope from
:mod:`.scopes` (``computer:execute`` unless configured), which the caller's token
and the device's registry grant must both carry; ``tool_scopes`` can give single
tools another scope (``desktop:observe`` for a screenshot tool, say).

The servers run in one background thread with its own event loop, so the
synchronous :class:`~.dispatch.Engine` can call them from any worker thread. A
server that exits is started again on its next call.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from .policy import PolicyError
from .scopes import ALL_SCOPES, SCOPE_EXECUTE

SERVER_NAME = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DEVICE_ARG = "device"
DEFAULT_TIMEOUT_SECONDS = 120.0
MAX_TIMEOUT_SECONDS = 600.0
DEFAULT_STARTUP_SECONDS = 30.0
RESTART_INTERVAL_SECONDS = 5.0
MAX_TOOLS_PER_DEVICE = 256
MAX_DESCRIPTION_CHARS = 2000
MAX_SCHEMA_BYTES = 64 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 12 * 1024 * 1024
ANNOTATION_HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


class FederationError(RuntimeError):
    """A federated MCP server could not run a call (not started, crashed, timed out, bad reply)."""


# --------------------------------------------------------------------- config


@dataclass(frozen=True)
class McpServerConfig:
    """One entry of a device's ``mcp_servers`` section."""

    name: str
    command: str
    args: tuple[str, ...] = ()
    scope: str = SCOPE_EXECUTE
    tools: frozenset[str] | None = None
    tool_scopes: Mapping[str, str] = field(default_factory=dict)
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: Path | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    startup_seconds: float = DEFAULT_STARTUP_SECONDS


def _number(entry: dict[str, Any], key: str, default: float, high: float, where: str) -> float:
    value = entry.get(key, default)
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 < value <= high:
        raise PolicyError(f"{where}.{key} must be a number above 0 and at most {high:g}")
    return float(value)


def load_mcp_servers(cfg: dict[str, Any], *, base: Path | None = None) -> tuple[McpServerConfig, ...]:
    """Parse the ``mcp_servers`` section (a mapping of server name to settings)."""
    section = cfg.get("mcp_servers")
    if section is None:
        return ()
    if not isinstance(section, dict):
        raise PolicyError("mcp_servers must be a mapping of server name to settings")
    servers = []
    for name, entry in section.items():
        where = f"mcp_servers.{name}"
        if not isinstance(name, str) or not SERVER_NAME.match(name):
            raise PolicyError(f"{where}: server names are 1-24 lowercase letters, digits, or '-', starting with a letter")
        if not isinstance(entry, dict):
            raise PolicyError(f"{where} must be a mapping")
        if entry.get("enabled", True) is False:
            continue
        command = entry.get("command")
        if not isinstance(command, str) or not command.strip():
            raise PolicyError(f"{where}.command is required")
        args = entry.get("args", [])
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise PolicyError(f"{where}.args must be a list of strings")
        scope = entry.get("scope", SCOPE_EXECUTE)
        if scope not in ALL_SCOPES:
            raise PolicyError(f"{where}.scope must be one of {', '.join(ALL_SCOPES)}")
        tools = entry.get("tools")
        if tools is not None and (not isinstance(tools, list) or not all(isinstance(t, str) and t for t in tools)):
            raise PolicyError(f"{where}.tools must be a list of tool names")
        tool_scopes = entry.get("tool_scopes", {})
        if not isinstance(tool_scopes, dict) or not all(
            isinstance(k, str) and v in ALL_SCOPES for k, v in tool_scopes.items()
        ):
            raise PolicyError(f"{where}.tool_scopes must map tool names to one of {', '.join(ALL_SCOPES)}")
        env = entry.get("env", {})
        if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
            raise PolicyError(f"{where}.env must map variable names to strings")
        cwd = entry.get("cwd")
        if cwd is not None and (not isinstance(cwd, str) or not cwd):
            raise PolicyError(f"{where}.cwd must be a directory path")
        cwd_path = Path(cwd).expanduser() if cwd else None
        if cwd_path is not None and not cwd_path.is_absolute() and base is not None:
            cwd_path = base / cwd_path
        servers.append(
            McpServerConfig(
                name=name,
                command=command,
                args=tuple(args),
                scope=scope,
                tools=frozenset(tools) if tools is not None else None,
                tool_scopes=dict(tool_scopes),
                env=dict(env),
                cwd=cwd_path,
                timeout_seconds=_number(entry, "timeout_seconds", DEFAULT_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS, where),
                startup_seconds=_number(entry, "startup_seconds", DEFAULT_STARTUP_SECONDS, 300.0, where),
            )
        )
    return tuple(servers)


# ---------------------------------------------------------------------- tools


@dataclass(frozen=True)
class FederatedTool:
    """A tool one device offers from one of its MCP servers, as the gateway sees it."""

    name: str
    server: str
    description: str
    input_schema: dict[str, Any]
    scope: str
    annotations: dict[str, Any] | None = None

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {
            "name": self.name,
            "server": self.server,
            "description": self.description,
            "input_schema": self.input_schema,
            "scope": self.scope,
        }
        if self.annotations:
            wire["annotations"] = self.annotations
        return wire


def exposed_name(server: str, tool: str) -> str:
    """``<server>_<tool>``; a tool already named with that prefix keeps its name."""
    prefix = f"{server}_"
    return tool if tool.startswith(prefix) else prefix + tool


def _clean_annotations(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    clean: dict[str, Any] = {k: raw[k] for k in ANNOTATION_HINTS if isinstance(raw.get(k), bool)}
    if isinstance(raw.get("title"), str):
        clean["title"] = raw["title"][:200]
    return clean or None


def _check_schema(schema: Any) -> dict[str, Any]:
    if not isinstance(schema, dict) or schema.get("type", "object") != "object":
        raise ValueError("input schema must be a JSON object schema")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ValueError("input schema properties must be an object")
    if DEVICE_ARG in properties:
        raise ValueError(f"input schema already has a '{DEVICE_ARG}' argument")
    if len(json.dumps(schema, separators=(",", ":"), default=str)) > MAX_SCHEMA_BYTES:
        raise ValueError("input schema is too large")
    return schema


def tools_from_wire(raw: Any, *, reserved: frozenset[str]) -> dict[str, FederatedTool]:
    """Validate the federated tools an agent reports; anything malformed is dropped."""
    tools: dict[str, FederatedTool] = {}
    if not isinstance(raw, list):
        return tools
    for item in raw[:MAX_TOOLS_PER_DEVICE]:
        if not isinstance(item, dict):
            continue
        name, server, scope = item.get("name"), item.get("server"), item.get("scope")
        if not isinstance(name, str) or not TOOL_NAME.match(name) or name in reserved or name in tools:
            continue
        if not isinstance(server, str) or not SERVER_NAME.match(server) or scope not in ALL_SCOPES:
            continue
        try:
            schema = _check_schema(item.get("input_schema"))
        except ValueError:
            continue
        description = item.get("description")
        tools[name] = FederatedTool(
            name=name,
            server=server,
            description=description[:MAX_DESCRIPTION_CHARS] if isinstance(description, str) else "",
            input_schema=schema,
            scope=scope,
            annotations=_clean_annotations(item.get("annotations")),
        )
    return tools


def result_text(result: dict[str, Any]) -> str:
    """The text blocks of a federated result, for error messages."""
    parts = [
        str(block.get("text", ""))
        for block in result.get("content") or []
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    return "\n".join(p for p in parts if p).strip()


# ------------------------------------------------------------------- runtime


@dataclass
class _Server:
    config: McpServerConfig
    session: Any = None
    tools: dict[str, Any] = field(default_factory=dict)  # exposed name -> downstream mcp Tool
    task: asyncio.Task[None] | None = None
    stop: asyncio.Event | None = None
    last_start: float = 0.0
    error: str | None = None


class Federation:
    """Runs a device's MCP servers and relays calls to them."""

    def __init__(
        self,
        servers: tuple[McpServerConfig, ...],
        *,
        env: Mapping[str, str] | None = None,
        reserved: frozenset[str] = frozenset(),
        log: Callable[[str], None] | None = None,
    ) -> None:
        self._servers = {cfg.name: _Server(cfg) for cfg in servers}
        self._env = dict(env) if env is not None else None
        self._reserved = reserved
        self._log = log or (lambda message: print(f"[federation] {message}", file=sys.stderr, flush=True))
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._tools: dict[str, FederatedTool] = {}
        self._routes: dict[str, tuple[str, str]] = {}  # exposed name -> (server, downstream tool)
        self._lock = threading.Lock()

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        """Start every server and list its tools. A server that fails is logged and left out."""
        if self._thread is not None or not self._servers:
            return
        loop = asyncio.new_event_loop()
        self._loop = loop
        self._thread = threading.Thread(target=loop.run_forever, name="contextbridge-federation", daemon=True)
        self._thread.start()
        for server in self._servers.values():
            future = asyncio.run_coroutine_threadsafe(self._launch(server), loop)
            try:
                future.result(timeout=server.config.startup_seconds + 5)
            except Exception as exc:  # noqa: BLE001 -- one bad server must not stop the device
                future.cancel()
                server.error = f"{type(exc).__name__}: {exc}"[:300]
                self._log(f"MCP server '{server.config.name}' did not start: {server.error}")
        self._rebuild()

    def close(self) -> None:
        loop, thread = self._loop, self._thread
        if loop is None or thread is None:
            return
        with contextlib.suppress(Exception):
            asyncio.run_coroutine_threadsafe(self._stop_all(), loop).result(timeout=10)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5)
        self._loop = self._thread = None

    @property
    def tools(self) -> dict[str, FederatedTool]:
        with self._lock:
            return dict(self._tools)

    def describe(self) -> list[dict[str, Any]]:
        rows = []
        for server in self._servers.values():
            row: dict[str, Any] = {
                "server": server.config.name,
                "scope": server.config.scope,
                "running": server.session is not None,
                "tools": sorted(server.tools),
            }
            if server.error:
                row["error"] = server.error
            rows.append(row)
        return rows

    # ---------------------------------------------------------------- calls

    def server_for(self, name: str) -> str | None:
        with self._lock:
            route = self._routes.get(name)
        return route[0] if route else None

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Run tool ``name`` (its exposed name) and return ``{content, structured_content, is_error}``."""
        with self._lock:
            route = self._routes.get(name)
        if route is None or self._loop is None:
            raise FederationError(f"Tool '{name}' is not available.")
        server = self._servers[route[0]]
        timeout = server.config.timeout_seconds
        future = asyncio.run_coroutine_threadsafe(self._call(server, route[1], arguments), self._loop)
        try:
            return future.result(timeout=timeout + server.config.startup_seconds + 10)
        except TimeoutError:
            future.cancel()
            raise FederationError(f"MCP server '{server.config.name}' did not answer within {timeout:g}s.") from None

    async def _call(self, server: _Server, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if server.session is None:
            await self._restart(server)
        session = server.session
        if session is None:
            raise FederationError(f"MCP server '{server.config.name}' is not running.")
        timeout = server.config.timeout_seconds
        try:
            result = await asyncio.wait_for(
                session.call_tool(tool, arguments, read_timeout_seconds=timedelta(seconds=timeout)), timeout + 5
            )
        except TimeoutError:
            raise FederationError(f"MCP server '{server.config.name}' did not answer within {timeout:g}s.") from None
        except Exception as exc:  # noqa: BLE001 -- the transport broke or the server refused
            from mcp.shared.exceptions import McpError
            from mcp.types import CONNECTION_CLOSED

            refused = isinstance(exc, McpError) and exc.error.code != CONNECTION_CLOSED
            if not refused or server.task is None or server.task.done():
                await self._stop(server)  # the server is gone; it is started again on the next call
            raise FederationError(f"MCP server '{server.config.name}': {exc}"[:2000]) from None
        reply: dict[str, Any] = {
            "content": [block.model_dump(mode="json", by_alias=True, exclude_none=True) for block in result.content],
            "structured_content": result.structuredContent if isinstance(result.structuredContent, dict) else None,
            "is_error": bool(result.isError),
        }
        if len(json.dumps(reply, separators=(",", ":"), default=str)) > MAX_RESULT_BYTES:
            raise FederationError(f"Result from '{tool}' is larger than {MAX_RESULT_BYTES // (1024 * 1024)} MB.")
        return reply

    # --------------------------------------------------------------- servers

    async def _launch(self, server: _Server) -> None:
        server.last_start = time.monotonic()
        server.stop = asyncio.Event()
        ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        server.task = asyncio.create_task(self._serve(server, ready))
        try:
            await asyncio.wait_for(asyncio.shield(ready), server.config.startup_seconds)
        except BaseException:
            await self._stop(server)
            raise
        server.error = None

    async def _serve(self, server: _Server, ready: asyncio.Future[None]) -> None:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        cfg = server.config
        env = {**(self._env or {}), **cfg.env} if (self._env is not None or cfg.env) else None
        params = StdioServerParameters(
            command=cfg.command, args=list(cfg.args), env=env, cwd=str(cfg.cwd) if cfg.cwd else None
        )
        try:
            async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
                await session.initialize()
                server.tools = await self._list(session, cfg)
                server.session = session
                if not ready.done():
                    ready.set_result(None)
                assert server.stop is not None
                await server.stop.wait()
        except BaseException as exc:
            if not ready.done():
                ready.set_exception(exc if isinstance(exc, Exception) else FederationError("stopped"))
            elif not isinstance(exc, asyncio.CancelledError):
                server.error = f"{type(exc).__name__}: {exc}"[:300]
                self._log(f"MCP server '{cfg.name}' stopped: {server.error}")
            if isinstance(exc, asyncio.CancelledError):
                raise
        finally:
            server.session = None

    async def _list(self, session: Any, cfg: McpServerConfig) -> dict[str, Any]:
        found: dict[str, Any] = {}
        cursor = None
        while True:
            page = await session.list_tools(cursor=cursor) if cursor else await session.list_tools()
            for tool in page.tools:
                if cfg.tools is not None and tool.name not in cfg.tools:
                    continue
                name = exposed_name(cfg.name, tool.name)
                if not TOOL_NAME.match(name):
                    self._log(f"MCP server '{cfg.name}': skipped '{tool.name}' (name not allowed)")
                    continue
                try:
                    _check_schema(tool.inputSchema)
                except ValueError as exc:
                    self._log(f"MCP server '{cfg.name}': skipped '{tool.name}' ({exc})")
                    continue
                found[name] = tool
            cursor = page.nextCursor
            if not cursor or len(found) >= MAX_TOOLS_PER_DEVICE:
                return found

    async def _restart(self, server: _Server) -> None:
        if time.monotonic() - server.last_start < RESTART_INTERVAL_SECONDS:
            return
        await self._stop(server)
        try:
            await self._launch(server)
        except Exception as exc:  # noqa: BLE001
            server.error = f"{type(exc).__name__}: {exc}"[:300]
            self._log(f"MCP server '{server.config.name}' did not restart: {server.error}")
            return
        self._rebuild()

    async def _stop(self, server: _Server) -> None:
        task = server.task
        server.task = None
        server.session = None
        if server.stop is not None:
            server.stop.set()
        if task is not None and not task.done():
            try:
                await asyncio.wait_for(task, 10)
            except BaseException:  # noqa: BLE001 -- stopping is best effort
                task.cancel()

    async def _stop_all(self) -> None:
        await asyncio.gather(*(self._stop(s) for s in self._servers.values()), return_exceptions=True)

    def _rebuild(self) -> None:
        tools: dict[str, FederatedTool] = {}
        routes: dict[str, tuple[str, str]] = {}
        for server in self._servers.values():
            for name, tool in server.tools.items():
                if name in self._reserved or name in tools:
                    self._log(f"MCP server '{server.config.name}': skipped '{name}' (name already in use)")
                    continue
                if len(tools) >= MAX_TOOLS_PER_DEVICE:
                    break
                annotations = tool.annotations.model_dump(exclude_none=True) if tool.annotations else None
                tools[name] = FederatedTool(
                    name=name,
                    server=server.config.name,
                    description=(tool.description or tool.title or "")[:MAX_DESCRIPTION_CHARS],
                    input_schema=dict(tool.inputSchema),
                    scope=server.config.tool_scopes.get(tool.name, server.config.scope),
                    annotations=_clean_annotations(annotations),
                )
                routes[name] = (server.config.name, tool.name)
        with self._lock:
            self._tools, self._routes = tools, routes
