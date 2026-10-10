"""The computer engine: one tool-call entry point shared by every device.

The gateway's ``local`` device and each remote agent build an :class:`Engine`
from their own :class:`ComputerPolicy` and run tool calls through
:meth:`Engine.execute`. Arguments are validated against the handler signatures,
so an agent never trusts the shape of what the gateway sends.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import ValidationError, validate_call

from . import commands, files, desktop
from .commands import ExitCallback, SessionManager
from .policy import ComputerPolicy, PolicyViolation
from .system import system_info

READ_TOOLS = frozenset(
    {"list_directory", "read_file", "get_file_info", "search_files", "search_code", "get_system_info"}
)
WRITE_TOOLS = frozenset({"write_file", "edit_block", "create_directory", "move_file"})
COMMAND_TOOLS = frozenset(
    {"run_command", "start_process", "read_process_output", "interact_with_process", "force_terminate", "list_sessions"}
)
DESKTOP_TOOLS = frozenset({"list_windows"})
PROCESS_LIST_TOOL = "list_processes"
PROCESS_KILL_TOOL = "kill_process"
ENGINE_TOOLS = READ_TOOLS | WRITE_TOOLS | COMMAND_TOOLS | DESKTOP_TOOLS | {PROCESS_LIST_TOOL, PROCESS_KILL_TOOL}


class InvalidArguments(ValueError):
    """Raised when a tool call's arguments do not match the tool's signature."""


def call_succeeded(tool: str, result: Any) -> bool:
    """Whether a call that returned normally achieved its goal (commands: exit 0, no timeout)."""
    if tool == "run_command" and isinstance(result, dict):
        return result.get("exit_code") == 0 and not result.get("timed_out")
    return True


def available_tools(policy: ComputerPolicy) -> frozenset[str]:
    """The exact tool surface ``policy`` permits."""
    names = set(READ_TOOLS)
    if policy.can_write:
        names |= WRITE_TOOLS
    if policy.commands_enabled:
        names |= COMMAND_TOOLS
    if policy.desktop_observe:
        names |= DESKTOP_TOOLS
    if policy.list_processes:
        names.add(PROCESS_LIST_TOOL)
    if policy.allow_kill:
        names.add(PROCESS_KILL_TOOL)
    return frozenset(names)


class Engine:
    """Executes tool calls on this machine under ``policy``."""

    def __init__(self, policy: ComputerPolicy, *, on_exit: ExitCallback | None = None) -> None:
        self.policy = policy
        self.tools = available_tools(policy)
        self.sessions = SessionManager(policy, on_exit=on_exit) if policy.commands_enabled else None

    def execute(self, tool: str, args: dict[str, Any] | None) -> dict[str, Any]:
        if tool not in self.tools:
            raise PolicyViolation(f"Tool '{tool}' is not enabled on this computer.")
        handler = _HANDLERS[tool]
        try:
            return handler(self, **(args or {}))
        except ValidationError as exc:
            problems = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
            raise InvalidArguments(f"Invalid arguments for '{tool}': {problems}") from None

    def shutdown(self) -> None:
        if self.sessions is not None:
            self.sessions.shutdown()


_HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {}


def _handler(name: str):
    def register(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        _HANDLERS[name] = validate_call(fn)
        return fn

    return register


@_handler("list_directory")
def _list_directory(engine: Any, path: str, depth: int = 1) -> dict[str, Any]:
    return files.list_directory(engine.policy, path, depth=depth)


@_handler("read_file")
def _read_file(engine: Any, path: str, offset: int = 0, length: int | None = None) -> dict[str, Any]:
    return files.read_file(engine.policy, path, offset=offset, length=length)


@_handler("get_file_info")
def _get_file_info(engine: Any, path: str) -> dict[str, Any]:
    return files.get_file_info(engine.policy, path)


@_handler("search_files")
def _search_files(engine: Any, path: str, pattern: str, max_results: int | None = None) -> dict[str, Any]:
    return files.search_files(engine.policy, path, pattern, max_results=max_results)


@_handler("search_code")
def _search_code(
    engine: Any,
    path: str,
    pattern: str,
    file_pattern: str | None = None,
    regex: bool = False,
    case_sensitive: bool = False,
    context_lines: int = 0,
    max_results: int | None = None,
) -> dict[str, Any]:
    return files.search_code(
        engine.policy,
        path,
        pattern,
        file_pattern=file_pattern,
        regex=regex,
        case_sensitive=case_sensitive,
        context_lines=context_lines,
        max_results=max_results,
    )


@_handler("get_system_info")
def _get_system_info(engine: Any) -> dict[str, Any]:
    return system_info(engine.policy)


@_handler("write_file")
def _write_file(engine: Any, path: str, content: str, mode: str = "rewrite") -> dict[str, Any]:
    return files.write_file(engine.policy, path, content, mode=mode)


@_handler("edit_block")
def _edit_block(
    engine: Any, path: str, old_string: str, new_string: str, expected_replacements: int = 1
) -> dict[str, Any]:
    return files.edit_block(engine.policy, path, old_string, new_string, expected_replacements=expected_replacements)


@_handler("create_directory")
def _create_directory(engine: Any, path: str) -> dict[str, Any]:
    return files.create_directory(engine.policy, path)


@_handler("move_file")
def _move_file(engine: Any, source: str, destination: str) -> dict[str, Any]:
    return files.move_file(engine.policy, source, destination)


@_handler("run_command")
def _run_command(
    engine: Any, command: str, cwd: str | None = None, timeout_seconds: float | None = None
) -> dict[str, Any]:
    return commands.run_command(engine.policy, command, cwd=cwd, timeout_seconds=timeout_seconds)


@_handler("start_process")
def _start_process(
    engine: Any,
    command: str,
    cwd: str | None = None,
    timeout_seconds: float | None = None,
    wait_seconds: float = 1.0,
) -> dict[str, Any]:
    return engine.sessions.start(command, cwd=cwd, timeout_seconds=timeout_seconds, wait_seconds=wait_seconds)


@_handler("read_process_output")
def _read_process_output(engine: Any, session_id: str, wait_seconds: float = 0.0) -> dict[str, Any]:
    return engine.sessions.read(session_id, wait_seconds=wait_seconds)


@_handler("interact_with_process")
def _interact_with_process(
    engine: Any, session_id: str, input: str, append_newline: bool = True, wait_seconds: float = 1.0
) -> dict[str, Any]:
    return engine.sessions.send(session_id, input, newline=append_newline, wait_seconds=wait_seconds)


@_handler("force_terminate")
def _force_terminate(engine: Any, session_id: str) -> dict[str, Any]:
    return engine.sessions.terminate(session_id)


@_handler("list_sessions")
def _list_sessions(engine: Any) -> dict[str, Any]:
    return {"sessions": engine.sessions.list()}


@_handler("list_windows")
def _list_windows(engine: Any) -> dict[str, Any]:
    return desktop.list_windows(authorized=engine.policy.desktop_observe)


@_handler("list_processes")
def _list_processes(engine: Any, name_filter: str | None = None, limit: int = 200) -> dict[str, Any]:
    return commands.list_processes(name_filter=name_filter, limit=max(1, min(limit, 1000)))


@_handler("kill_process")
def _kill_process(engine: Any, pid: int, force: bool = False) -> dict[str, Any]:
    return commands.kill_process(pid, force=force)


if set(_HANDLERS) != ENGINE_TOOLS:
    raise RuntimeError("every engine tool needs exactly one handler")
