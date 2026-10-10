"""The computer engine: one tool-call entry point shared by every device.

The gateway's ``local`` device and each remote agent build an :class:`Engine`
from their own :class:`ComputerPolicy` and run tool calls through
:meth:`Engine.execute`. Arguments are validated against the handler signatures,
so an agent never trusts the shape of what the gateway sends.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from typing import Any

from pydantic import ValidationError, validate_call

from . import commands, desktop, documents, files, media, trash
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
MEDIA_TOOLS = frozenset({"media_inventory"})
PROCESS_LIST_TOOL = "list_processes"
PROCESS_KILL_TOOL = "kill_process"
DOCUMENT_READ_TOOLS = frozenset({"read_document"})
DOCUMENT_WRITE_TOOLS = frozenset({"write_document", "edit_document", "write_spreadsheet", "edit_pdf"})
DELETE_TOOL = "delete_file"
TRASH_READ_TOOL = "list_deleted"
TRASH_RESTORE_TOOL = "restore_deleted"
ENGINE_TOOLS = (
    READ_TOOLS | WRITE_TOOLS | COMMAND_TOOLS | DESKTOP_TOOLS | MEDIA_TOOLS
    | DOCUMENT_READ_TOOLS | DOCUMENT_WRITE_TOOLS
    | {PROCESS_LIST_TOOL, PROCESS_KILL_TOOL, DELETE_TOOL, TRASH_READ_TOOL, TRASH_RESTORE_TOOL}
)
_DOCUMENT_LIBRARIES = ("pypdf", "docx", "openpyxl", "reportlab")

def documents_available() -> bool:
    return all(importlib.util.find_spec(name) is not None for name in _DOCUMENT_LIBRARIES)



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
    docs = documents_available()
    if docs:
        names |= DOCUMENT_READ_TOOLS
    if policy.can_write:
        names |= WRITE_TOOLS
        if docs:
            names |= DOCUMENT_WRITE_TOOLS
    if policy.can_delete:
        names.add(DELETE_TOOL)
        if policy.delete_mode == "trash":
            names |= {TRASH_READ_TOOL, TRASH_RESTORE_TOOL}
    if policy.commands_enabled:
        names |= COMMAND_TOOLS
    if policy.media_discover:
        names |= MEDIA_TOOLS
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


@_handler("delete_file")
def _delete_file(engine: Any, path: str, recursive: bool = False) -> dict[str, Any]:
    return trash.delete_file(engine.policy, path, recursive=recursive)


@_handler("list_deleted")
def _list_deleted(engine: Any, limit: int = 50) -> dict[str, Any]:
    return trash.list_deleted(engine.policy, limit=limit)


@_handler("restore_deleted")
def _restore_deleted(engine: Any, trash_id: str) -> dict[str, Any]:
    return trash.restore_deleted(engine.policy, trash_id)


@_handler("read_document")
def _read_document(
    engine: Any,
    path: str,
    pages: str | None = None,
    sheet: str | None = None,
    cell_range: str | None = None,
    find: str | None = None,
    formulas: bool = False,
    max_chars: int | None = None,
) -> dict[str, Any]:
    return documents.read_document(
        engine.policy,
        path,
        pages=pages,
        sheet=sheet,
        cell_range=cell_range,
        find=find,
        formulas=formulas,
        max_chars=max_chars,
    )


@_handler("write_document")
def _write_document(engine: Any, path: str, content: str, title: str | None = None) -> dict[str, Any]:
    return documents.write_document(engine.policy, path, content, title=title)


@_handler("edit_document")
def _edit_document(
    engine: Any, path: str, old_text: str, new_text: str, expected_replacements: int = 1
) -> dict[str, Any]:
    return documents.edit_document(
        engine.policy, path, old_text, new_text, expected_replacements=expected_replacements
    )


@_handler("write_spreadsheet")
def _write_spreadsheet(
    engine: Any,
    path: str,
    rows: list[list[str | int | float | bool | None]],
    sheet: str | None = None,
    start_cell: str = "A1",
) -> dict[str, Any]:
    return documents.write_spreadsheet(engine.policy, path, rows, sheet=sheet, start_cell=start_cell)


@_handler("edit_pdf")
def _edit_pdf(
    engine: Any,
    path: str,
    delete_pages: str | None = None,
    rotate_pages: str | None = None,
    rotate_degrees: int = 90,
    insert_pdf: str | None = None,
    insert_at: int | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    return documents.edit_pdf(
        engine.policy,
        path,
        delete_pages=delete_pages,
        rotate_pages=rotate_pages,
        rotate_degrees=rotate_degrees,
        insert_pdf=insert_pdf,
        insert_at=insert_at,
        output_path=output_path,
    )


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


@_handler("media_inventory")
def _media_inventory(engine: Any) -> dict[str, Any]:
    return media.media_inventory(authorized=engine.policy.media_discover)


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
