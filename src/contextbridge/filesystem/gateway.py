"""ContextBridge filesystem route.

A separate MCP server from the computer route, with its own config, port,
bearer token and allowlist. It serves only the roots in its config. Write tools are
advertised only when at least one root is writable; read-only roots refuse writes.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any, Literal

import anyio
import yaml
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse

from contextbridge.hardening import protect_process_secrets

from .. import __version__
from .audit import GatewayAuditLog
from .fs import Filesystem, FsError, filesystem_from_config
from .search import (
    DEFAULT_MAX_RESULTS,
    DEFAULT_PAGE,
    DEFAULT_TIMEOUT_MS,
    SearchManager,
)
from .server import (
    AllowlistMiddleware,
    _add_audit_fields,
    _BearerTokenVerifier,
    _config_relative,
    _guard_low_level_handlers,
    _require_token,
    _AuditedServer,
    advertised_tool_names,
    unauthenticated_response,
    uvicorn_config,
)
from .policy import FS_READ_TOOLS, FS_WRITE_TOOLS

TOKEN_ENV = "CONTEXTBRIDGE_FS_AUTH_TOKEN"
COMPUTER_TOKEN_ENV = "CONTEXTBRIDGE_COMPUTER_TOKEN"
AUDIT_ENV = "CONTEXTBRIDGE_FS_AUDIT_LOG"
DEFAULT_NAME = "ContextBridge Files"

_READ = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)
# Overwrites or removes existing content.
_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False
)
_CREATE_DIRECTORY = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
)
# Reads only, but each call starts a new search.
_SEARCH = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=False, openWorldHint=False
)
# Refuses to overwrite, so nothing is lost, but a repeat call fails.
_MOVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
)


def allowed_fs_tools(fs: Filesystem) -> frozenset[str]:
    return FS_READ_TOOLS | FS_WRITE_TOOLS if fs.writable else FS_READ_TOOLS


def _instructions(fs: Filesystem) -> str:
    lines = ["Paths must be absolute and inside one of these directories:"]
    for root in fs.roots:
        lines.append(f"- {root.path} ({'read-write' if root.writable else 'read-only'})")
    lines.append("Deleted items are moved to a trash folder that tools cannot access.")
    lines.append(
        "start_search returns a search_id and the first results; page through the rest "
        "with get_more_search_results while the search runs or after it finishes."
    )
    return "\n".join(lines)


def _result_fields(result: dict[str, Any]) -> dict[str, Any]:
    """Audit fields taken from a tool's result."""
    fields: dict[str, Any] = {}
    if "bytes" in result:
        fields["size"] = result["bytes"]
    if "trash_path" in result:
        fields["destination"] = result["trash_path"]
    if "search_id" in result:
        fields["search_id"] = result["search_id"]
    if isinstance(result.get("results"), list):
        fields["result_count"] = len(result["results"])
    return fields


def create_fs_server(
    *,
    fs: Filesystem,
    token: str,
    audit: GatewayAuditLog | None = None,
    name: str = DEFAULT_NAME,
) -> FastMCP:
    """Build the filesystem route with bearer auth always attached."""
    verifier = _BearerTokenVerifier(_require_token(token, name=TOKEN_ENV))
    if audit is None:
        audit = GatewayAuditLog(os.environ.get(AUDIT_ENV), route="fs")
    allowed = allowed_fs_tools(fs)
    searches = SearchManager(fs)
    server = _AuditedServer(
        name=name,
        version=__version__,
        auth=verifier,
        mask_error_details=True,
        instructions=_instructions(fs),
    )
    server.audit_log = audit

    def audited(
        op: Callable[[], dict[str, Any]],
        *,
        path: str | list[str] | None = None,
        destination: str | None = None,
        search_id: str | None = None,
        query: str | None = None,
    ) -> dict[str, Any]:
        # Audit as one request through middleware, not a second per-tool log.
        _add_audit_fields(path=path, destination=destination, search_id=search_id, query=query)
        try:
            result = op()
        except FsError as exc:
            _add_audit_fields(detail=exc.code)
            raise ToolError(str(exc)) from None
        fields = _result_fields(result)
        _add_audit_fields(**fields)
        return result

    async def run(op: Callable[..., dict[str, Any]], *args: Any, **audit_kw: Any) -> Any:
        # Filesystem calls block, so they run in a worker thread. abandon_on_cancel
        # lets the middleware's timeout answer the client; the thread itself can't be
        # stopped and may still finish, but it can no longer write an audit line.
        work = partial(audited, partial(op, *args), **audit_kw)
        return await anyio.to_thread.run_sync(work, abandon_on_cancel=True)

    @server.tool(name="read_file", annotations=_READ)
    async def read_file(path: str, offset: int = 0, length: int | None = None) -> dict[str, Any]:
        """Read a UTF-8 text file by lines. path must be absolute or start with ~. offset is the
        0-based first line; a negative offset reads the last lines (offset=-50 reads the last 50).
        length caps the lines returned (default 1000). When has_more is true, read on with offset
        set to start_line + line_count. Binary files are refused."""
        return await run(fs.read_file, path, offset, length, path=path)

    @server.tool(name="read_multiple_files", annotations=_READ)
    async def read_multiple_files(paths: list[str]) -> dict[str, Any]:
        """Read up to 50 UTF-8 text files in one call, each in full up to a shared size limit. A
        file that fails (missing, binary, or over the limit) gets an error in its own entry; the
        others are still read. Use read_file with offset and length for a large file."""
        return await run(fs.read_multiple_files, paths, path=paths)

    @server.tool(name="list_directory", annotations=_READ)
    async def list_directory(path: str, depth: int = 2) -> dict[str, Any]:
        """List a directory's entries up to depth levels deep (1-10, default 2). Symlinks are
        listed, not followed. truncated means the entry limit was reached; list a subdirectory, or
        use a smaller depth, to see the rest."""
        return await run(fs.list_directory, path, depth, path=path)

    @server.tool(name="get_file_info", annotations=_READ)
    async def get_file_info(path: str) -> dict[str, Any]:
        """Show a file's or directory's size, timestamps, permissions, and type, whether it is a
        symlink, and whether its root is writable. Use it to size up a large file before reading it."""
        return await run(fs.get_file_info, path, path=path)

    @server.tool(name="start_search", annotations=_SEARCH)
    async def start_search(
        path: str,
        pattern: str,
        search_type: Literal["files", "content"] = "files",
        file_pattern: str | None = None,
        ignore_case: bool = True,
        literal: bool = False,
        include_hidden: bool = False,
        context_lines: int = 0,
        max_results: int = DEFAULT_MAX_RESULTS,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, Any]:
        """Search recursively under path in the background. search_type "files" (default) matches
        file and directory names: a glob if pattern has *, ? or [, else a substring. "content"
        matches lines of text files against a regular expression, or plain text with literal=true.
        file_pattern limits which files are searched ("*.py", "*.{ts,tsx}|*.md"). Hidden entries are
        skipped unless include_hidden is true. Returns a search_id, the status, and the first
        results; line numbers are 1-based."""
        return await run(
            searches.start,
            path,
            pattern,
            search_type,
            file_pattern,
            ignore_case,
            literal,
            include_hidden,
            context_lines,
            max_results,
            timeout_ms,
            path=path,
            query=pattern,
        )

    @server.tool(name="get_more_search_results", annotations=_READ)
    async def get_more_search_results(
        search_id: str, offset: int = 0, length: int = DEFAULT_PAGE
    ) -> dict[str, Any]:
        """Get a page of a search's results from offset (0-based; negative counts from the end).
        has_more stays true while more results exist or the search is still running, so keep paging
        until it is false."""
        return await run(
            searches.more, search_id, offset, length, search_id=search_id
        )

    @server.tool(name="stop_search", annotations=_READ)
    async def stop_search(search_id: str) -> dict[str, Any]:
        """Stop a running search. The results found so far stay available to
        get_more_search_results."""
        return await run(searches.stop, search_id, search_id=search_id)

    @server.tool(name="list_searches", annotations=_READ)
    async def list_searches() -> dict[str, Any]:
        """List recent searches with their status and how many results each has."""
        return await run(searches.list)

    if fs.writable:

        @server.tool(name="write_file", annotations=_DESTRUCTIVE)
        async def write_file(
            path: str, content: str, mode: Literal["rewrite", "append"] = "rewrite"
        ) -> dict[str, Any]:
            """Create or replace a text file (mode "rewrite", atomic, keeping the file's
            permissions) or add to its end (mode "append"). The parent directory must exist; create
            it with create_directory. Each call is limited in size: write a large file as a first
            part and then appends. To change part of an existing file, edit_block is safer than
            rewriting it."""
            return await run(fs.write_file, path, content, mode, path=path)

        @server.tool(name="edit_block", annotations=_DESTRUCTIVE)
        async def edit_block(
            file_path: str, old_string: str, new_string: str, expected_replacements: int = 1
        ) -> dict[str, Any]:
            """Replace exact text in a file: the preferred way to change part of a file. old_string
            must match the file exactly, whitespace and line endings included, so read the lines
            first. The call fails unless old_string occurs exactly expected_replacements times
            (default 1); add surrounding lines to make one match unique. When old_string is not
            found, the error shows the closest text in the file and how it differs."""
            return await run(
                fs.edit_block,
                file_path,
                old_string,
                new_string,
                expected_replacements,
                path=file_path,
            )

        @server.tool(name="create_directory", annotations=_CREATE_DIRECTORY)
        async def create_directory(path: str) -> dict[str, Any]:
            """Create a directory, including any missing parent directories. Succeeds if it already
            exists."""
            return await run(fs.create_directory, path, path=path)

        @server.tool(name="move_file", annotations=_MOVE)
        async def move_file(source: str, destination: str) -> dict[str, Any]:
            """Move or rename a file or directory. Refused if destination already exists, so nothing
            is overwritten."""
            return await run(
                fs.move_file, source, destination, path=source, destination=destination
            )

        @server.tool(name="delete_file", annotations=_DESTRUCTIVE)
        async def delete_file(path: str, recursive: bool = False) -> dict[str, Any]:
            """Delete a file, symlink, or directory by moving it to a trash folder that tools cannot
            reach; it can be restored only on the host. A non-empty directory needs recursive=true."""
            return await run(fs.delete_file, path, recursive, path=path)

    server.add_middleware(
        AllowlistMiddleware(
            audit,
            allowed_tools=allowed,
            route_name="filesystem",
            service_name="ContextBridge filesystem",
        )
    )
    _guard_low_level_handlers(server, audit, route_name="filesystem")

    @server.custom_route("/", methods=["GET"])
    async def root_status(request: Request) -> JSONResponse:
        if (refused := unauthenticated_response(request)) is not None:
            return refused
        return JSONResponse({"service": name, "mcp_path": "/mcp", "tools": sorted(allowed)})

    return server


def main() -> None:
    ap = argparse.ArgumentParser(description="ContextBridge filesystem route")
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    # Other processes of this user (a computer-route command, say) must not read the token from /proc.
    protect_process_secrets()
    try:
        token = _require_token(os.environ.get(TOKEN_ENV), name=TOKEN_ENV)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    if token == os.environ.get(COMPUTER_TOKEN_ENV):
        raise SystemExit(f"{TOKEN_ENV} must differ from {COMPUTER_TOKEN_ENV}.")

    serve = cfg.get("serve") or {}
    host = serve.get("host", "127.0.0.1")
    port = serve.get("port")
    if not port:
        raise SystemExit(f"{args.config}: serve.port is required.")

    try:
        config_path = Path(args.config)
        fs = filesystem_from_config(cfg.get("filesystem"), config_path=config_path)
        configured_log = serve.get("audit_log")
        audit_log = os.environ.get(AUDIT_ENV) or (
            str(_config_relative(configured_log, config_path)) if configured_log else None
        )
        audit = GatewayAuditLog(audit_log, route="fs")
    except (OSError, ValueError) as exc:
        raise SystemExit(f"filesystem route startup failed: {exc}") from None

    server = create_fs_server(
        fs=fs, token=token, audit=audit, name=cfg.get("name", DEFAULT_NAME)
    )
    expected = allowed_fs_tools(fs)
    advertised = advertised_tool_names(server)
    if advertised != expected:
        raise SystemExit(
            f"filesystem tool surface mismatch: expected {set(expected)!r}, got {advertised!r}"
        )

    writable = sum(root.writable for root in fs.roots)
    print(
        f"[filesystem] serving {len(advertised)} tools over {len(fs.roots)} root(s) "
        f"({writable} writable) on {host}:{port}",
        file=sys.stderr,
        flush=True,
    )
    server.run(
        transport="http",
        host=host,
        port=port,
        show_banner=False,
        uvicorn_config=uvicorn_config(serve),
    )


if __name__ == "__main__":
    main()
