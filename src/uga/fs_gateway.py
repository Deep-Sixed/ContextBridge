"""ContextBridge filesystem route.

A separate MCP server from the read-only UGA route, with its own config, port,
bearer token and allowlist. It serves only the roots in its config. Write tools are
advertised only when at least one root is writable; read-only roots refuse writes.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
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

from . import __version__
from .audit import UgaAuditLog
from .fs import Filesystem, FsError, filesystem_from_config
from .fs_search import (
    DEFAULT_MAX_RESULTS,
    DEFAULT_PAGE,
    DEFAULT_TIMEOUT_MS,
    SearchManager,
)
from .gateway import (
    UgaAllowlistMiddleware,
    _BearerTokenVerifier,
    _current_request_id,
    _elapsed_ms,
    _require_token,
    advertised_tool_names,
    http_middleware,
    unauthenticated_response,
)
from .policy import FS_READ_TOOLS, FS_WRITE_TOOLS

TOKEN_ENV = "CONTEXTBRIDGE_FS_AUTH_TOKEN"
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
    audit: UgaAuditLog | None = None,
    name: str = DEFAULT_NAME,
) -> FastMCP:
    """Build the filesystem route with bearer auth always attached."""
    verifier = _BearerTokenVerifier(_require_token(token, name=TOKEN_ENV))
    if audit is None:
        audit = UgaAuditLog(os.environ.get(AUDIT_ENV), route="fs")
    allowed = allowed_fs_tools(fs)
    searches = SearchManager(fs)
    server = FastMCP(
        name=name,
        version=__version__,
        auth=verifier,
        mask_error_details=True,
        instructions=_instructions(fs),
    )

    def audited(tool: str, op: Callable[[], dict[str, Any]], **fields: Any) -> dict[str, Any]:
        """Run ``op`` and write the tool's audit line; ``fields`` go to the audit log."""
        started = time.monotonic()
        request_id = _current_request_id.get()
        try:
            result = op()
        except FsError as exc:
            audit.record(
                tool=tool,
                **fields,
                success=False,
                detail=exc.code,
                request_id=request_id,
                elapsed_ms=_elapsed_ms(started),
            )
            raise ToolError(str(exc)) from None
        except Exception as exc:
            audit.record(
                tool=tool,
                **fields,
                success=False,
                detail=type(exc).__name__,
                request_id=request_id,
                elapsed_ms=_elapsed_ms(started),
            )
            raise
        audit.record(
            tool=tool,
            **{**fields, **_result_fields(result)},
            success=True,
            request_id=request_id,
            elapsed_ms=_elapsed_ms(started),
        )
        return result

    async def run(tool: str, op: Callable[..., dict[str, Any]], *args: Any, **audit_kw: Any) -> Any:
        # abandon_on_cancel lets the middleware's timeout cancel the call; see gateway.py.
        work = partial(audited, tool, partial(op, *args), **audit_kw)
        return await anyio.to_thread.run_sync(work, abandon_on_cancel=True)

    @server.tool(name="read_file", annotations=_READ)
    async def read_file(path: str, offset: int = 0, length: int | None = None) -> dict[str, Any]:
        """Read a UTF-8 text file by line. offset is the first line (0-based); a
        negative offset reads the last lines. length caps the lines returned."""
        return await run("read_file", fs.read_file, path, offset, length, path=path)

    @server.tool(name="read_multiple_files", annotations=_READ)
    async def read_multiple_files(paths: list[str]) -> dict[str, Any]:
        """Read several UTF-8 text files. A failure on one file is reported in its
        entry and does not fail the others."""
        return await run("read_multiple_files", fs.read_multiple_files, paths, path=paths)

    @server.tool(name="list_directory", annotations=_READ)
    async def list_directory(path: str, depth: int = 2) -> dict[str, Any]:
        """List a directory's entries up to depth levels deep. Symlinks are listed,
        not followed."""
        return await run("list_directory", fs.list_directory, path, depth, path=path)

    @server.tool(name="get_file_info", annotations=_READ)
    async def get_file_info(path: str) -> dict[str, Any]:
        """Get a file's or directory's size, timestamps, permissions and type."""
        return await run("get_file_info", fs.get_file_info, path, path=path)

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
        """Search recursively under path, in the background. search_type "files"
        matches file and directory names (a glob if pattern has * ? or [, else a
        substring); "content" matches lines of text files against a regular
        expression, or a plain string with literal=true. file_pattern limits which
        files are searched, e.g. "*.py" or "*.{ts,tsx}|*.md". Returns a search_id,
        the status and the first results; line numbers are 1-based."""
        return await run(
            "start_search",
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
        """Get results of a search from offset (0-based; negative counts from the
        end). has_more is true while more results exist or the search is running."""
        return await run(
            "get_more_search_results", searches.more, search_id, offset, length, search_id=search_id
        )

    @server.tool(name="stop_search", annotations=_READ)
    async def stop_search(search_id: str) -> dict[str, Any]:
        """Stop a running search. Results found so far stay available."""
        return await run("stop_search", searches.stop, search_id, search_id=search_id)

    @server.tool(name="list_searches", annotations=_READ)
    async def list_searches() -> dict[str, Any]:
        """List recent searches with their status and result counts."""
        return await run("list_searches", searches.list)

    if fs.writable:

        @server.tool(name="write_file", annotations=_DESTRUCTIVE)
        async def write_file(
            path: str, content: str, mode: Literal["rewrite", "append"] = "rewrite"
        ) -> dict[str, Any]:
            """Create or overwrite a text file, or append to it. The parent directory
            must exist."""
            return await run("write_file", fs.write_file, path, content, mode, path=path)

        @server.tool(name="edit_block", annotations=_DESTRUCTIVE)
        async def edit_block(
            file_path: str, old_string: str, new_string: str, expected_replacements: int = 1
        ) -> dict[str, Any]:
            """Replace exact text in a file. Fails unless old_string occurs exactly
            expected_replacements times."""
            return await run(
                "edit_block",
                fs.edit_block,
                file_path,
                old_string,
                new_string,
                expected_replacements,
                path=file_path,
            )

        @server.tool(name="create_directory", annotations=_CREATE_DIRECTORY)
        async def create_directory(path: str) -> dict[str, Any]:
            """Create a directory, including any missing parent directories."""
            return await run("create_directory", fs.create_directory, path, path=path)

        @server.tool(name="move_file", annotations=_MOVE)
        async def move_file(source: str, destination: str) -> dict[str, Any]:
            """Move or rename a file or directory. Fails if destination exists."""
            return await run(
                "move_file", fs.move_file, source, destination, path=source, destination=destination
            )

        @server.tool(name="delete_file", annotations=_DESTRUCTIVE)
        async def delete_file(path: str, recursive: bool = False) -> dict[str, Any]:
            """Delete a file, symlink or directory by moving it to the trash. A
            non-empty directory needs recursive=true."""
            return await run("delete_file", fs.delete_file, path, recursive, path=path)

    server.add_middleware(
        UgaAllowlistMiddleware(
            audit,
            allowed_tools=allowed,
            route_name="filesystem",
            service_name="ContextBridge filesystem",
        )
    )

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

    try:
        token = _require_token(os.environ.get(TOKEN_ENV), name=TOKEN_ENV)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    if token == os.environ.get("MCP_AUTH_TOKEN"):
        raise SystemExit(f"{TOKEN_ENV} must differ from MCP_AUTH_TOKEN.")

    serve = cfg.get("serve") or {}
    host = serve.get("host", "127.0.0.1")
    port = serve.get("port")
    if not port:
        raise SystemExit(f"{args.config}: serve.port is required.")

    try:
        fs = filesystem_from_config(cfg.get("filesystem"), config_path=Path(args.config))
        audit = UgaAuditLog(os.environ.get(AUDIT_ENV) or serve.get("audit_log"), route="fs")
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
        f"[uga fs] serving {len(advertised)} tools over {len(fs.roots)} root(s) "
        f"({writable} writable) on {host}:{port}",
        file=sys.stderr,
        flush=True,
    )
    server.run(
        transport="http",
        host=host,
        port=port,
        show_banner=False,
        middleware=http_middleware(audit),
    )


if __name__ == "__main__":
    main()
