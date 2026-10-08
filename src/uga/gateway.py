"""Unidirectional Gateway Appliance MCP route.

Exposes exactly two ChatGPT-compatible tools — ``search`` and ``fetch`` — backed by
the read-only Datacore JSONL adapter. Default-deny policy rejects every other tool.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from collections.abc import Sequence
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

from . import __version__
from .adapter import DatacoreRecordNotFound, DatacoreStore, repo_root
from .audit import UgaAuditLog
from .policy import UGA_ALLOWED_TOOLS, is_tool_allowed

_store: DatacoreStore | None = None
_audit: UgaAuditLog | None = None
DEFAULT_METADATA_TIMEOUT_SECONDS = 5.0
DEFAULT_TOOL_TIMEOUT_SECONDS = 10.0
DEFAULT_SEARCH_LIMIT = 10


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _metadata_timeout_seconds() -> float:
    return _env_float("UGA_MCP_METADATA_TIMEOUT_SECONDS", DEFAULT_METADATA_TIMEOUT_SECONDS)


def _tool_timeout_seconds() -> float:
    return _env_float("UGA_MCP_TOOL_TIMEOUT_SECONDS", DEFAULT_TOOL_TIMEOUT_SECONDS)


def _search_limit() -> int:
    return _env_int("UGA_MCP_SEARCH_LIMIT", DEFAULT_SEARCH_LIMIT)


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1000))


_CLIENT_LABEL_MAX_LEN = 64


class RecordNotFoundError(ToolError):
    """Raised by ``fetch`` for an unknown id; audited as ``not_found``."""


def _request_context(context: MiddlewareContext[Any]) -> Any:
    fastmcp_context = context.fastmcp_context
    if fastmcp_context is None:
        return None
    try:
        return fastmcp_context.request_context
    except Exception:
        return None


def _request_id(context: MiddlewareContext[Any]) -> str:
    """Return the JSON-RPC request id so audit lines match the client's request."""
    request_context = _request_context(context)
    message_id = getattr(request_context, "request_id", None)
    if message_id is None:
        message_id = getattr(context.message, "id", None)
    if message_id is not None:
        return f"mcp-{message_id}"
    return uuid.uuid4().hex[:12]


def _client_label(context: MiddlewareContext[Any]) -> str | None:
    """Return the client's self-reported ``clientInfo`` as ``name/version``.

    The value is client-supplied and unauthenticated; it labels audit lines only.
    """
    params = getattr(context.message, "params", None)
    info = getattr(params, "clientInfo", None)
    if info is None:
        session = getattr(_request_context(context), "session", None)
        info = getattr(getattr(session, "client_params", None), "clientInfo", None)
    name = str(getattr(info, "name", None) or "").strip()
    if not name:
        return None
    version = str(getattr(info, "version", None) or "").strip()
    label = f"{name}/{version}" if version else name
    return label[:_CLIENT_LABEL_MAX_LEN]


def _call_fields(name: str, arguments: Any) -> dict[str, str]:
    """Pick the audited argument for an allowed tool; other arguments are never logged."""
    if not isinstance(arguments, dict):
        return {}
    if name == "search" and isinstance(arguments.get("query"), str):
        return {"query": arguments["query"]}
    if name == "fetch" and isinstance(arguments.get("id"), str):
        return {"record_id": arguments["id"]}
    return {}


def _result_count(result: Any) -> int | None:
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict) and isinstance(structured.get("results"), list):
        return len(structured["results"])
    return None


def _failure_detail(exc: BaseException) -> str:
    if isinstance(exc, RecordNotFoundError):
        return "not_found"
    # FastMCP wraps unexpected tool exceptions in ToolError; audit the original type.
    if isinstance(exc, ToolError) and exc.__cause__ is not None:
        return type(exc.__cause__).__name__
    return type(exc).__name__


def _get_store() -> DatacoreStore:
    global _store
    if _store is None:
        path = os.environ.get("UGA_DATACORE_JSONL")
        _store = DatacoreStore.from_jsonl(path) if path else DatacoreStore.from_jsonl()
    return _store


def _get_audit() -> UgaAuditLog:
    global _audit
    if _audit is None:
        _audit = UgaAuditLog(
            os.environ.get("UGA_AUDIT_LOG"),
            route="uga",
            include_query_preview=os.environ.get("UGA_AUDIT_QUERY_PREVIEW") == "1",
        )
    return _audit


class UgaAllowlistMiddleware(Middleware):
    """Hide non-allowed tools, reject forbidden calls, and audit each request once."""

    def __init__(self, audit: UgaAuditLog) -> None:
        self._audit = audit

    async def on_initialize(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        started = time.monotonic()
        request_id = _request_id(context)
        client = _client_label(context)
        try:
            with anyio.fail_after(_metadata_timeout_seconds()):
                result = await call_next(context)
        except TimeoutError:
            elapsed = _elapsed_ms(started)
            self._audit.record(
                tool="initialize",
                success=False,
                detail="timeout",
                client_label=client,
                request_id=request_id,
                elapsed_ms=elapsed,
            )
            raise RuntimeError("Nexus Datacore MCP initialize timed out") from None
        except Exception as exc:
            elapsed = _elapsed_ms(started)
            self._audit.record(
                tool="initialize",
                success=False,
                detail=type(exc).__name__,
                client_label=client,
                request_id=request_id,
                elapsed_ms=elapsed,
            )
            raise
        elapsed = _elapsed_ms(started)
        self._audit.record(
            tool="initialize",
            success=True,
            client_label=client,
            request_id=request_id,
            elapsed_ms=elapsed,
        )
        return result

    async def on_list_tools(self, context: MiddlewareContext[Any], call_next: Any) -> Sequence[Tool]:
        started = time.monotonic()
        request_id = _request_id(context)
        client = _client_label(context)
        try:
            with anyio.fail_after(_metadata_timeout_seconds()):
                tools = await call_next(context)
        except TimeoutError:
            elapsed = _elapsed_ms(started)
            self._audit.record(
                tool="tools/list",
                success=False,
                detail="timeout",
                client_label=client,
                request_id=request_id,
                elapsed_ms=elapsed,
            )
            raise RuntimeError("Nexus Datacore MCP tools/list timed out") from None
        except Exception as exc:
            elapsed = _elapsed_ms(started)
            self._audit.record(
                tool="tools/list",
                success=False,
                detail=type(exc).__name__,
                client_label=client,
                request_id=request_id,
                elapsed_ms=elapsed,
            )
            raise
        filtered = [t for t in tools if is_tool_allowed(t.name)]
        elapsed = _elapsed_ms(started)
        self._audit.record(
            tool="tools/list",
            success=True,
            result_count=len(filtered),
            client_label=client,
            request_id=request_id,
            elapsed_ms=elapsed,
        )
        return filtered

    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        started = time.monotonic()
        request_id = _request_id(context)
        client = _client_label(context)
        raw_name = getattr(context.message, "name", None)
        name = str(raw_name) if raw_name else "<unknown>"
        if not is_tool_allowed(name):
            self._audit.record(
                tool=name,
                success=False,
                detail="policy_denied",
                client_label=client,
                request_id=request_id,
                elapsed_ms=_elapsed_ms(started),
            )
            raise ToolError(f"Tool '{name}' is not permitted on the UGA route.")
        fields = _call_fields(name, getattr(context.message, "arguments", None))
        try:
            with anyio.fail_after(_tool_timeout_seconds()):
                result = await call_next(context)
        except TimeoutError:
            elapsed = _elapsed_ms(started)
            self._audit.record(
                tool=name,
                success=False,
                detail="timeout",
                client_label=client,
                request_id=request_id,
                elapsed_ms=elapsed,
                **fields,
            )
            raise ToolError(f"Tool '{name}' timed out on the Nexus Datacore route.") from None
        except Exception as exc:
            elapsed = _elapsed_ms(started)
            self._audit.record(
                tool=name,
                success=False,
                detail=_failure_detail(exc),
                client_label=client,
                request_id=request_id,
                elapsed_ms=elapsed,
                **fields,
            )
            raise
        elapsed = _elapsed_ms(started)
        self._audit.record(
            tool=name,
            success=True,
            result_count=_result_count(result),
            client_label=client,
            request_id=request_id,
            elapsed_ms=elapsed,
            **fields,
        )
        return result


# search and fetch only read a fixed local snapshot: no side effects, same input
# gives the same output, and nothing outside the approved JSONL is reached.
_READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


def create_uga_server(*, name: str = "Nexus UGA") -> FastMCP:
    server = FastMCP(name=name, version=__version__)

    # Tool calls are audited once, in UgaAllowlistMiddleware.on_call_tool.
    @server.tool(name="search", annotations=_READ_ONLY, timeout=_tool_timeout_seconds())
    def search(query: str) -> dict[str, Any]:
        """Search approved Datacore records by keyword."""
        return {"results": _get_store().search_records(query, limit=_search_limit())}

    @server.tool(name="fetch", annotations=_READ_ONLY, timeout=_tool_timeout_seconds())
    def fetch(id: str) -> dict[str, Any]:
        """Fetch a single approved Datacore record by id."""
        try:
            return _get_store().fetch_record(id)
        except DatacoreRecordNotFound:
            raise RecordNotFoundError(f"Record not found: {id}") from None

    server.add_middleware(UgaAllowlistMiddleware(_get_audit()))

    @server.custom_route("/", methods=["GET"])
    async def root_status(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "service": "Nexus UGA",
                "mcp_path": "/mcp",
                "tools": sorted(UGA_ALLOWED_TOOLS),
            }
        )

    return server


def advertised_tool_names(server: FastMCP) -> set[str]:
    import anyio

    async def _names() -> set[str]:
        tools = await server.list_tools(run_middleware=False)
        return {t.name for t in tools}

    return anyio.run(_names)


def main() -> None:
    ap = argparse.ArgumentParser(description="Nexus Unidirectional Gateway Appliance")
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    token = os.environ.get("MCP_AUTH_TOKEN")
    if not token:
        raise SystemExit("MCP_AUTH_TOKEN must be set for the UGA gateway (fail closed).")

    serve = cfg.get("serve") or {}
    host = serve.get("host", "127.0.0.1")
    port = serve.get("port")
    if not port:
        raise SystemExit(f"{args.config}: serve.port is required.")

    audit_path = serve.get("audit_log")
    if audit_path:
        os.environ.setdefault("UGA_AUDIT_LOG", audit_path)

    jsonl_path = cfg.get("datacore_jsonl")
    if jsonl_path:
        resolved = Path(jsonl_path)
        if not resolved.is_absolute():
            resolved = repo_root() / resolved
        os.environ.setdefault("UGA_DATACORE_JSONL", str(resolved))

    server = create_uga_server(name=cfg.get("name", "Nexus UGA"))
    advertised = advertised_tool_names(server)
    if advertised != UGA_ALLOWED_TOOLS:
        raise SystemExit(
            f"UGA tool surface mismatch: expected {set(UGA_ALLOWED_TOOLS)!r}, got {advertised!r}"
        )

    server.auth = StaticTokenVerifier({token: {"client_id": "nexus-uga"}})
    print(f"[uga] serving search/fetch on {host}:{port}", file=sys.stderr, flush=True)
    server.run(transport="http", host=host, port=port, show_banner=False)


if __name__ == "__main__":
    main()
