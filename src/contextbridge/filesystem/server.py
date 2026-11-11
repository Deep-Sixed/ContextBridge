"""MCP server plumbing for the filesystem route.

Bearer-token auth, a default-deny allowlist for tools and every other MCP method,
per-call timeouts, and one audit line per request. The route's tools live in
:mod:`contextbridge.filesystem.gateway`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
import weakref
from collections.abc import Awaitable, Callable, Sequence
from contextvars import ContextVar
from pathlib import Path
from typing import Any

import anyio
import mcp.types
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp.server.lowlevel.server import request_ctx
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData
from starlette.applications import Starlette
from starlette.middleware import Middleware as AsgiMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .audit import GatewayAuditLog, clip

DEFAULT_METADATA_TIMEOUT_SECONDS = 5.0
DEFAULT_TOOL_TIMEOUT_SECONDS = 10.0
MIN_TOKEN_LENGTH = 32

# Requests fastmcp routes through middleware. Of these, AllowlistMiddleware runs
# initialize, tools/list and allowlisted tools/call, answers the resource and prompt
# listings with nothing, and rejects the rest.
_MIDDLEWARE_ROUTED_REQUESTS = (
    mcp.types.CallToolRequest,
    mcp.types.ListToolsRequest,
    mcp.types.ListResourcesRequest,
    mcp.types.ListResourceTemplatesRequest,
    mcp.types.ReadResourceRequest,
    mcp.types.ListPromptsRequest,
    mcp.types.GetPromptRequest,
)
_EMPTY_LIST_METHODS = frozenset({"resources/list", "resources/templates/list", "prompts/list"})

# The request's audit fields. The middleware sets it, the tools add what they know
# (path, query, result_count), and the middleware writes it as one line.
_audit_fields: ContextVar[dict[str, Any] | None] = ContextVar("contextbridge_audit_fields", default=None)
# True while the MCP SDK refreshes its tool cache during a tools/call. That
# tools/list comes from the SDK, not the client, so it is not audited.
_tool_cache_refresh: ContextVar[bool] = ContextVar("contextbridge_tool_cache_refresh", default=False)
# A random key per MCP session; JSON-RPC ids are only unique within a session.
_session_keys: weakref.WeakKeyDictionary[Any, str] = weakref.WeakKeyDictionary()


# Settings were once named UGA_*; a deployment that still sets those keeps working.
_LEGACY_PREFIX = "UGA_"


def _env(name: str) -> str | None:
    """The value of a ``CONTEXTBRIDGE_*`` setting, falling back to its legacy name."""
    value = os.environ.get(name)
    if not value and name.startswith("CONTEXTBRIDGE_"):
        value = os.environ.get(_LEGACY_PREFIX + name.removeprefix("CONTEXTBRIDGE_"))
    return value


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _metadata_timeout_seconds() -> float:
    return _env_float("CONTEXTBRIDGE_MCP_METADATA_TIMEOUT_SECONDS", DEFAULT_METADATA_TIMEOUT_SECONDS)


def _tool_timeout_seconds() -> float:
    return _env_float("CONTEXTBRIDGE_MCP_TOOL_TIMEOUT_SECONDS", DEFAULT_TOOL_TIMEOUT_SECONDS)


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1000))


def _request_id() -> str:
    """Return ``<session key>:<JSON-RPC id>``, or a fresh UUID outside a request.

    ``initialize`` is handled before the SDK sets a request context, so it gets a UUID.
    """
    try:
        ctx = request_ctx.get()
    except LookupError:
        return uuid.uuid4().hex
    key = _session_keys.get(ctx.session)
    if key is None:
        key = _session_keys[ctx.session] = uuid.uuid4().hex
    return f"{key}:{ctx.request_id}"


def _who(params: Any = None) -> dict[str, str | None]:
    """The client's self-declared clientInfo name and its peer address."""
    # initialize carries clientInfo in its params; later requests read it off the session.
    info = getattr(params, "clientInfo", None)
    if info is None:
        try:
            info = request_ctx.get().session.client_params.clientInfo
        except (LookupError, AttributeError):
            info = None
    return {"client_label": getattr(info, "name", None), "peer": _peer()}


def _add_audit_fields(**fields: Any) -> None:
    current = _audit_fields.get()
    if current is not None:
        current.update(fields)


def _peer() -> str | None:
    try:
        request = get_http_request()
    except RuntimeError:
        return None
    return request.client.host if request.client else None


def _require_token(token: str | None, *, name: str) -> str:
    if not token:
        raise ValueError(f"{name} must be set (fail closed).")
    if len(token) < MIN_TOKEN_LENGTH:
        raise ValueError(f"{name} must be at least {MIN_TOKEN_LENGTH} characters.")
    return token


class _BearerTokenVerifier(TokenVerifier):
    """Accept exactly one static bearer token, compared in constant time.

    Only a SHA-256 digest of the token is kept in memory.
    """

    def __init__(self, token: str) -> None:
        super().__init__()
        self._digest = hashlib.sha256(token.encode("utf-8")).digest()

    async def verify_token(self, token: str) -> AccessToken | None:
        presented = hashlib.sha256(token.encode("utf-8")).digest()
        if not hmac.compare_digest(presented, self._digest):
            return None
        return AccessToken(token=token, client_id="contextbridge-files", scopes=[])


class AuthFailureAuditMiddleware:
    """Audit HTTP requests rejected by auth; these never reach the MCP middleware."""

    def __init__(self, app: ASGIApp, audit: GatewayAuditLog) -> None:
        self.app = app
        self._audit = audit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def audited_send(message: Message) -> None:
            if message["type"] == "http.response.start" and message["status"] in (401, 403):
                if message["status"] == 403:
                    detail = "forbidden"
                elif any(name == b"authorization" for name, _ in scope.get("headers", [])):
                    detail = "invalid_token"
                else:
                    detail = "missing_token"
                client = scope.get("client")
                self._audit.record(
                    tool="auth",
                    success=False,
                    detail=detail,
                    peer=client[0] if client else None,
                )
            await send(message)

        await self.app(scope, receive, audited_send)


class _AuditedServer(FastMCP):
    """FastMCP whose HTTP app always audits requests rejected by auth.

    ``run()`` builds its app through ``http_app`` too, so every way of serving the
    gateway over HTTP gets the audit middleware.
    """

    audit_log: GatewayAuditLog

    def http_app(  # type: ignore[override]
        self,
        path: str | None = None,
        middleware: list[AsgiMiddleware] | None = None,
        **kwargs: Any,
    ) -> Starlette:
        audit_middleware = AsgiMiddleware(AuthFailureAuditMiddleware, audit=self.audit_log)
        return super().http_app(path, [audit_middleware, *(middleware or [])], **kwargs)


def unauthenticated_response(request: Request) -> JSONResponse | None:
    """Return a 401 for a custom-route request the bearer middleware did not authenticate.

    Custom routes are not wrapped by the MCP endpoint's auth check. The bearer
    middleware still runs for every request, so refuse anyone it did not
    authenticate.
    """
    user = request.scope.get("user")
    if user is not None and user.is_authenticated:
        return None
    return JSONResponse(
        {"error": "invalid_token", "error_description": "Authentication required"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def _not_permitted(method: str, route_name: str = "filesystem") -> McpError:
    return McpError(
        ErrorData(
            code=mcp.types.METHOD_NOT_FOUND,
            message=f"Method '{clip(method)}' is not permitted on the {route_name} route.",
        )
    )


class AllowlistMiddleware(Middleware):
    """Default-deny policy and one audit line for every request fastmcp routes here.

    initialize, tools/list (filtered to the allowlist) and allowlisted tools/call
    run. resources/list, resources/templates/list and prompts/list answer empty;
    everything else is rejected.
    """

    def __init__(
        self,
        audit: GatewayAuditLog,
        *,
        allowed_tools: frozenset[str],
        route_name: str = "filesystem",
        service_name: str = "ContextBridge filesystem",
    ) -> None:
        self._audit = audit
        self._allowed_tools = allowed_tools
        self._route_name = route_name
        self._service_name = service_name

    def _filter(self, tools: Sequence[Any]) -> list[Any]:
        return [t for t in tools if t.name in self._allowed_tools]

    async def on_request(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        method = context.method or "<unknown>"
        if method == "tools/list" and _tool_cache_refresh.get():
            return self._filter(await call_next(context))

        started = time.monotonic()
        fields: dict[str, Any] = {
            "request_id": _request_id(),
            **_who(getattr(context.message, "params", None)),
        }
        label = method
        if method == "tools/call":
            raw_name = getattr(context.message, "name", None)
            label = str(raw_name) if raw_name else "<unknown>"
            if label not in self._allowed_tools:
                self._record(label, started, fields, success=False, detail="policy_denied")
                raise ToolError(
                    f"Tool '{clip(label)}' is not permitted on the {self._route_name} route."
                )
            timeout = _tool_timeout_seconds()
        elif method in ("initialize", "tools/list"):
            timeout = _metadata_timeout_seconds()
        elif method in _EMPTY_LIST_METHODS:
            self._record(label, started, fields, success=True, result_count=0)
            return []
        else:
            self._record(label, started, fields, success=False, detail="policy_denied")
            raise _not_permitted(method, self._route_name)

        fields_token = _audit_fields.set(fields)
        try:
            with anyio.fail_after(timeout):
                result = await call_next(context)
        except TimeoutError:
            self._record(label, started, fields, success=False, detail="timeout")
            if method == "tools/call":
                raise ToolError(
                    f"Tool '{label}' timed out on the {self._service_name} route."
                ) from None
            raise RuntimeError(f"{self._service_name} MCP {method} timed out") from None
        except Exception as exc:
            # fastmcp wraps a tool's own exception in a masked ToolError; log the original type.
            cause = exc.__cause__ if isinstance(exc, ToolError) and exc.__cause__ else exc
            detail = fields.get("detail") or type(cause).__name__
            self._record(label, started, fields, success=False, detail=detail)
            raise
        finally:
            _audit_fields.reset(fields_token)
        if method == "tools/list":
            result = self._filter(result)
            fields["result_count"] = len(result)
        self._record(label, started, fields, success=True)
        return result

    def _record(self, label: str, started: float, fields: dict[str, Any], **outcome: Any) -> None:
        self._audit.record(tool=label, elapsed_ms=_elapsed_ms(started), **{**fields, **outcome})


LowLevelHandler = Callable[[Any], Awaitable[Any]]


def _guard_low_level_handlers(
    server: FastMCP, audit: GatewayAuditLog, route_name: str = "filesystem"
) -> None:
    """Apply the policy to the MCP requests fastmcp's middleware never sees.

    The SDK answers ping itself and rejects methods that have no handler. Any other
    handler fastmcp registers outside the middleware (logging/setLevel on newer
    releases) is replaced with an audited denial. The SDK also calls the tools/list
    handler with ``None`` to refresh its tool cache during a tools/call; that call
    is flagged so the middleware does not audit it as a client tools/list.
    """
    handlers: dict[type, LowLevelHandler] = server._mcp_server.request_handlers
    for request_type, handler in list(handlers.items()):
        if request_type is mcp.types.ListToolsRequest:
            handlers[request_type] = _flag_tool_cache_refresh(handler)
        elif request_type is mcp.types.PingRequest or request_type in _MIDDLEWARE_ROUTED_REQUESTS:
            continue
        else:
            handlers[request_type] = _audited_denial(audit, route_name)


def _flag_tool_cache_refresh(handler: LowLevelHandler) -> LowLevelHandler:
    async def list_tools(request: Any) -> Any:
        if request is not None:
            return await handler(request)
        token = _tool_cache_refresh.set(True)
        try:
            return await handler(request)
        finally:
            _tool_cache_refresh.reset(token)

    return list_tools


def _audited_denial(audit: GatewayAuditLog, route_name: str) -> LowLevelHandler:
    async def deny(request: Any) -> Any:
        audit.record(
            tool=request.method,
            success=False,
            detail="policy_denied",
            request_id=_request_id(),
            **_who(),
        )
        raise _not_permitted(request.method, route_name)

    return deny


def advertised_tool_names(server: FastMCP) -> set[str]:
    async def _names() -> set[str]:
        tools = await server.list_tools(run_middleware=False)
        return {t.name for t in tools}

    return anyio.run(_names)


def uvicorn_config(serve: dict[str, Any]) -> dict[str, Any]:
    """uvicorn settings for a route's ``serve`` config block.

    uvicorn trusts X-Forwarded-For from 127.0.0.1 by default, which would let any
    local client choose the peer address the audit log records. Only proxies
    listed in serve.forwarded_allow_ips are trusted.
    """
    forwarded_allow_ips = serve.get("forwarded_allow_ips")
    config: dict[str, Any] = {"proxy_headers": bool(forwarded_allow_ips)}
    if forwarded_allow_ips:
        config["forwarded_allow_ips"] = forwarded_allow_ips
    return config


def _config_relative(value: str, config_path: Path) -> Path:
    """A path from the config file; relative paths are resolved against its directory."""
    path = Path(value).expanduser()
    return path if path.is_absolute() else config_path.resolve().parent / path
