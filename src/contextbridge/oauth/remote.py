"""The remote MCP listener: the computer tools behind OAuth, limited per client.

Shares the gateway's :class:`~contextbridge.computer.server.DeviceRouter`, so a
remote client reaches the same devices, under the same device policies, as the
local endpoint -- but only the scopes and devices its grant names, re-checked
against ``remote.allow_scopes`` / ``remote.allow_devices`` on every call.
"""

from __future__ import annotations

from fastmcp import FastMCP

from ..computer.audit import ComputerAuditLog
from ..computer.server import (
    TOOL_SCOPES,
    AuthorizationError,
    Authorizer,
    DeviceGrant,
    DeviceRouter,
    create_computer_server,
    token_authorizer,
)
from ..remote.registry import DeviceRegistry
from .activation import ActivationBroker
from .provider import SCOPE_DESCRIPTIONS, ContextBridgeOAuthProvider, RemoteSettings, _page
from .store import OAuthStore


def remote_authorizer(settings: RemoteSettings) -> Authorizer:
    """Token scope check, capped by the scopes the config allows remote clients today."""

    def authorize(tool: str, scope: str | None = None) -> str:
        client = token_authorizer(tool, scope)
        scope = scope or TOOL_SCOPES[tool]
        if scope not in settings.allow_scopes:
            raise AuthorizationError(f"Remote clients may not use '{scope}' (remote.allow_scopes).")
        return client

    return authorize


def remote_devices(settings: RemoteSettings) -> DeviceGrant:
    """The devices named in the caller's grant that the config still allows. No grant, no devices."""

    def devices() -> frozenset[str]:
        try:
            from fastmcp.server.dependencies import get_access_token

            token = get_access_token()
        except Exception:  # noqa: BLE001 -- no request context at all: no devices
            token = None
        granted = (token.claims or {}).get("devices") if token is not None else None
        if not isinstance(granted, list):
            return frozenset()
        return frozenset(d for d in granted if isinstance(d, str) and settings.device_allowed(d))

    return devices


def create_remote_server(
    router: DeviceRouter,
    *,
    audit: ComputerAuditLog,
    settings: RemoteSettings,
    store: OAuthStore,
    name: str = "ContextBridge Computer",
    registry: DeviceRegistry | None = None,
    agents_url: str | None = None,
) -> FastMCP:
    server = create_computer_server(
        None,
        audit=audit,
        router=router,
        authorize=remote_authorizer(settings),
        devices=remote_devices(settings),
        listener="remote",
        name=name,
    )
    provider = ContextBridgeOAuthProvider(
        settings,
        store,
        audit,
        offered_devices=lambda: [row["device"] for row in router.describe()],
    )
    if registry is not None:
        # With an agent listener, new devices can be added from the browser at /activate.
        broker = ActivationBroker(
            public_url=settings.public_url,
            registry=registry,
            store=store,
            audit=audit,
            agents_url=agents_url,
            client_address=provider._client_address,
            page=_page,
            scope_descriptions=SCOPE_DESCRIPTIONS,
        )
        provider.extra_routes.extend(broker.routes())
    server.auth = provider
    return server
