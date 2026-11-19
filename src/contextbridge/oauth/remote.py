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
from .dashboard import OwnerDashboard
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
    """The devices named in the caller's grant that the config still allows. No grant, no devices.

    With a scope, only the devices where the grant holds that scope. The claims are read from the
    grant on every request, so the owner narrowing a grant applies to tokens already issued.
    """

    def devices(scope: str | None = None) -> frozenset[str]:
        try:
            from fastmcp.server.dependencies import get_access_token

            token = get_access_token()
        except Exception:  # noqa: BLE001 -- no request context at all: no devices
            token = None
        claims = (token.claims or {}) if token is not None else {}
        granted = claims.get("devices")
        if not isinstance(granted, list):
            return frozenset()
        reachable = frozenset(d for d in granted if isinstance(d, str) and settings.device_allowed(d))
        if scope is None:
            return reachable
        per_device = claims.get("device_scopes")
        if not isinstance(per_device, dict):
            return frozenset()  # fail closed: a token without per-device scopes reaches no device for a scope
        return frozenset(d for d in reachable if scope in (per_device.get(d) or ()))

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
        # The owner's view of devices and grants, behind the same passphrase and authenticator check.
        dashboard = OwnerDashboard(
            public_url=settings.public_url,
            registry=registry,
            store=store,
            audit=audit,
            describe=router.describe,
            client_address=provider._client_address,
            page=_page,
            allow_scopes=settings.allow_scopes,
            device_allowed=settings.device_allowed,
            tool_scopes=TOOL_SCOPES,
        )
        provider.extra_routes.extend(dashboard.routes())
    server.auth = provider
    return server
