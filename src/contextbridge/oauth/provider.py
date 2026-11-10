"""OAuth 2.1 authorization server for remote MCP clients (ChatGPT, Claude, ...).

Built on FastMCP's :class:`OAuthProvider` and the MCP SDK's endpoints, which
implement discovery (RFC 8414 / RFC 9728), Dynamic Client Registration
(RFC 7591), PKCE S256, and resource indicators (RFC 8707). This module supplies
the decisions:

* **Registration** only for redirect URIs on configured hosts (claude.ai,
  claude.com, chatgpt.com by default); at most 50 clients, and ones never
  approved expire after a day or make room for new ones.
* **Consent**: every authorization stops at ``/consent``, where the owner must
  enter the passphrase *and* a TOTP code, and picks which scopes (capped by
  ``remote.allow_scopes``) and which devices (capped by ``remote.allow_devices``)
  the client receives. Only read access starts checked. Five failures lock
  consent for 15 minutes.
* **Tokens** are opaque, stored hashed, bound to this MCP resource. Access tokens
  are short-lived; refresh tokens rotate on use and presenting a rotated one
  revokes the whole grant.
"""

from __future__ import annotations

import html
import ipaddress
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from fastmcp.server.auth import AccessToken, OAuthProvider
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from ..computer.audit import AuditError, ComputerAuditLog
from ..computer.server import (
    ALL_SCOPES,
    SCOPE_EXECUTE,
    SCOPE_PROCESS,
    SCOPE_READ,
    SCOPE_DESKTOP_OBSERVE,
    SCOPE_MEDIA_DISCOVER,
    SCOPE_WRITE,
)
from .store import OAuthStateError, OAuthStore, new_token

CODE_SECONDS = 300
PENDING_SECONDS = 600
MAX_PENDING = 100
SCOPE_DESCRIPTIONS = {
    SCOPE_READ: "Read files and documents, search, see system info, processes, and devices",
    SCOPE_DESKTOP_OBSERVE: "Observe window titles and IDs on authorized desktops",
    SCOPE_MEDIA_DISCOVER: "Inspect media-device availability without recording",
    SCOPE_WRITE: "Create, edit, move, and delete files and documents in writable folders",
    SCOPE_EXECUTE: "Run commands and interactive sessions",
    SCOPE_PROCESS: "Terminate processes",
}


@dataclass(frozen=True)
class RemoteSettings:
    public_url: str
    allow_scopes: tuple[str, ...]
    allow_devices: tuple[str, ...]  # ("*",) means every enrolled device
    allowed_redirect_hosts: tuple[str, ...]
    access_seconds: int = 3600
    refresh_seconds: int = 30 * 86400

    @property
    def resource_url(self) -> str:
        return self.public_url.rstrip("/") + "/mcp"

    def device_allowed(self, device: str) -> bool:
        return "*" in self.allow_devices or device in self.allow_devices


@dataclass
class _Pending:
    client_id: str
    client_name: str
    client_scopes: tuple[str, ...]
    params: AuthorizationParams
    form_token: str
    expires_at: float
    redirect_origin: str = field(default="")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ContextBridgeOAuthProvider(OAuthProvider):
    def __init__(
        self,
        settings: RemoteSettings,
        store: OAuthStore,
        audit: ComputerAuditLog,
        *,
        offered_devices: Callable[[], list[str]],
    ) -> None:
        super().__init__(
            base_url=settings.public_url,
            # Clients may ask for any scope; the owner decides at consent, capped by remote.allow_scopes.
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=list(ALL_SCOPES), default_scopes=list(ALL_SCOPES)
            ),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.settings = settings
        self.store = store
        self.audit = audit
        self._offered_devices = offered_devices
        self._pending: dict[str, _Pending] = {}

    # ------------------------------------------------------------ helpers

    def _log(self, event: str, **fields: Any) -> None:
        try:
            self.audit.record(event, **fields)
        except AuditError:
            pass  # the tool-call path is fail-closed; OAuth bookkeeping events are best effort

    def offered_devices(self) -> list[str]:
        return [d for d in self._offered_devices() if self.settings.device_allowed(d)]

    def _check_redirect(self, uri: str) -> None:
        parts = urlsplit(uri)
        host = (parts.hostname or "").lower()
        if host not in self.settings.allowed_redirect_hosts:
            raise RegistrationError(
                "invalid_redirect_uri", f"redirect host {host!r} is not allowed by this server"
            )
        if parts.scheme != "https" and not (parts.scheme == "http" and _is_loopback(host)):
            raise RegistrationError("invalid_redirect_uri", "redirect URIs must use https")

    # --------------------------------------------------------- registration

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        record = self.store.get_client(client_id)
        if record is None:
            return None
        fields = {k: v for k, v in record.items() if k in OAuthClientInformationFull.model_fields}
        return OAuthClientInformationFull.model_validate(fields)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            self._check_redirect(str(uri))
        try:
            self.store.save_client(client_info.model_dump(mode="json", exclude_none=True))
        except OAuthStateError as exc:
            raise RegistrationError("invalid_client_metadata", str(exc)) from None
        self._log(
            "oauth_client_registered",
            client=client_info.client_id,
            client_name=client_info.client_name,
            redirect_uris=[str(u) for u in client_info.redirect_uris or []],
        )

    # --------------------------------------------------------- authorization

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource and params.resource.rstrip("/") not in (
            self.settings.resource_url,
            self.settings.public_url.rstrip("/"),
        ):
            raise AuthorizeError("invalid_request", "this server only issues tokens for its own MCP endpoint")
        now = time.time()
        self._pending = {k: v for k, v in self._pending.items() if v.expires_at > now}
        while len(self._pending) >= MAX_PENDING:
            self._pending.pop(next(iter(self._pending)))
        request_id = secrets.token_urlsafe(24)
        redirect = urlsplit(str(params.redirect_uri))
        self._pending[request_id] = _Pending(
            client_id=client.client_id or "",
            client_name=client.client_name or client.client_id or "unnamed client",
            client_scopes=tuple((client.scope or "").split()),
            params=params,
            form_token=secrets.token_urlsafe(24),
            expires_at=now + PENDING_SECONDS,
            redirect_origin=f"{redirect.scheme}://{redirect.netloc}",
        )
        self._log("oauth_authorization_requested", client=client.client_id, scopes=params.scopes)
        return f"{self.settings.public_url.rstrip('/')}/consent?request={request_id}"

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        routes.append(Route("/consent", self._consent, methods=["GET", "POST"]))
        return routes

    async def _consent(self, request: Request) -> Response:
        if request.method == "GET":
            pending = self._pending.get(request.query_params.get("request", ""))
            if pending is None or pending.expires_at <= time.time():
                return _page("This authorization request has expired. Start again from your AI client.", status=400)
            return self._form(request.query_params["request"], pending)

        form = await request.form()
        request_id = str(form.get("request", ""))
        pending = self._pending.get(request_id)
        if pending is None or pending.expires_at <= time.time():
            return _page("This authorization request has expired. Start again from your AI client.", status=400)
        if not secrets.compare_digest(str(form.get("form_token", "")), pending.form_token):
            return _page("Invalid form submission.", status=400)

        state = pending.params.state
        if form.get("action") == "deny":
            del self._pending[request_id]
            self._log("oauth_consent_denied", client=pending.client_id, reason="owner_denied")
            return RedirectResponse(
                construct_redirect_uri(str(pending.params.redirect_uri), error="access_denied", state=state),
                status_code=302,
            )

        failure = self.store.verify_owner(str(form.get("passphrase", "")), str(form.get("totp", "")))
        if failure is not None:
            self._log("oauth_consent_failed", client=pending.client_id, reason=failure)
            if failure == "locked":
                minutes = max(1, round((self.store.locked_until() - time.time()) / 60))
                return _page(f"Too many failed attempts. Approval is locked for about {minutes} minutes.", status=429)
            return self._form(request_id, pending, error="Wrong passphrase or authenticator code.", status=401)

        scopes = [s for s in form.getlist("scope") if s in self._grantable(pending)]
        devices = [d for d in form.getlist("device") if d in self.offered_devices()]
        if not scopes or not devices:
            return self._form(request_id, pending, error="Choose at least one permission and one device.", status=400)

        code = new_token()
        self.store.save_code(
            code,
            {
                "client_id": pending.client_id,
                "scopes": scopes,
                "devices": devices,
                "code_challenge": pending.params.code_challenge,
                "redirect_uri": str(pending.params.redirect_uri),
                "redirect_uri_provided_explicitly": pending.params.redirect_uri_provided_explicitly,
                "resource": self.settings.resource_url,
                "expires_at": time.time() + CODE_SECONDS,
            },
        )
        del self._pending[request_id]
        self._log("oauth_consent_granted", client=pending.client_id, scopes=scopes, devices=devices)
        return RedirectResponse(
            construct_redirect_uri(str(pending.params.redirect_uri), code=code, state=state), status_code=302
        )

    def _grantable(self, pending: _Pending) -> list[str]:
        """Scopes the owner may approve: allowed for remote use and registered by the client."""
        return [s for s in ALL_SCOPES if s in self.settings.allow_scopes and s in pending.client_scopes]

    def _form(self, request_id: str, pending: _Pending, *, error: str = "", status: int = 200) -> HTMLResponse:
        # Least privilege by default: only read starts checked; anything more is a deliberate tick.
        scope_rows = "".join(
            f'<label><input type="checkbox" name="scope" value="{html.escape(s)}"'
            f'{" checked" if s == SCOPE_READ else ""}> <code>{html.escape(s)}</code> — '
            f"{html.escape(SCOPE_DESCRIPTIONS[s])}</label>"
            for s in self._grantable(pending)
        ) or "<p>None of the permissions this client registered for are allowed remotely.</p>"
        offered = self.offered_devices()
        device_rows = "".join(
            f'<label><input type="checkbox" name="device" value="{html.escape(d)}"'
            f'{" checked" if len(offered) == 1 else ""}> {html.escape(d)}</label>'
            for d in offered
        ) or "<p>No devices are available to remote clients.</p>"
        redirect_host = urlsplit(str(pending.params.redirect_uri)).netloc
        body = f"""
<h1>Allow access to your computers?</h1>
<p><strong>{html.escape(pending.client_name)}</strong> wants to use ContextBridge.
Approving sends an authorization code to <strong>{html.escape(redirect_host)}</strong>.
Only approve a request you started yourself.</p>
{f'<p class="error">{html.escape(error)}</p>' if error else ""}
<form method="post" action="/consent">
<input type="hidden" name="request" value="{html.escape(request_id)}">
<input type="hidden" name="form_token" value="{html.escape(pending.form_token)}">
<fieldset><legend>Permissions</legend>{scope_rows}</fieldset>
<fieldset><legend>Devices</legend>{device_rows}</fieldset>
<fieldset><legend>Confirm it is you</legend>
<label>Passphrase <input type="password" name="passphrase" autocomplete="current-password" required></label>
<label>Authenticator code <input name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" required></label>
</fieldset>
<button name="action" value="approve">Approve</button>
<button name="action" value="deny" formnovalidate>Deny</button>
</form>
<p class="small">Client id: <code>{html.escape(pending.client_id)}</code></p>"""
        return _page(body, status=status, raw=True, form_action=pending.redirect_origin)

    # ---------------------------------------------------------------- tokens

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        record = self.store.get_code(authorization_code)
        if record is None or record["client_id"] != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=record["scopes"],
            expires_at=record["expires_at"],
            client_id=record["client_id"],
            code_challenge=record["code_challenge"],
            redirect_uri=AnyUrl(record["redirect_uri"]),
            redirect_uri_provided_explicitly=record["redirect_uri_provided_explicitly"],
            resource=record["resource"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        record = self.store.get_code(authorization_code.code)
        if record is None:
            raise TokenError("invalid_grant", "authorization code already used or expired")
        try:
            grant_id, access, refresh = self.store.create_grant(
                client_id=record["client_id"],
                scopes=record["scopes"],
                devices=record["devices"],
                resource=record["resource"],
                code=authorization_code.code,
                access_seconds=self.settings.access_seconds,
                refresh_seconds=self.settings.refresh_seconds,
            )
        except OAuthStateError as exc:
            raise TokenError("invalid_grant", str(exc)) from None
        self._log(
            "oauth_token_issued", client=client.client_id, grant=grant_id, scopes=record["scopes"],
            devices=record["devices"],
        )
        return OAuthToken(
            access_token=access,
            expires_in=self.settings.access_seconds,
            scope=" ".join(record["scopes"]),
            refresh_token=refresh,
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        found = self.store.find_refresh(refresh_token)
        if found is None:
            return None
        grant_id, grant, reused = found
        if reused:
            # A rotated token came back: assume it leaked and cut off the whole grant.
            self.store.revoke_grant(grant_id)
            self._log("oauth_refresh_reuse_detected", client=grant["client_id"], grant=grant_id)
            return None
        if grant["client_id"] != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=grant["client_id"],
            scopes=grant["scopes"],
            expires_at=int(grant["refresh_expires_at"]),
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        found = self.store.find_refresh(refresh_token.token)
        if found is None or found[2]:
            raise TokenError("invalid_grant", "refresh token is no longer valid")
        grant_id, grant, _ = found
        granted = [s for s in grant["scopes"] if not scopes or s in scopes]
        try:
            access, refresh = self.store.rotate(
                grant_id,
                refresh_token.token,
                scopes=granted,
                access_seconds=self.settings.access_seconds,
                refresh_seconds=self.settings.refresh_seconds,
            )
        except OAuthStateError as exc:
            raise TokenError("invalid_grant", str(exc)) from None
        self._log("oauth_token_refreshed", client=client.client_id, grant=grant_id)
        return OAuthToken(
            access_token=access, expires_in=self.settings.access_seconds, scope=" ".join(granted), refresh_token=refresh
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        try:
            found = self.store.find_access(token)
        except OAuthStateError:
            return None
        if found is None:
            return None
        grant_id, grant, expires_at = found
        if grant.get("resource") not in (None, self.settings.resource_url):
            return None
        return AccessToken(
            token=token,
            client_id=grant["client_id"],
            scopes=grant["scopes"],
            expires_at=int(expires_at),
            resource=grant.get("resource"),
            claims={"devices": grant["devices"], "grant": grant_id},
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        found = self.store.find_access(token.token) or self.store.find_refresh(token.token)
        if found is not None:
            self.store.revoke_grant(found[0])
            self._log("oauth_grant_revoked", client=found[1]["client_id"], grant=found[0], by="client")


# ------------------------------------------------------------------ HTML


_STYLE = """
body{font:16px/1.5 system-ui,sans-serif;max-width:38rem;margin:2rem auto;padding:0 1rem;color:#1b1b1f;background:#fafafa}
fieldset{border:1px solid #ccc;border-radius:8px;margin:1rem 0;padding:.5rem 1rem}
label{display:block;margin:.4rem 0}
input[type=password],input[name=totp]{display:block;width:100%;padding:.4rem;font-size:1rem}
button{font-size:1rem;padding:.5rem 1.2rem;margin-right:.5rem}
.error{color:#b00020;font-weight:600}.small{color:#666;font-size:.85rem}
"""


def _page(body: str, *, status: int = 200, raw: bool = False, form_action: str = "") -> HTMLResponse:
    content = body if raw else f"<h1>ContextBridge</h1><p>{html.escape(body)}</p>"
    document = (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width, initial-scale=1">'
        f"<title>ContextBridge authorization</title><style>{_STYLE}</style></head><body>{content}</body></html>"
    )
    # The form posts to this page, which redirects to the client; browsers apply form-action to that redirect.
    form_sources = " ".join(filter(None, ["'self'", form_action]))
    # same-origin, not no-referrer: under no-referrer a browser sends "Origin: null" with the form's POST
    # back to this page, and HostOriginGuard rejects that (403). Cross-origin requests, including the
    # redirect to the client, still carry no Referer, so the consent URL and its request id stay private.
    headers = {
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; "
            f"form-action {form_sources}"
        ),
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "same-origin",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    return HTMLResponse(document, status_code=status, headers=headers)
