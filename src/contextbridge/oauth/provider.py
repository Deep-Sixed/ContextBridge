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
MAX_PENDING_PER_CLIENT = 3
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
    # The header a proxy on this host sets to the real client address (e.g. CF-Connecting-IP).
    # When set, consent failures lock out that address alone instead of every caller.
    client_ip_header: str | None = None

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
    # The client as registered, so an approval can reinstate it if the full table dropped it meanwhile.
    client: dict[str, Any] = field(default_factory=dict)


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
        # More pages served beside consent (device activation), added by create_remote_server.
        self.extra_routes: list[Route] = []

    # ------------------------------------------------------------ helpers

    def _log(self, event: str, **fields: Any) -> None:
        try:
            self.audit.record(event, **fields)
        except AuditError:
            pass  # the tool-call path is fail-closed; OAuth bookkeeping events are best effort

    def offered_devices(self) -> list[str]:
        return [d for d in self._offered_devices() if self.settings.device_allowed(d)]

    def _client_address(self, request: Request) -> str | None:
        """The caller's address as the configured proxy header reports it, or None to share one lockout."""
        if not self.settings.client_ip_header:
            return None
        value = request.headers.get(self.settings.client_ip_header)
        if not value:
            return None
        # In a forwarded list only the last entry was added by the proxy; earlier ones are whatever
        # the client sent, and trusting them would let it dodge the lockout by inventing addresses.
        try:
            return str(ipaddress.ip_address(value.split(",")[-1].strip()))
        except ValueError:
            return None

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
        self._make_room(client.client_id or "")
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
            client=client.model_dump(mode="json", exclude_none=True),
        )
        self._log("oauth_authorization_requested", client=client.client_id, scopes=params.scopes)
        return f"{self.settings.public_url.rstrip('/')}/consent?request={request_id}"

    def _make_room(self, client_id: str) -> None:
        """Keep the pending requests bounded without letting one client push out everyone else's.

        A client keeps only its newest few requests, and when the table is full the client holding
        the most gives up its oldest. Dicts keep insertion order, so the first match is the oldest.
        """
        def oldest_of(owner: str) -> str:
            return next(k for k, v in self._pending.items() if v.client_id == owner)

        while sum(1 for v in self._pending.values() if v.client_id == client_id) >= MAX_PENDING_PER_CLIENT:
            del self._pending[oldest_of(client_id)]
        while len(self._pending) >= MAX_PENDING:
            counts: dict[str, int] = {}
            for pending in self._pending.values():
                counts[pending.client_id] = counts.get(pending.client_id, 0) + 1
            del self._pending[oldest_of(max(counts, key=counts.__getitem__))]

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        routes.append(Route("/consent", self._consent, methods=["GET", "POST"]))
        routes.extend(self.extra_routes)
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

        address = self._client_address(request)
        failure = self.store.verify_owner(
            str(form.get("passphrase", "")), str(form.get("totp", "")), client=address
        )
        if failure is not None:
            self._log("oauth_consent_failed", client=pending.client_id, reason=failure, peer=address)
            if failure == "locked":
                minutes = max(1, round((self.store.locked_until(address) - time.time()) / 60))
                return _page(f"Too many failed attempts. Approval is locked for about {minutes} minutes.", status=429)
            return self._form(request_id, pending, error="Wrong passphrase or authenticator code.", status=401)

        scopes = [s for s in form.getlist("scope") if s in self._grantable(pending)]
        devices = [d for d in form.getlist("device") if d in self.offered_devices()]
        if not scopes or not devices:
            return self._form(request_id, pending, error="Choose at least one permission and one device.", status=400)

        # A re-authorization the owner asked for from the dashboard: keep its per-device choices
        # (within what was just approved) and replace the grant it was asked for.
        supersedes, device_scopes = None, None
        wanted = self._reauth(pending)
        if wanted is not None:
            supersedes, wanted_scopes = wanted
            device_scopes = {d: [s for s in scopes if s in wanted_scopes.get(d, scopes)] for d in devices}
        code = new_token()
        try:
            self._save_code(code, pending, scopes, devices, device_scopes=device_scopes, supersedes=supersedes)
        except OAuthStateError as exc:  # the client was dropped and every slot now holds an approved one
            return self._form(request_id, pending, error=f"Cannot approve: {exc}.", status=409)
        del self._pending[request_id]
        self._log("oauth_consent_granted", client=pending.client_id, scopes=scopes, devices=devices)
        return RedirectResponse(
            construct_redirect_uri(str(pending.params.redirect_uri), code=code, state=state), status_code=302
        )

    def _reauth(self, pending: _Pending) -> tuple[str, dict[str, list[str]]] | None:
        """(grant id, wanted scopes per device) when the owner asked this client to authorize again."""
        found = self.store.reauth_request(pending.client_id)
        if found is None:
            return None
        grant_id, grant = found
        return grant_id, self.store.device_scopes(grant) | dict(grant.get("reauth_wanted") or {})

    def _save_code(
        self, code: str, pending: _Pending, scopes: list[str], devices: list[str], *,
        device_scopes: dict[str, list[str]] | None = None, supersedes: str | None = None,
    ) -> None:
        self.store.save_code(
            code,
            {
                "client_id": pending.client_id,
                "scopes": scopes,
                "devices": devices,
                **({"device_scopes": device_scopes} if device_scopes is not None else {}),
                **({"supersedes": supersedes} if supersedes else {}),
                "code_challenge": pending.params.code_challenge,
                "redirect_uri": str(pending.params.redirect_uri),
                "redirect_uri_provided_explicitly": pending.params.redirect_uri_provided_explicitly,
                "resource": self.settings.resource_url,
                "expires_at": time.time() + CODE_SECONDS,
            },
            client=pending.client,
        )

    def _grantable(self, pending: _Pending) -> list[str]:
        """Scopes the owner may approve: allowed for remote use and registered by the client."""
        return [s for s in ALL_SCOPES if s in self.settings.allow_scopes and s in pending.client_scopes]

    def _form(self, request_id: str, pending: _Pending, *, error: str = "", status: int = 200) -> HTMLResponse:
        # Least privilege by default: only read starts checked; anything more is a deliberate tick.
        # The exception is a re-authorization the owner asked for from the dashboard: what they asked
        # for starts checked, and they still confirm it here with the passphrase and a code.
        wanted = self._reauth(pending)
        wanted_scopes = {s for v in wanted[1].values() for s in v} if wanted else {SCOPE_READ}
        wanted_devices = set(wanted[1]) if wanted else set()
        scope_rows = "".join(
            f'<label><input type="checkbox" name="scope" value="{html.escape(s)}"'
            f'{" checked" if s in wanted_scopes else ""}> <code>{html.escape(s)}</code> — '
            f"{html.escape(SCOPE_DESCRIPTIONS[s])}</label>"
            for s in self._grantable(pending)
        ) or "<p>None of the permissions this client registered for are allowed remotely.</p>"
        # No device starts checked, not even when only one is offered: each device is a deliberate tick,
        # so a grant never reaches a computer the owner did not choose for this client.
        device_rows = "".join(
            f'<label><input type="checkbox" name="device" value="{html.escape(d)}"'
            f'{" checked" if d in wanted_devices else ""}> {html.escape(d)}</label>'
            for d in self.offered_devices()
        ) or "<p>No devices are available to remote clients.</p>"
        reauth_note = (
            "<p>You asked for this from the dashboard. Approving replaces the client's current access; "
            "each device keeps the permissions you chose there.</p>" if wanted else ""
        )
        redirect_host = urlsplit(str(pending.params.redirect_uri)).netloc
        body = f"""
<h1>Allow access to your computers?</h1>
<p><strong>{html.escape(pending.client_name)}</strong> wants to use ContextBridge.
Approving sends an authorization code to <strong>{html.escape(redirect_host)}</strong>.
Only approve a request you started yourself.</p>
{reauth_note}
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
                device_scopes=record.get("device_scopes"),
                supersedes=record.get("supersedes"),
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
            scopes=self.store.access_scopes(grant, token),
            expires_at=int(expires_at),
            resource=grant.get("resource"),
            claims={"devices": grant["devices"], "device_scopes": self.store.device_scopes(grant), "grant": grant_id},
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
table{border-collapse:collapse;margin:1rem 0}th,td{text-align:left;padding:.2rem .8rem .2rem 0;vertical-align:top}
pre{background:#eee;padding:.6rem .8rem;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.head{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
a.button{background:#1a73e8;color:#fff;padding:.5rem 1rem;border-radius:8px;text-decoration:none;font-weight:600}
.list{list-style:none;padding:0;margin:1rem 0;border:1px solid #ddd;border-radius:10px;background:#fff}
.row{display:flex;align-items:center;gap:.8rem;padding:.8rem 1rem;border-top:1px solid #eee}.row:first-child{border-top:0}
.row .main{flex:1;min-width:0}.name{font-weight:600;font-family:ui-monospace,monospace}.seen{color:#555;font-size:.9rem}
.dot{width:.6rem;height:.6rem;border-radius:50%;flex:none}.dot.on{background:#1e8e3e}.dot.off{background:#999}
.pill{font-size:.8rem;padding:.15rem .5rem;border-radius:6px}.pill.on{background:#e6f4ea;color:#1e8e3e}.pill.off{background:#eee;color:#666}
.row form{margin:0}button.link{background:none;border:0;padding:0;margin:0;color:#1a73e8;cursor:pointer;font-size:.95rem}
button.danger,button.link.danger{color:#b00020}.notice{color:#1e8e3e;font-weight:600}
input[name=user_code]{display:block;width:100%;padding:.4rem;font-size:1.4rem;letter-spacing:.15em;text-transform:uppercase}
"""


def _page(
    body: str, *, status: int = 200, raw: bool = False, form_action: str = "", style: str = _STYLE,
    title: str = "ContextBridge authorization", html_attrs: str = "",
) -> HTMLResponse:
    """A hardened page: no scripts, no framing, not cached. ``body``, ``title`` and ``html_attrs`` are trusted HTML."""
    content = body if raw else f"<h1>ContextBridge</h1><p>{html.escape(body)}</p>"
    document = (
        f"<!doctype html><html lang=en{(' ' + html_attrs) if html_attrs else ''}><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width, initial-scale=1">'
        f"<title>{title}</title><style>{style}</style></head><body>{content}</body></html>"
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
