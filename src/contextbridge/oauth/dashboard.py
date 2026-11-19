"""Owner dashboard at /devices: the fleet, the assistants that can reach it, and how to add more.

After signing in with the passphrase and an authenticator code (the same check, and the same
lockout, as the consent and activation pages) the owner sees:

* **Devices**: each enrolled device by name, then when it was last seen, with its status, and a
  Remove button (revokes the device; its connection is dropped within about a second).
* **Add a device**: the one-command installers and the activation page.
* **Assistants**: every active grant (which client, which devices, which permissions, since when)
  with a Revoke button.
* **Where you use it**: the MCP endpoint and how to add it to each assistant.

The session is a random id in a cookie (HttpOnly, SameSite=Strict, Secure on https, ``__Host-``
prefixed) that lasts 15 minutes from sign-in and is kept only in memory, so a gateway restart signs
everyone out. Every change is a POST carrying the session's CSRF token, and Remove and Revoke ask
for confirmation first. Sessions are bounded; signing in again replaces the oldest.
"""

from __future__ import annotations

import html
import ipaddress
import secrets
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..computer.audit import AuditError, ComputerAuditLog
from ..remote.registry import DeviceRegistry, RegistryError
from .store import OAuthStateError, OAuthStore

SESSION_SECONDS = 15 * 60
MAX_SESSIONS = 10
# A device seen this recently but not connected here was most likely heard by another gateway process.
RECENT_SECONDS = 3 * 60


def _is_loopback_url(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def ago(when: datetime | None, now: datetime | None = None) -> str:
    """'just now', '5 minutes ago', '10 hours ago', '7 days ago'."""
    if when is None:
        return "not since the gateway started"
    now = now or datetime.now(timezone.utc)
    seconds = max(0, int((now - when).total_seconds()))
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= size:
            count = seconds // size
            return f"{count} {unit}{'s' if count != 1 else ''} ago"
    return "just now"


def _parse(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class OwnerDashboard:
    def __init__(
        self,
        *,
        public_url: str,
        registry: DeviceRegistry,
        store: OAuthStore,
        audit: ComputerAuditLog,
        describe: Callable[[], list[dict[str, Any]]],
        client_address: Callable[[Request], str | None],
        page: Callable[..., Response],
    ) -> None:
        self.public_url = public_url.rstrip("/")
        self.registry = registry
        self.store = store
        self.audit = audit
        self._describe = describe
        self._client_address = client_address
        self._page = page
        self._sessions: dict[str, dict[str, Any]] = {}
        secure = urlsplit(self.public_url).scheme == "https"
        # __Host- makes the browser refuse the cookie unless it is Secure, host-only and Path=/.
        self.cookie = "__Host-cb_owner" if secure else "cb_owner"
        self._secure = secure

    def routes(self) -> list[Route]:
        return [
            Route("/devices", self._home, methods=["GET"]),
            Route("/devices/login", self._login, methods=["POST"]),
            Route("/devices/logout", self._logout, methods=["POST"]),
            Route("/devices/add", self._add, methods=["GET"]),
            Route("/devices/remove", self._remove, methods=["POST"]),
            Route("/devices/revoke-grant", self._revoke_grant, methods=["POST"]),
        ]

    # ------------------------------------------------------------ helpers

    def _log(self, event: str, **fields: Any) -> None:
        try:
            self.audit.record(event, **fields)
        except AuditError:
            pass

    def _session(self, request: Request) -> dict[str, Any] | None:
        now = time.time()
        self._sessions = {k: v for k, v in self._sessions.items() if v["expires_at"] > now}
        return self._sessions.get(request.cookies.get(self.cookie, ""))

    async def _authorized_form(self, request: Request) -> tuple[dict[str, Any] | None, Any]:
        """The session and form of a POST that carries the session's CSRF token, else (None, form)."""
        session = self._session(request)
        form = await request.form()
        if session is None or not secrets.compare_digest(str(form.get("csrf", "")), session["csrf"]):
            return None, form
        return session, form

    def _signed_out(self) -> Response:
        return RedirectResponse("/devices", status_code=303)

    def _render(self, body: str, *, status: int = 200) -> Response:
        return self._page(body, status=status, raw=True)

    # --------------------------------------------------------------- pages

    async def _home(self, request: Request) -> Response:
        session = self._session(request)
        if session is None:
            return self._login_form()
        return self._render(self._dashboard(session))

    async def _login(self, request: Request) -> Response:
        form = await request.form()
        address = self._client_address(request)
        failure = self.store.verify_owner(str(form.get("passphrase", "")), str(form.get("totp", "")), client=address)
        if failure is not None:
            self._log("dashboard_sign_in_failed", reason=failure, peer=address)
            if failure == "locked":
                minutes = max(1, round((self.store.locked_until(address) - time.time()) / 60))
                return self._login_form(error=f"Too many failed attempts. Sign-in is locked for about {minutes} minutes.", status=429)
            return self._login_form(error="Wrong passphrase or authenticator code.", status=401)
        while len(self._sessions) >= MAX_SESSIONS:
            del self._sessions[min(self._sessions, key=lambda k: self._sessions[k]["expires_at"])]
        session_id = secrets.token_urlsafe(32)
        self._sessions[session_id] = {"csrf": secrets.token_urlsafe(24), "expires_at": time.time() + SESSION_SECONDS}
        self._log("dashboard_signed_in", peer=address)
        response = RedirectResponse("/devices", status_code=303)
        response.set_cookie(
            self.cookie, session_id, max_age=SESSION_SECONDS, path="/", secure=self._secure, httponly=True,
            samesite="strict",
        )
        return response

    async def _logout(self, request: Request) -> Response:
        session, _ = await self._authorized_form(request)
        if session is not None:
            self._sessions = {k: v for k, v in self._sessions.items() if v is not session}
        response = RedirectResponse("/devices", status_code=303)
        response.delete_cookie(self.cookie, path="/", secure=self._secure, httponly=True, samesite="strict")
        return response

    async def _add(self, request: Request) -> Response:
        if self._session(request) is None:
            return self._signed_out()
        base = html.escape(self.public_url)
        body = f"""
<p><a href="/devices">&larr; Devices</a></p>
<h1>Add a device</h1>
{self._loopback_warning()}
<p>Run the installer on the new computer. It will display an eight-character activation code. Enter that code on
the <a href="/activate">activation page</a> ({base}/activate) and approve the device. No SSH configuration or
manually generated credentials are required.</p>
<h2>Linux</h2>
<p>As the user the agent should run as (not root):</p>
<pre>curl -fsSL {base}/install/remote-linux.sh | sh</pre>
<p class="small">Options after <code>sh -s --</code>: <code>--name NAME</code>, <code>--policy full</code>.</p>
<h2>Windows</h2>
<p>In PowerShell as Administrator:</p>
<pre>irm -ErrorAction Stop '{base}/install/remote-windows.ps1' | iex</pre>
<p>Or download <a href="/install/ContextBridgeSetup.cmd">ContextBridgeSetup.cmd</a> and double-click it; Windows asks
for administrator approval. It is not signed, so SmartScreen may warn about it.</p>
<p class="small">To reconnect or upgrade a device, run the same command on it again: it keeps its identity.</p>"""
        return self._render(body)

    async def _remove(self, request: Request) -> Response:
        session, form = await self._authorized_form(request)
        if session is None:
            return self._signed_out()
        name = str(form.get("device", ""))
        record = self.registry.by_name(name)
        if record is None:
            return self._render(self._dashboard(session, error=f"No active device named {name!r}."), status=404)
        if form.get("confirm") != "yes":
            body = f"""
<h1>Remove {html.escape(name)}?</h1>
<p>{html.escape(name)} is disconnected at once and can no longer connect. Assistants lose access to it.
To add it back later, run the installer on it again.</p>
<form method="post" action="/devices/remove">
<input type="hidden" name="csrf" value="{html.escape(session["csrf"])}">
<input type="hidden" name="device" value="{html.escape(name)}">
<input type="hidden" name="confirm" value="yes">
<button class="danger">Remove {html.escape(name)}</button> <a href="/devices">Cancel</a>
</form>"""
            return self._render(body)
        try:
            self.registry.revoke(record.device_id)
        except RegistryError as exc:
            return self._render(self._dashboard(session, error=str(exc)), status=409)
        self._log("device_revoked_by_owner", device=name, device_id=record.device_id, via="dashboard")
        return self._render(self._dashboard(session, notice=f"Removed {name}."))

    async def _revoke_grant(self, request: Request) -> Response:
        session, form = await self._authorized_form(request)
        if session is None:
            return self._signed_out()
        grant_id = str(form.get("grant", ""))
        found = next((g for g in self._grants() if g["grant_id"] == grant_id), None)
        if found is None:
            return self._render(self._dashboard(session, error="That access was already revoked."), status=404)
        if form.get("confirm") != "yes":
            body = f"""
<h1>Revoke {html.escape(found["client_name"])}'s access?</h1>
<p>Approved {html.escape(found["since"])} for {html.escape(", ".join(found["devices"]) or "no devices")}.
Its tokens stop working on the next request; to use it again, connect it from the assistant and approve it.</p>
<form method="post" action="/devices/revoke-grant">
<input type="hidden" name="csrf" value="{html.escape(session["csrf"])}">
<input type="hidden" name="grant" value="{html.escape(grant_id)}">
<input type="hidden" name="confirm" value="yes">
<button class="danger">Revoke</button> <a href="/devices">Cancel</a>
</form>"""
            return self._render(body)
        try:
            self.store.revoke_grant(grant_id)
        except OAuthStateError as exc:
            return self._render(self._dashboard(session, error=str(exc)), status=409)
        self._log("oauth_grant_revoked", client=found["client_id"], grant=grant_id, by="owner_dashboard")
        return self._render(self._dashboard(session, notice=f"Revoked {found['client_name']} ({found['since']})."))

    # -------------------------------------------------------------- content

    def _grants(self) -> list[dict[str, Any]]:
        rows = []
        for client in self.store.clients():
            hosts = sorted({urlsplit(u).netloc for u in client.get("redirect_uris", []) if "://" in u})
            for grant in client["grants"]:
                if grant.get("revoked_at") is not None or grant.get("refresh_expires_at", 0) <= time.time():
                    continue
                created = _parse(grant.get("created_at"))
                rows.append({
                    "grant_id": grant["grant_id"],
                    "client_id": client["client_id"],
                    "client_name": client.get("client_name") or "Unnamed client",
                    "hosts": hosts,
                    "devices": list(grant.get("devices", [])),
                    "scopes": list(grant.get("scopes", [])),
                    "created": created,
                    "since": created.strftime("%b %d, %Y %H:%M UTC") if created else "unknown",
                })
        return sorted(rows, key=lambda r: (r["client_name"].lower(), r["created"] or datetime.min.replace(tzinfo=timezone.utc)))

    def _devices(self) -> list[dict[str, Any]]:
        return [d for d in self._describe() if d.get("device", "") != "local"]

    def _loopback_warning(self) -> str:
        if not _is_loopback_url(self.public_url):
            return ""
        return f"""<p class="error">This gateway's public URL is {html.escape(self.public_url)}, which only this
computer can reach. Assistants and new devices elsewhere cannot use the addresses below. Set
<code>remote.public_url</code> to the https address clients reach (for example https://mcp.contextbridge.app) and
restart the gateway.</p>"""

    @staticmethod
    def _elsewhere_warning(devices: list[dict[str, Any]]) -> str:
        """Warn when no device is connected here although some were heard from moments ago.

        Online means connected to *this* process's agent listener. "Last seen" also comes from a state
        file the live hub rewrites every minute, so a second gateway sharing the state directory sees
        recent times for devices it holds no connection to, and would otherwise call them all offline.
        """
        if any(d.get("online") for d in devices):
            return ""
        now = datetime.now(timezone.utc)
        recent = [
            d.get("device", "") for d in devices
            if (seen := _parse(d.get("last_seen"))) is not None and (now - seen).total_seconds() <= RECENT_SECONDS
        ]
        if not recent:
            return ""
        return f"""<p class="error">No device is connected to this gateway, yet {html.escape(", ".join(recent))}
{"was" if len(recent) == 1 else "were"} heard from in the last few minutes. If this persists, another ContextBridge
gateway is probably running with the same state directory and the agents are connected to that one. Check which
process listens on the agent port and serves the public URL.</p>"""

    def _device_rows(self, csrf: str, devices: list[dict[str, Any]]) -> str:
        now = datetime.now(timezone.utc)
        rows = []
        for device in devices:
            name = device.get("device", "")
            online = bool(device.get("online"))
            info = device.get("info") or {}
            if online:
                seen = f"Online now · connected {ago(_parse(device.get('connected_since')), now)}"
            elif _parse(device.get("last_seen")) is None:
                seen = "Not seen since the gateway started"
            else:
                seen = f"Last seen {ago(_parse(device.get('last_seen')), now)}"
            details = " · ".join(filter(None, [info.get("platform"), info.get("agent_version") and f"agent {info['agent_version']}"]))
            rows.append(f"""
<li class="row">
  <span class="dot {'on' if online else 'off'}" aria-hidden="true"></span>
  <div class="main"><div class="name">{html.escape(name)}</div>
  <div class="seen">{html.escape(seen)}</div>
  {f'<div class="small">{html.escape(details)}</div>' if details else ""}</div>
  <span class="pill {'on' if online else 'off'}">{'Online' if online else 'Offline'}</span>
  <form method="post" action="/devices/remove"><input type="hidden" name="csrf" value="{csrf}">
  <input type="hidden" name="device" value="{html.escape(name)}"><button class="link danger">Remove</button></form>
</li>""")
        return "".join(rows) or '<li class="row"><div class="main">No devices yet. Add one.</div></li>'

    def _grant_rows(self, csrf: str) -> str:
        rows = []
        for grant in self._grants():
            rows.append(f"""
<li class="row">
  <div class="main"><div class="name">{html.escape(grant["client_name"])}
  <span class="small">{html.escape(", ".join(grant["hosts"]))}</span></div>
  <div class="seen">Devices: {html.escape(", ".join(grant["devices"]) or "none")}</div>
  <div class="small">{html.escape(", ".join(grant["scopes"]))} · approved {html.escape(grant["since"])}</div></div>
  <form method="post" action="/devices/revoke-grant"><input type="hidden" name="csrf" value="{csrf}">
  <input type="hidden" name="grant" value="{html.escape(grant["grant_id"])}"><button class="link danger">Revoke</button></form>
</li>""")
        return "".join(rows) or '<li class="row"><div class="main">No assistant has access.</div></li>'

    def _dashboard(self, session: dict[str, Any], *, notice: str = "", error: str = "") -> str:
        csrf = html.escape(session["csrf"])
        endpoint = html.escape(self.public_url + "/mcp")
        minutes = max(1, round((session["expires_at"] - time.time()) / 60))
        devices = self._devices()
        body = f"""
<div class="head"><h1>Devices</h1><a class="button" href="/devices/add">+ Add a device</a></div>
<p class="small">Computers your assistants can reach through ContextBridge. Signed in for about {minutes} more minutes.</p>
{f'<p class="notice">{html.escape(notice)}</p>' if notice else ""}
{f'<p class="error">{html.escape(error)}</p>' if error else ""}
{self._loopback_warning()}
{self._elsewhere_warning(devices)}
<ul class="list">{self._device_rows(csrf, devices)}</ul>
<h2>Assistants with access</h2>
<p class="small">Each approval is separate: an assistant reaches only the devices ticked when it was approved.</p>
<ul class="list">{self._grant_rows(csrf)}</ul>
<h2>Where you use it</h2>
<p>Add this MCP server to your assistant, then approve it on the page that opens:</p>
<pre>{endpoint}</pre>
<ul class="small">
<li><strong>ChatGPT</strong>: Settings, Apps &amp; Connectors, add a custom connector with this URL.</li>
<li><strong>Claude</strong>: Settings, Connectors, Add custom connector with this URL.</li>
<li><strong>Gemini / Antigravity</strong>: add it as a remote MCP server with this URL.</li>
<li><strong>Any MCP client</strong> (Cursor, VS Code, OpenCode, custom agents): use this URL; it signs in with OAuth.</li>
</ul>
<form method="post" action="/devices/logout"><input type="hidden" name="csrf" value="{csrf}">
<button class="link">Sign out</button></form>"""
        return body

    def _login_form(self, *, error: str = "", status: int = 200) -> Response:
        body = f"""
<h1>Devices</h1>
<p>Sign in to see and manage your devices and the assistants that can reach them.</p>
{f'<p class="error">{html.escape(error)}</p>' if error else ""}
<form method="post" action="/devices/login">
<label>Passphrase <input type="password" name="passphrase" autocomplete="current-password" required></label>
<label>Authenticator code <input name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" required></label>
<button>Sign in</button>
</form>"""
        return self._render(body, status=status)
