"""Owner dashboard: devices, endpoints and assistant access, usage, and settings.

After signing in with the passphrase and an authenticator code (the same check, and the same
lockout, as the consent and activation pages) the owner has four pages:

* **Devices** (``/devices``): each enrolled device by name, then when it was last seen, its system
  and agent version, and Remove (revokes the device; its connection drops within about a second).
  **Add a device** (``/devices/add``) shows the one-command installers and leads to ``/activate``.
* **Endpoints** (``/devices/endpoints``): the MCP endpoint, how to connect each assistant, and every
  assistant's access, *per device*: which permissions it holds on which computer. Narrowing applies
  on the next request, for tokens already issued too. Widening never exceeds what the assistant's
  token was approved for; to go further the owner requests re-authorization, which the assistant
  completes on the consent page. Every change is kept in the grant's history and the audit log.
* **Usage** (``/devices/usage``): tool calls this month, the daily average, and six months of totals.
* **Settings** (``/devices/settings``): sign out, change the passphrase, light or dark.

The session is a random id in a cookie (HttpOnly, SameSite=Strict, Secure on https, ``__Host-``
prefixed) that lasts 15 minutes from sign-in and is kept only in memory, so a gateway restart signs
everyone out. Every change is a POST carrying the session's CSRF token; Remove and Revoke ask for
confirmation first. The pages run no scripts (see ``dashboard_view``).
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..computer.audit import AuditError, ComputerAuditLog
from ..computer.scopes import ALL_SCOPES, SCOPE_READ
from ..remote.registry import DeviceRegistry, RegistryError
from .dashboard_view import STYLE, centered, esc, hidden, icon, shell
from .store import MIN_PASSPHRASE_LENGTH, OAuthStateError, OAuthStore
from .usage import UsageCounter

SESSION_SECONDS = 15 * 60
MAX_SESSIONS = 10
# A device seen this recently but not connected here was most likely heard by another gateway process.
RECENT_SECONDS = 3 * 60
THEME_COOKIE = "cb_theme"
LOCAL_DEVICE = "local"

SCOPE_LABELS = {
    "computer:read": ("Read", "Read files and system information"),
    "computer:write": ("Write", "Create, edit and delete files"),
    "computer:execute": ("Execute", "Run permitted commands"),
    "computer:process": ("Process", "End processes"),
    "desktop:observe": ("Desktop", "See window titles on the desktop"),
    "media:discover": ("Media", "See which cameras and microphones exist"),
}


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


def _is_loopback_url(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _short(scope: str) -> str:
    return scope.split(":", 1)[-1]


def _stamp(when: Any) -> str:
    parsed = _parse(when)
    return f"{parsed:%b} {parsed.day} {parsed:%H:%M}" if parsed else ""


def _nice_ceiling(value: int) -> int:
    """The smallest 1, 2 or 5 times a power of ten at or above ``value`` (at least 10)."""
    step = 10
    while True:
        for factor in (1, 2, 5):
            if step * factor >= value:
                return step * factor
        step *= 10


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
        allow_scopes: tuple[str, ...] = ALL_SCOPES,
        device_allowed: Callable[[str], bool] = lambda device: True,
        tool_scopes: dict[str, str] | None = None,
        usage: UsageCounter | None = None,
    ) -> None:
        self.public_url = public_url.rstrip("/")
        self.registry = registry
        self.store = store
        self.audit = audit
        self._describe = describe
        self._client_address = client_address
        self._page = page
        self.allow_scopes = tuple(s for s in ALL_SCOPES if s in allow_scopes)
        self._device_allowed = device_allowed
        self._tool_scopes = tool_scopes or {}
        self.usage = usage or UsageCounter(getattr(audit, "path", None))
        self.gateway_name = socket.gethostname().split(".")[0].lower()
        self._sessions: dict[str, dict[str, Any]] = {}
        secure = urlsplit(self.public_url).scheme == "https"
        # __Host- makes the browser refuse the cookie unless it is Secure, host-only and Path=/.
        self.cookie = "__Host-cb_owner" if secure else "cb_owner"
        self._secure = secure

    def routes(self) -> list[Route]:
        return [
            Route("/devices", self._home, methods=["GET"]),
            Route("/devices/add", self._add, methods=["GET"]),
            Route("/devices/endpoints", self._endpoints, methods=["GET"]),
            Route("/devices/usage", self._usage_page, methods=["GET"]),
            Route("/devices/settings", self._settings, methods=["GET"]),
            Route("/devices/login", self._login, methods=["POST"]),
            Route("/devices/logout", self._logout, methods=["POST"]),
            Route("/devices/remove", self._remove, methods=["POST"]),
            Route("/devices/revoke-grant", self._revoke_grant, methods=["POST"]),
            Route("/devices/grant-access", self._grant_access, methods=["POST"]),
            Route("/devices/reauth", self._reauth, methods=["POST"]),
            Route("/devices/cancel-reauth", self._cancel_reauth, methods=["POST"]),
            Route("/devices/passphrase", self._passphrase, methods=["POST"]),
            Route("/devices/theme", self._theme, methods=["POST"]),
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

    @staticmethod
    def _theme_of(request: Request) -> str:
        return "light" if request.cookies.get(THEME_COOKIE) == "light" else "dark"

    def _render(self, request: Request, body: str, *, status: int = 200, title: str = "Devices") -> Response:
        return self._page(
            body, status=status, raw=True, style=STYLE, title=f"{esc(title)} · ContextBridge",
            html_attrs=f'data-theme="{self._theme_of(request)}"',
        )

    def _screen(
        self, request: Request, session: dict[str, Any], current: str, content: str, *, status: int = 200,
        title: str = "", notice: str = "", error: str = "",
    ) -> Response:
        flash = "".join([
            f'<div class="note note-ok" role="status">{esc(notice)}</div>' if notice else "",
            f'<div class="note note-warn" role="alert">{esc(error)}</div>' if error else "",
        ])
        body = shell(
            flash + content, current=current, device_count=len(self._devices()), gateway=self.gateway_name,
            calls_this_month=int(self.usage.summary()["this_month"]),
        )
        return self._render(request, body, status=status, title=title or current.title())

    @staticmethod
    def _csrf(session: dict[str, Any]) -> str:
        return hidden("csrf", session["csrf"])

    # ------------------------------------------------------------ sign-in

    async def _login(self, request: Request) -> Response:
        form = await request.form()
        address = self._client_address(request)
        failure = self.store.verify_owner(str(form.get("passphrase", "")), str(form.get("totp", "")), client=address)
        if failure is not None:
            self._log("dashboard_sign_in_failed", reason=failure, peer=address)
            if failure == "locked":
                minutes = max(1, round((self.store.locked_until(address) - time.time()) / 60))
                return self._login_form(
                    request, error=f"Too many failed attempts. Sign-in is locked for about {minutes} minutes.",
                    status=429,
                )
            return self._login_form(request, error="Wrong passphrase or authenticator code.", status=401)
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

    def _login_form(self, request: Request, *, error: str = "", status: int = 200) -> Response:
        body = centered(f"""
<div class="brand" style="padding:0"><div class="brand-mark">{icon("bridge")}</div>
<div><b>ContextBridge</b><span>Remote MCP</span></div></div>
<div><h5>Sign in</h5><p class="sm muted">Manage your devices and the assistants that can reach them.</p></div>
{f'<div class="note note-warn" role="alert">{esc(error)}</div>' if error else ""}
<form method="post" action="/devices/login" class="stack gap4">
<div class="field"><label for="pp">Passphrase</label>
<input class="input" id="pp" type="password" name="passphrase" autocomplete="current-password" required></div>
<div class="field"><label for="code">Authenticator code</label>
<input class="input mono" id="code" name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" required></div>
<button class="btn btn-primary">Sign in</button>
</form>""")
        return self._render(request, body, status=status, title="Sign in")

    # ------------------------------------------------------------ devices

    def _devices(self) -> list[dict[str, Any]]:
        return [d for d in self._describe() if d.get("device", "") != LOCAL_DEVICE]

    def _loopback_warning(self) -> str:
        if not _is_loopback_url(self.public_url):
            return ""
        return f"""<div class="note note-warn" role="alert">This gateway's public URL is {esc(self.public_url)}, which
only this computer can reach. Assistants and new devices elsewhere cannot use the addresses below. Set
<code>remote.public_url</code> to the https address clients reach (for example https://mcp.contextbridge.app) and
restart the gateway.</div>"""

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
        return f"""<div class="note note-warn" role="alert">No device is connected to this gateway, yet
{esc(", ".join(recent))} {"was" if len(recent) == 1 else "were"} heard from in the last few minutes. If this
persists, another ContextBridge gateway is probably running with the same state directory and the agents are
connected to that one. Check which process listens on the agent port and serves the public URL.</div>"""

    @staticmethod
    def _seen(device: dict[str, Any], now: datetime) -> str:
        if device.get("online"):
            return f"Online now · connected {ago(_parse(device.get('connected_since')), now)}"
        if _parse(device.get("last_seen")) is None:
            return "Not seen since the gateway started"
        return f"Last seen {ago(_parse(device.get('last_seen')), now)}"

    def _device_rows(self, session: dict[str, Any], devices: list[dict[str, Any]]) -> str:
        now = datetime.now(timezone.utc)
        rows = []
        for device in devices:
            name = device.get("device", "")
            online = bool(device.get("online"))
            info = device.get("info") or {}
            details = " · ".join(filter(None, [
                info.get("platform"), info.get("agent_version") and f"agent {info['agent_version']}",
            ]))
            reconnect = "" if online else (
                '<a class="btn btn-ghost btn-sm" href="/devices/add" title="Run the installer on it again">Reconnect</a>'
            )
            rows.append(f"""
<div class="item">
 <span class="dot{' on' if online else ''}" aria-hidden="true"></span>
 <div class="grow stack" style="gap:2px"><span class="name">{esc(name)}</span>
 <span class="seen small muted">{esc(self._seen(device, now))}</span>
 {f'<span class="small fainter">{esc(details)}</span>' if details else ""}</div>
 <span class="tag {'tag-accent' if online else 'tag-neutral'}">{'Online' if online else 'Offline'}</span>
 {reconnect}
 <form method="post" action="/devices/remove">{self._csrf(session)}{hidden("device", name)}
 <button class="btn btn-quiet">Remove</button></form>
</div>""")
        return "".join(rows) or '<div class="item muted sm">No devices yet. Add one to let your AI clients reach it.</div>'

    async def _home(self, request: Request) -> Response:
        session = self._session(request)
        if session is None:
            return self._login_form(request)
        return self._devices_page(request, session)

    def _devices_page(
        self, request: Request, session: dict[str, Any], *, notice: str = "", error: str = "", status: int = 200
    ) -> Response:
        devices = self._devices()
        content = f"""
<header class="page-head"><div><h2>Devices</h2><p>Machines your AI clients can reach through the gateway.</p></div>
<a class="btn btn-primary" href="/devices/add" style="padding:9px 14px">{icon("plus")}Add a device</a></header>
{self._loopback_warning()}{self._elsewhere_warning(devices)}
<section class="panel">
 <div class="list-head"><span class="panel-title">Your devices <span class="faint" style="font-weight:400">· {len(devices)}</span></span></div>
 {self._device_rows(session, devices)}
 <div class="foot">Your AI clients reach these devices through an endpoint. <a href="/devices/endpoints">Manage endpoints</a></div>
</section>"""
        return self._screen(request, session, "devices", content, notice=notice, error=error, status=status)

    async def _add(self, request: Request) -> Response:
        session = self._session(request)
        if session is None:
            return self._signed_out()
        os_name = "linux" if request.query_params.get("os") == "linux" else "windows"
        base = esc(self.public_url)
        tabs = "".join(
            f'<a href="/devices/add?os={key}"{" aria-current=page" if key == os_name else ""}>{label}</a>'
            for key, label in (("windows", "Windows"), ("linux", "Linux"))
        )
        recommended = '<span class="tag tag-accent" style="padding:1px 8px">Recommended</span>'
        if os_name == "windows":
            methods = f"""
<details class="method" open><summary><div class="grow stack" style="gap:2px">
 <span class="row strong" style="gap:var(--space-2);font-size:14px">Download and run{recommended}</span>
 <span class="small faint">Easiest option. No commands to type.</span></div><span class="chev">{icon("caret")}</span></summary>
 <div class="method-body"><a class="btn btn-primary" href="/install/ContextBridgeSetup.cmd" style="padding:10px">{icon("download")}Download ContextBridgeSetup.cmd</a>
 <span class="small muted">Double-click the file and approve the administrator prompt. SmartScreen may warn: the file is not signed.</span></div>
</details>
<details class="method"><summary><div class="grow stack" style="gap:2px"><span class="strong" style="font-size:14px">PowerShell setup script</span>
 <span class="small faint">One command in PowerShell as Administrator.</span></div><span class="chev">{icon("caret")}</span></summary>
 <div class="method-body"><pre class="cmd">irm -ErrorAction Stop '{base}/install/remote-windows.ps1' | iex</pre>
 <span class="small muted">Installs Python and Git with winget if they are missing.</span></div>
</details>
<details class="method"><summary><div class="grow stack" style="gap:2px"><span class="strong" style="font-size:14px">Manual (advanced)</span>
 <span class="small faint">Clone the repository and use your own Python 3.11+.</span></div><span class="chev">{icon("caret")}</span></summary>
 <div class="method-body"><pre class="cmd">git clone https://github.com/Deep-Sixed/ContextBridge C:\\ContextBridge
cd C:\\ContextBridge; py -3 -m venv .venv
.venv\\Scripts\\python -m pip install -e .</pre>
 <span class="small muted">Then run <code>contextbridge-agent activate</code> with <code>--server {base}</code>.</span></div>
</details>"""
        else:
            methods = f"""
<div class="stack" style="gap:2px"><span class="row strong" style="gap:var(--space-2);font-size:14px">Quick setup{recommended}</span>
<span class="small faint">Run as the user the agent should run as, not root. Asks for sudo only to install missing packages.</span></div>
<pre class="cmd"><span class="prompt">$ </span>curl -fsSL {base}/install/remote-linux.sh | sh</pre>
<span class="small faint">Installs into ~/.local/share/contextbridge and runs as a systemd user service. Options go after
<code>sh -s --</code>, for example <code>--name NAME</code> or <code>--policy full</code>.</span>"""
        content = f"""
<a class="btn btn-ghost btn-sm" href="/devices" style="align-self:flex-start">{icon("left")}Devices</a>
{self._loopback_warning()}
<div class="panel stack gap6" style="padding:var(--space-8)">
 <div class="stepper"><span class="on"><b>1</b>Choose method</span><span><b>2</b>Approve</span><span><b>3</b>Verify</span></div>
 <div><h4>Connect a device</h4><p class="muted" style="font-size:14px">The agent runs on the device and dials out to your
 gateway, so it needs no inbound ports. It enforces its own policy and keeps its own audit log.</p></div>
 <div class="tabs">{tabs}</div>
 <div class="stack gap3">{methods}</div>
 <div class="row wrap" style="justify-content:space-between">
  <span class="small faint grow" style="min-width:220px">Run the installer on the new computer. It will display an
  eight-character activation code. Enter that code on the activation page and approve the device. No SSH configuration
  or manually generated credentials are required.</span>
  <a class="btn btn-secondary" href="/activate">I have a code{icon("right")}</a>
 </div>
 <p class="small faint">To reconnect or upgrade a device, run the same command on it again: it keeps its identity. Once
 approved, it appears on <a href="/devices">Devices</a> as Online.</p>
</div>"""
        return self._screen(request, session, "devices", content, title="Add a device")

    async def _remove(self, request: Request) -> Response:
        session, form = await self._authorized_form(request)
        if session is None:
            return self._signed_out()
        name = str(form.get("device", ""))
        record = self.registry.by_name(name)
        if record is None:
            return self._devices_page(request, session, error=f"No active device named {name!r}.", status=404)
        if form.get("confirm") != "yes":
            return self._confirm(
                request, session, title=f"Remove {name}?",
                text=f"{name} is disconnected at once and can no longer connect. Assistants lose access to it. "
                     "To add it back later, run the installer on it again.",
                action="/devices/remove", fields={"device": name}, verb="Remove", back="/devices",
            )
        try:
            self.registry.revoke(record.device_id)
        except RegistryError as exc:
            return self._devices_page(request, session, error=str(exc), status=409)
        self._log("device_revoked_by_owner", device=name, device_id=record.device_id, via="dashboard")
        return self._devices_page(request, session, notice=f"Removed {name}.")

    def _confirm(
        self, request: Request, session: dict[str, Any], *, title: str, text: str, action: str,
        fields: dict[str, str], verb: str, back: str,
    ) -> Response:
        body = centered(f"""<h5>{esc(title)}</h5><p class="sm muted">{esc(text)}</p>
<form method="post" action="{esc(action)}" class="actions">{self._csrf(session)}
{"".join(hidden(k, v) for k, v in fields.items())}{hidden("confirm", "yes")}
<a class="btn btn-secondary" href="{esc(back)}">Cancel</a><button class="btn btn-primary">{esc(verb)}</button></form>""")
        return self._render(request, body, title=title)

    # ---------------------------------------------------------- endpoints

    def _grants(self) -> list[dict[str, Any]]:
        rows = []
        for client in self.store.clients():
            hosts = sorted({urlsplit(u).netloc for u in client.get("redirect_uris", []) if "://" in u})
            loopback = bool(hosts) and all(_is_loopback_url("http://" + h) for h in hosts)
            for grant in client["grants"]:
                if grant.get("revoked_at") is not None or grant.get("refresh_expires_at", 0) <= time.time():
                    continue
                created = _parse(grant.get("created_at"))
                rows.append({
                    "grant_id": grant["grant_id"],
                    "client_id": client["client_id"],
                    "client_name": client.get("client_name") or "Unnamed client",
                    "hosts": hosts,
                    "origin": "Local PKCE" if loopback else ", ".join(hosts) or "unknown origin",
                    "devices": list(grant.get("devices", [])),
                    "scopes": list(grant.get("scopes", [])),
                    "device_scopes": self.store.device_scopes(grant),
                    "history": list(grant.get("history", [])),
                    "reauth": bool(grant.get("reauth_requested_at")),
                    "created": created,
                    "since": created.strftime("%b %d, %Y %H:%M UTC") if created else "unknown",
                    "approved": f"{created:%b} {created.day}" if created else "unknown",
                })
        return sorted(
            rows, key=lambda r: (r["client_name"].lower(), r["created"] or datetime.min.replace(tzinfo=timezone.utc))
        )

    def _capabilities(self) -> dict[str, dict[str, Any]]:
        """Each device an assistant may be given: what it can do at all, and a short description.

        For an online device that is what its agent offers (a read-only agent has no write tools);
        otherwise the scopes it was approved for. The dashboard can only narrow what a device allows.
        """
        caps: dict[str, dict[str, Any]] = {}
        for row in self._describe():
            name = row.get("device", "")
            if not name or not self._device_allowed(name):
                continue
            if name == LOCAL_DEVICE:
                scopes = set(ALL_SCOPES)
            else:
                record = self.registry.by_name(name) if self.registry is not None else None
                scopes = set(record.scopes if record is not None else row.get("scopes") or [])
                tools = row.get("tools")
                if row.get("online") and isinstance(tools, list) and self._tool_scopes:
                    scopes &= {self._tool_scopes.get(t) for t in tools}
            scopes &= set(self.allow_scopes)
            info = row.get("info") or {}
            platform = str(info.get("platform") or "").split(" ")[0]
            mode = "full" if set(self.allow_scopes) <= scopes else ("read-only" if scopes <= {SCOPE_READ} else "limited")
            caps[name] = {
                "scopes": scopes,
                "host": " · ".join(filter(None, ["this gateway" if name == LOCAL_DEVICE else platform, mode])),
            }
        return caps

    def _grant_panel(
        self, session: dict[str, Any], grant: dict[str, Any], caps: dict[str, dict[str, Any]], open_: bool
    ) -> str:
        scopes = self.allow_scopes
        token = set(grant["scopes"])
        current = grant["device_scopes"]
        name = grant["client_name"]
        cols = f"minmax(96px,1.4fr) repeat({len(scopes)},minmax(52px,1fr))"
        head = "".join(
            f'<span style="text-align:center" title="{esc(SCOPE_LABELS[s][1])}">{esc(SCOPE_LABELS[s][0])}</span>'
            for s in scopes
        )

        def row(device: str, granted: bool) -> str:
            cap = caps.get(device, {"scopes": set(), "host": "not connected"})
            cells = []
            for s in scopes:
                label = SCOPE_LABELS[s][0]
                if s not in cap["scopes"]:
                    cells.append(
                        f'<div class="cell"><span class="deny" title="{esc(device)} does not allow '
                        f'{esc(_short(s))}">—</span></div>'
                    )
                    continue
                beyond = s not in token
                title = f"{label} isn't in this assistant's token scopes" if beyond else f"{label} on {device}"
                cells.append(
                    f'<div class="cell"><label class="{"beyond" if beyond else ""}" title="{esc(title)}">'
                    f'<input type="checkbox" name="perm" value="{esc(device)}|{esc(s)}"'
                    f'{" checked" if s in current.get(device, []) else ""} aria-label="{esc(label)} on {esc(device)}">'
                    "</label></div>"
                )
            return (
                f'<div class="grid grid-row{"" if granted else " out"}" style="grid-template-columns:{cols}">'
                f'<div class="stack" style="line-height:1.3"><span class="devname mono sm">{esc(device)}</span>'
                f'<span class="fainter" style="font-size:11px">{esc(cap["host"])}</span></div>{"".join(cells)}</div>'
            )

        granted = sorted(d for d in current if current[d])
        others = sorted(d for d in caps if d not in granted)
        rows = "".join(row(d, True) for d in granted)
        if others:
            rows += (
                f'<div class="grid" style="grid-template-columns:{cols}"><span class="grid-sep">Not in this grant: '
                "tick a permission to add the device</span></div>" + "".join(row(d, False) for d in others)
            )
        beyond = sorted(
            {s for d in granted for s in current[d] if s not in token and s in caps.get(d, {}).get("scopes", set())},
            key=ALL_SCOPES.index,
        )
        reauth = ""
        if beyond:
            where = "; ".join(f"{SCOPE_LABELS[s][0]} on {', '.join(d for d in granted if s in current[d])}" for s in beyond)
            gid_field = self._csrf(session) + hidden("grant", grant["grant_id"])
            action = (
                '<div class="row wrap" style="gap:var(--space-2)"><span class="tag tag-accent">Requested · consent page '
                f'on next connection</span><form method="post" action="/devices/cancel-reauth">{gid_field}'
                '<button class="btn btn-secondary btn-sm">Cancel request</button></form></div>' if grant["reauth"] else
                f'<form method="post" action="/devices/reauth">{gid_field}'
                '<button class="btn btn-primary btn-sm">Request re-authorization</button></form>'
            )
            reauth = f"""<div class="note note-ok row wrap"><div class="grow stack" style="gap:2px;min-width:220px">
<span class="sm strong">{esc(where)} isn't covered by {esc(name)}'s token</span>
<span class="small muted">Until {esc(name)} re-authorizes, the gateway enforces only what its token allows. Requesting it
lets the current token run until it expires (at most an hour); the assistant then reconnects through the consent page,
where you approve with your passphrase and a code. Until then it cannot refresh, so if you deny that page or it never
reconnects, it loses access: cancel the request to keep its current access instead.</span></div>{action}</div>"""
        history = "".join(
            f'<span class="at">{esc(_stamp(h.get("at")))}</span><span class="what">'
            f'{esc(("Owner " if h.get("by") == "owner" else "") + str(h.get("text", "")))}</span>'
            for h in grant["history"][:4]
        ) or '<span class="at"></span><span class="what fainter">No changes recorded yet.</span>'
        count = len(granted)
        tags = (
            '<span class="tag tag-accent">Re-authorization requested</span>' if grant["reauth"] else
            '<span class="tag tag-outline">Needs re-authorization</span>' if beyond else ""
        )
        chips = "".join(f'<code class="chip">{esc(s)}</code>' for s in grant["scopes"])
        return f"""
<details class="grant" id="{esc(grant["grant_id"])}"{" open" if open_ else ""}>
<summary class="row" style="padding:var(--space-4) var(--space-6)"><div class="grow stack" style="gap:2px">
<span class="strong" style="font-size:14px">{esc(name)}</span>
<span class="small faint">{esc(grant["origin"])} · {count} device{"s" if count != 1 else ""}</span></div>
{tags}<span class="chev">{icon("caret")}</span></summary>
<div class="grant-body">
 <div class="row wrap small muted" style="gap:var(--space-2)"><span>Token scopes</span>{chips}
 <span class="fainter">· approved {esc(grant["approved"])}. The gateway never enforces more than these.</span></div>
 <form method="post" action="/devices/grant-access" class="stack gap6">{self._csrf(session)}{hidden("grant", grant["grant_id"])}
  <div class="grid-scroll"><div class="grid grid-head" style="grid-template-columns:{cols}"><span>Device</span>{head}</div>{rows}</div>
  <div class="legend"><span>— That device doesn't allow it. The dashboard never raises a device's own limits, and agents
  run with the account and token chosen when they were installed.</span>
  <span class="row" style="gap:6px"><span class="swatch"></span>Outside the token's scopes</span></div>
  <div class="row wrap" style="justify-content:flex-end;gap:var(--space-2)">
   <span class="small faint grow" style="min-width:200px">Removals apply on the next request, including for tokens already issued.</span>
   <button type="reset" class="btn btn-secondary btn-sm">Discard</button>
   <button class="btn btn-primary btn-sm">Save changes</button></div>
 </form>
 {reauth}
 <div class="stack gap2"><span class="small faint">Recent changes</span><div class="log">{history}</div></div>
 <form method="post" action="/devices/revoke-grant" class="row" style="justify-content:flex-end">{self._csrf(session)}
 {hidden("grant", grant["grant_id"])}<button class="btn btn-secondary btn-sm muted">Revoke access</button></form>
</div>
</details>"""

    def _endpoints_page(
        self, request: Request, session: dict[str, Any], *, open_grant: str = "", notice: str = "", error: str = "",
        status: int = 200,
    ) -> Response:
        endpoint = self.public_url + "/mcp"
        grants = self._grants()
        caps = self._capabilities()
        first = open_grant or (grants[0]["grant_id"] if grants else "")
        panels = "".join(self._grant_panel(session, g, caps, g["grant_id"] == first) for g in grants) or (
            '<div class="panel pad sm muted">No assistant has access. Connect one below.</div>'
        )
        clients = (
            ("GPT", "ChatGPT", "Paste the connector URL into a custom connector.", [
                ("Add a connector", (
                    "In ChatGPT, open Settings, Apps & Connectors, and create a custom connector with the endpoint URL."
                )),
                ("Approve on the consent page", (
                    "Sign in with your passphrase and an authenticator code. Only read starts ticked; "
                    "set more per device here afterwards."
                ))]),
            ("CL", "Claude", "Paste the connector URL into a custom connector.", [
                ("Add a connector", "In Claude, open Settings, Connectors, Add custom connector, and paste the endpoint URL."),
                ("Approve on the consent page", "Only computer:read starts ticked; anything more is a deliberate choice.")]),
            ("GEM", "Gemini / Antigravity", "Add ContextBridge as a custom MCP server.", [
                ("Add the server", "Register the endpoint URL as a remote MCP server."),
                ("Approve on the consent page", "Pick the devices it may use, then adjust permissions here.")]),
            ("MCP", "Any MCP client", "Cursor, VS Code, OpenCode, custom agents.", [
                ("Register the endpoint", "Add it as a remote MCP server; it signs in with OAuth."),
                ("Authorize once", "Access is kept per assistant and can be narrowed or revoked here at any time.")]),
        )

        def steps(items: list[tuple[str, str]]) -> str:
            return "".join(
                f'<li><span class="num">{i}</span><div class="stack" style="gap:2px"><span class="sm strong">{esc(t)}</span>'
                f'<span class="sm muted">{esc(b)}</span></div></li>'
                for i, (t, b) in enumerate(items, 1)
            )

        client_rows = "".join(f"""
<details class="disclosure" style="border-top:1px solid var(--color-neutral-900)">
<summary><span class="mono-badge">{mono}</span><div class="grow stack" style="gap:2px">
<span class="strong" style="font-size:14px">{esc(title)}</span><span class="small faint">{esc(desc)}</span></div>
<span class="row sm" style="gap:6px;color:var(--color-accent-300)">Set up<span class="chev">{icon("caret")}</span></span></summary>
<ol class="steps">{steps(items)}</ol>
</details>""" for mono, title, desc, items in clients)
        content = f"""
<header class="page-head"><div><h2>Endpoints</h2><p>Where your assistants connect. Every client shares the same devices,
policies and audit log.</p></div></header>
{self._loopback_warning()}
<section class="panel pad stack gap4">
 <div class="row" style="align-items:flex-start"><div class="grow stack" style="gap:2px"><span class="panel-title">Remote endpoint</span>
 <span class="sm muted">For ChatGPT, Claude and other cloud clients, published through your tunnel.</span></div>
 <span class="tag tag-accent">OAuth</span></div>
 <input class="input urlbox" readonly value="{esc(endpoint)}" aria-label="Endpoint URL">
 <span class="small faint">Select the address and copy it into your assistant.</span>
</section>
<section class="stack gap3">
 <div class="stack" style="gap:2px"><div class="row panel-title" style="gap:var(--space-2)"><span class="muted">{icon("shield")}</span>Assistant access</div>
 <div class="sm muted">Pairing creates a minimal read grant. Set each assistant's devices and permissions here, per device.
 Reductions apply on the next request, including for existing tokens.</div></div>
 {panels}
</section>
<section class="panel">
 <div style="padding:var(--space-6) var(--space-6) var(--space-4)"><div class="panel-title" style="margin-bottom:2px">Connect a client</div>
 <div class="sm muted">Add the remote endpoint as a custom connector. The client opens a consent page where you approve it.</div></div>
 {client_rows}
</section>"""
        return self._screen(request, session, "endpoints", content, notice=notice, error=error, status=status)

    async def _endpoints(self, request: Request) -> Response:
        session = self._session(request)
        if session is None:
            return self._signed_out()
        return self._endpoints_page(request, session, open_grant=request.query_params.get("open", ""))

    def _found_grant(self, grant_id: str) -> dict[str, Any] | None:
        return next((g for g in self._grants() if g["grant_id"] == grant_id), None)

    async def _grant_access(self, request: Request) -> Response:
        session, form = await self._authorized_form(request)
        if session is None:
            return self._signed_out()
        grant_id = str(form.get("grant", ""))
        found = self._found_grant(grant_id)
        if found is None:
            return self._endpoints_page(request, session, error="That access was already revoked.", status=404)
        caps = self._capabilities()
        before = found["device_scopes"]
        wanted: dict[str, set[str]] = {}
        for value in form.getlist("perm"):
            device, _, scope = str(value).partition("|")
            # Only what the device itself allows and remote use permits; anything else is ignored.
            if device in caps and scope in caps[device]["scopes"]:
                wanted.setdefault(device, set()).add(scope)
        # A device the page could not show (not offered to remote clients right now) keeps what it had.
        for device, kept in before.items():
            if device not in caps:
                wanted[device] = set(kept)
        after = {d: [s for s in ALL_SCOPES if s in v] for d, v in wanted.items() if v}
        changes = []
        for device in sorted(set(before) | set(after)):
            old, new = set(before.get(device, [])), set(after.get(device, []))
            if not old and new:
                changes.append(f"added {device} with {', '.join(_short(s) for s in ALL_SCOPES if s in new)}")
            elif old and not new:
                changes.append(f"removed {device}")
            else:
                for s in ALL_SCOPES:
                    if s in new and s not in old:
                        changes.append(f"allowed {_short(s)} on {device}")
                    elif s in old and s not in new:
                        changes.append(f"removed {_short(s)} on {device}")
        if not changes:
            return self._endpoints_page(request, session, open_grant=grant_id, notice="No changes to save.")
        try:
            self.store.set_device_scopes(grant_id, after, changes=changes)
        except OAuthStateError as exc:
            return self._endpoints_page(request, session, error=str(exc), status=409)
        self._log(
            "oauth_grant_changed", client=found["client_id"], grant=grant_id, by="owner_dashboard",
            before=before, after=after, changes=changes,
        )
        note = f"Saved {len(changes)} change{'s' if len(changes) != 1 else ''} for {found['client_name']}."
        if any(s not in found["scopes"] for v in after.values() for s in v):
            note += " Some permissions are outside its token and need re-authorization before they apply."
        return self._endpoints_page(request, session, open_grant=grant_id, notice=note)

    async def _reauth(self, request: Request) -> Response:
        session, form = await self._authorized_form(request)
        if session is None:
            return self._signed_out()
        grant_id = str(form.get("grant", ""))
        found = self._found_grant(grant_id)
        if found is None:
            return self._endpoints_page(request, session, error="That access was already revoked.", status=404)
        wanted = sorted(
            {s for v in found["device_scopes"].values() for s in v if s not in found["scopes"]}, key=ALL_SCOPES.index
        )
        if not wanted:
            return self._endpoints_page(
                request, session, open_grant=grant_id, notice="Its token already covers everything ticked."
            )
        try:
            self.store.request_reauth(grant_id, [_short(s) for s in wanted], found["device_scopes"])
        except OAuthStateError as exc:
            return self._endpoints_page(request, session, error=str(exc), status=409)
        self._log("oauth_reauth_requested", client=found["client_id"], grant=grant_id, scopes=wanted, by="owner_dashboard")
        return self._endpoints_page(
            request, session, open_grant=grant_id,
            notice=f"Requested re-authorization. {found['client_name']} sees the consent page when its current token expires.",
        )

    async def _cancel_reauth(self, request: Request) -> Response:
        session, form = await self._authorized_form(request)
        if session is None:
            return self._signed_out()
        grant_id = str(form.get("grant", ""))
        found = self._found_grant(grant_id)
        if found is None:
            return self._endpoints_page(request, session, error="That access was already revoked.", status=404)
        try:
            self.store.cancel_reauth(grant_id)
        except OAuthStateError as exc:
            return self._endpoints_page(request, session, error=str(exc), status=409)
        self._log("oauth_reauth_cancelled", client=found["client_id"], grant=grant_id, by="owner_dashboard")
        return self._endpoints_page(
            request, session, open_grant=grant_id,
            notice=f"Cancelled. {found['client_name']} keeps its current access and refreshes normally.",
        )

    async def _revoke_grant(self, request: Request) -> Response:
        session, form = await self._authorized_form(request)
        if session is None:
            return self._signed_out()
        grant_id = str(form.get("grant", ""))
        found = self._found_grant(grant_id)
        if found is None:
            return self._endpoints_page(request, session, error="That access was already revoked.", status=404)
        if form.get("confirm") != "yes":
            return self._confirm(
                request, session, title=f"Revoke {found['client_name']}'s access?",
                text=f"Approved {found['since']} for {', '.join(found['devices']) or 'no devices'}. Its tokens stop "
                     "working on the next request; to use it again, connect it from the assistant and approve it.",
                action="/devices/revoke-grant", fields={"grant": grant_id}, verb="Revoke", back="/devices/endpoints",
            )
        try:
            self.store.revoke_grant(grant_id)
        except OAuthStateError as exc:
            return self._endpoints_page(request, session, error=str(exc), status=409)
        self._log("oauth_grant_revoked", client=found["client_id"], grant=grant_id, by="owner_dashboard")
        return self._endpoints_page(request, session, notice=f"Revoked {found['client_name']} ({found['since']}).")

    # -------------------------------------------------------------- usage

    async def _usage_page(self, request: Request) -> Response:
        session = self._session(request)
        if session is None:
            return self._signed_out()
        usage = self.usage.summary()
        months = usage["months"]
        top = _nice_ceiling(max([n for _, n in months] + [1]))
        bars = "".join(
            f'<div class="bar" title="{label}: {n:,} calls" style="height:{max(n / top * 100, 1 if n else 0):.1f}%"></div>'
            for label, n in months
        )
        labels = "".join(f"<span>{label}</span>" for label, _ in months)
        since, today = usage["since"], usage["today"]
        content = f"""
<header class="page-head"><div><h2>Usage</h2><p>Tool calls across every endpoint and device, from the audit log.</p></div></header>
<div class="tiles">
 <div class="panel pad stack gap2"><span class="sm muted">Tool calls this month</span><span class="big">{usage["this_month"]:,}</span>
 <span class="small faint">{since:%b} 1 – {today:%b} {today.day}</span></div>
 <div class="panel pad stack gap2"><span class="sm muted">Daily average</span><span class="big">{usage["daily_average"]:,}</span>
 <span class="small faint">Calls so far this month ÷ days elapsed</span></div>
</div>
<div class="panel pad stack gap6">
 <div><div class="panel-title">Calls over time</div><div class="sm muted">Last 6 months, grouped by month</div></div>
 <div class="chart"><div class="yaxis"><span>{top:,}</span><span>{top // 2:,}</span><span>0</span></div>
 <div class="bars">{bars}</div><span></span><div class="xaxis">{labels}</div></div>
</div>"""
        return self._screen(request, session, "usage", content)

    # ----------------------------------------------------------- settings

    def _settings_page(
        self, request: Request, session: dict[str, Any], *, notice: str = "", error: str = "", status: int = 200,
        open_passphrase: bool = False, theme: str | None = None,
    ) -> Response:
        minutes = max(1, round((session["expires_at"] - time.time()) / 60))
        theme = theme or self._theme_of(request)
        seg = "".join(
            f'<button name="theme" value="{v}" aria-pressed="{"true" if v == theme else "false"}">{label}</button>'
            for v, label in (("dark", "Dark"), ("light", "Light"))
        )
        n = MIN_PASSPHRASE_LENGTH
        content = f"""
<header class="page-head"><div><h2>Settings</h2><p>Account and appearance.</p></div></header>
<div class="stack gap4">
<div class="panel pad row"><span class="avatar lg">{icon("user")}</span>
 <div class="grow stack" style="gap:2px"><span class="strong" style="font-size:14px">Gateway owner</span>
 <span class="small faint">Sessions end after 15 minutes · about {minutes} more minute{"s" if minutes != 1 else ""}</span></div>
 <form method="post" action="/devices/logout">{self._csrf(session)}<button class="btn btn-secondary">Sign out</button></form></div>
<details class="panel"{" open" if open_passphrase else ""}><summary class="row pad">
 <div class="grow stack" style="gap:2px"><span class="strong" style="font-size:14px">Owner passphrase</span>
 <span class="sm muted">Changing it needs your current passphrase and an authenticator code.</span></div>
 <span class="btn btn-secondary">Change passphrase</span></summary>
 <form method="post" action="/devices/passphrase" class="stack gap4" style="padding:0 var(--space-6) var(--space-6)">{self._csrf(session)}
 <div class="field"><label for="cur">Current passphrase</label>
 <input class="input" id="cur" type="password" name="current" autocomplete="current-password" required></div>
 <div class="field"><label for="tc">Authenticator code</label>
 <input class="input mono" id="tc" name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" required></div>
 <div class="field"><label for="np">New passphrase ({n}+ characters)</label>
 <input class="input" id="np" type="password" name="new" autocomplete="new-password" minlength="{n}" required></div>
 <div class="field"><label for="rp">Repeat new passphrase</label>
 <input class="input" id="rp" type="password" name="repeat" autocomplete="new-password" minlength="{n}" required></div>
 <div class="row wrap"><span class="small faint grow">Other dashboard sessions are signed out. The same passphrase
 approves assistants and devices.</span><button class="btn btn-primary">Change passphrase</button></div>
 </form></details>
<div class="panel pad row wrap"><div class="grow stack" style="gap:2px"><span class="strong" style="font-size:14px">Appearance</span>
 <span class="sm muted">Match the rest of your tooling.</span></div>
 <form method="post" action="/devices/theme" class="seg">{self._csrf(session)}{seg}</form></div>
</div>"""
        return self._screen(request, session, "settings", content, notice=notice, error=error, status=status)

    async def _settings(self, request: Request) -> Response:
        session = self._session(request)
        if session is None:
            return self._signed_out()
        return self._settings_page(request, session)

    async def _passphrase(self, request: Request) -> Response:
        session, form = await self._authorized_form(request)
        if session is None:
            return self._signed_out()
        new, repeat = str(form.get("new", "")), str(form.get("repeat", ""))
        if len(new) < MIN_PASSPHRASE_LENGTH:
            return self._settings_page(
                request, session, error=f"The new passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters.",
                status=400, open_passphrase=True,
            )
        if new != repeat:
            return self._settings_page(
                request, session, error="The new passphrases do not match.", status=400, open_passphrase=True
            )
        address = self._client_address(request)
        failure = self.store.verify_owner(str(form.get("current", "")), str(form.get("totp", "")), client=address)
        if failure is not None:
            self._log("owner_passphrase_change_failed", reason=failure, peer=address)
            locked = failure == "locked"
            return self._settings_page(
                request, session, status=429 if locked else 401, open_passphrase=True,
                error="Too many failed attempts. Try again later." if locked
                else "Wrong current passphrase or authenticator code.",
            )
        try:
            self.store.change_passphrase(new)
        except OAuthStateError as exc:
            return self._settings_page(request, session, error=str(exc), status=409)
        self._sessions = {k: v for k, v in self._sessions.items() if v is session}
        self._log("owner_passphrase_changed", peer=address, via="dashboard")
        return self._settings_page(request, session, notice="Passphrase changed. Other sessions were signed out.")

    async def _theme(self, request: Request) -> Response:
        session, form = await self._authorized_form(request)
        if session is None:
            return self._signed_out()
        theme = "light" if form.get("theme") == "light" else "dark"
        response = RedirectResponse("/devices/settings", status_code=303)
        response.set_cookie(
            THEME_COOKIE, theme, max_age=365 * 86400, path="/", secure=self._secure, httponly=True, samesite="strict",
        )
        return response
