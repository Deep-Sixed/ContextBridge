"""Browser activation of new devices: no enrollment code to copy, no SSH to the gateway.

Modeled on the OAuth 2.0 Device Authorization Grant (RFC 8628):

1. The installer generates the device key and calls ``POST /activate/start`` with the
   device name, its public key, and host details. It gets back a secret ``device_code``
   and a short ``user_code`` such as ``WXYZ-1234``.
2. It tells the person at the machine: open ``<public_url>/activate`` and enter the code.
3. The owner signs in there with the passphrase and an authenticator code, checks the
   name, host, and key fingerprint, picks the device's permissions, and approves.
   Approval registers the device and its public key in the device registry.
4. Meanwhile the installer polls ``POST /activate/poll`` with the ``device_code``; once
   approved it receives the device id and stores its identity, then connects as usual.

The device key never leaves the machine and is bound to the approval, so whoever holds
the user code alone cannot enroll anything. Pending activations live in memory only:
they expire after ten minutes, at most ``MAX_ACTIVATIONS`` exist at once, and each client
address may start a few per window. Approval shares the consent page's owner lockout.
"""

from __future__ import annotations

import base64
import hashlib
import html
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from ..computer.audit import AuditError, ComputerAuditLog
from ..computer.scopes import ALL_SCOPES, SCOPE_READ
from ..remote.registry import DeviceRegistry, RegistryError, load_public_key, validate_name
from .store import OAuthStore

ACTIVATION_SECONDS = 600
POLL_SECONDS = 5
MAX_ACTIVATIONS = 20
MAX_STARTS_PER_ADDRESS = 5
START_WINDOW_SECONDS = 600
# RFC 8628 section 6.1: consonants only, so a code cannot spell words and is easy to read aloud.
USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"
_INFO_KEYS = ("hostname", "platform", "agent_version", "python")
# Installers served at /install/<name>, with this gateway's addresses filled in (see installers/).
INSTALLERS = {
    "remote-linux.sh": "text/x-shellscript",
    "remote-windows.ps1": "text/plain",
    "ContextBridgeSetup.cmd": "application/octet-stream",
}
_MAX_INFO_CHARS = 120


def key_fingerprint(public_key: str) -> str:
    """A short, human-comparable fingerprint of a device's base64 Ed25519 public key."""
    digest = hashlib.sha256(base64.b64decode(public_key)).hexdigest()[:24]
    return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))


def new_user_code() -> str:
    raw = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def normalize_user_code(code: str) -> str:
    raw = "".join(ch for ch in code.upper() if ch.isalnum())
    return f"{raw[:4]}-{raw[4:]}" if len(raw) == 8 else raw


def _hash(device_code: str) -> str:
    return hashlib.sha256(device_code.encode("utf-8")).hexdigest()


@dataclass
class Activation:
    device_code_hash: str
    user_code: str
    name: str
    public_key: str
    info: dict[str, str]
    expires_at: float
    address: str | None
    form_token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    status: str = "pending"  # pending | approved | denied
    result: dict[str, Any] = field(default_factory=dict)
    last_poll: float = 0.0


class ActivationBroker:
    def __init__(
        self,
        *,
        public_url: str,
        registry: DeviceRegistry,
        store: OAuthStore,
        audit: ComputerAuditLog,
        agents_url: str | None = None,
        client_address: Callable[[Request], str | None] = lambda request: None,
        page: Callable[..., Response],
        scope_descriptions: dict[str, str],
    ) -> None:
        self.public_url = public_url.rstrip("/")
        self.registry = registry
        self.store = store
        self.audit = audit
        self.agents_url = agents_url
        self._client_address = client_address
        self._page = page
        self._scope_descriptions = scope_descriptions
        self._activations: dict[str, Activation] = {}  # by device_code hash
        self._starts: dict[str | None, list[float]] = {}

    # ------------------------------------------------------------ helpers

    def _log(self, event: str, **fields: Any) -> None:
        try:
            self.audit.record(event, **fields)
        except AuditError:
            pass  # bookkeeping events are best effort, as on the consent page

    def _expire(self) -> None:
        now = time.time()
        for key in [k for k, a in self._activations.items() if a.expires_at <= now]:
            activation = self._activations.pop(key)
            if activation.status == "pending":
                self._log("device_activation_expired", device=activation.name, user_code=activation.user_code)
        window = now - START_WINDOW_SECONDS
        self._starts = {k: kept for k, v in self._starts.items() if (kept := [t for t in v if t > window])}

    def _by_user_code(self, user_code: str) -> Activation | None:
        wanted = normalize_user_code(user_code)
        for activation in self._activations.values():
            if activation.status == "pending" and secrets.compare_digest(activation.user_code, wanted):
                return activation
        return None

    def routes(self) -> list[Route]:
        return [
            Route("/activate/start", self._start, methods=["POST"]),
            Route("/activate/poll", self._poll, methods=["POST"]),
            Route("/activate", self._activate_page, methods=["GET", "POST"]),
            Route("/install/{name}", self._installer, methods=["GET"]),
        ]

    # ------------------------------------------------------------ installers

    def installer_text(self, name: str) -> str | None:
        """An installer script with this gateway's public and agent addresses filled in, or None."""
        if name not in INSTALLERS:
            return None
        text = resources.files(__package__).joinpath("installers", name).read_text(encoding="utf-8")
        text = text.replace("__CONTEXTBRIDGE_SERVER__", self.public_url)
        if self.agents_url:
            text = text.replace("__CONTEXTBRIDGE_AGENTS_URL__", self.agents_url)
        return text

    async def _installer(self, request: Request) -> Response:
        name = request.path_params["name"]
        text = self.installer_text(name)
        if text is None:
            return PlainTextResponse("Not found\n", status_code=404)
        headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
        if name.endswith(".cmd"):
            headers["Content-Disposition"] = f'attachment; filename="{name}"'
        return PlainTextResponse(text, media_type=INSTALLERS[name], headers=headers)

    # ------------------------------------------------- installer endpoints

    async def _json(self, request: Request) -> dict[str, Any] | None:
        try:
            body = await request.json()
        except ValueError:
            return None
        return body if isinstance(body, dict) else None

    async def _start(self, request: Request) -> Response:
        body = await self._json(request)
        if body is None:
            return JSONResponse({"error": "invalid_request", "message": "expected a JSON object"}, status_code=400)
        self._expire()
        address = self._client_address(request)
        if address is not None and len(self._starts.get(address, [])) >= MAX_STARTS_PER_ADDRESS:
            return JSONResponse(
                {"error": "slow_down", "message": "too many activations from this address; try again later"},
                status_code=429,
            )
        if len(self._activations) >= MAX_ACTIVATIONS:
            return JSONResponse(
                {"error": "slow_down", "message": "too many activations are waiting; try again later"},
                status_code=429,
            )
        name = body.get("name")
        public_key = body.get("public_key")
        try:
            validate_name(name)
            load_public_key(public_key if isinstance(public_key, str) else "")
        except RegistryError as exc:
            return JSONResponse({"error": "invalid_request", "message": str(exc)}, status_code=400)
        if self.registry.name_taken(name) or any(a.name == name for a in self._activations.values()):
            return JSONResponse(
                {"error": "name_taken", "message": f"a device named {name!r} is already enrolled or waiting"},
                status_code=409,
            )
        raw_info = body.get("info") if isinstance(body.get("info"), dict) else {}
        info = {k: str(raw_info[k])[:_MAX_INFO_CHARS] for k in _INFO_KEYS if k in raw_info}

        device_code = secrets.token_urlsafe(32)
        user_code = new_user_code()
        while self._by_user_code(user_code) is not None:
            user_code = new_user_code()
        activation = Activation(
            device_code_hash=_hash(device_code),
            user_code=user_code,
            name=name,
            public_key=public_key,
            info=info,
            expires_at=time.time() + ACTIVATION_SECONDS,
            address=address,
        )
        self._activations[activation.device_code_hash] = activation
        if address is not None:
            self._starts.setdefault(address, []).append(time.time())
        self._log(
            "device_activation_started", device=name, user_code=user_code, peer=address,
            fingerprint=key_fingerprint(public_key), host=info.get("hostname"),
        )
        verification_uri = f"{self.public_url}/activate"
        return JSONResponse(
            {
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": verification_uri,
                "verification_uri_complete": f"{verification_uri}?code={user_code}",
                "expires_in": ACTIVATION_SECONDS,
                "interval": POLL_SECONDS,
                "fingerprint": key_fingerprint(public_key),
            }
        )

    async def _poll(self, request: Request) -> Response:
        body = await self._json(request)
        device_code = body.get("device_code") if body else None
        if not isinstance(device_code, str):
            return JSONResponse({"error": "invalid_request", "message": "device_code is required"}, status_code=400)
        self._expire()
        key = _hash(device_code)
        activation = self._activations.get(key)
        if activation is None:
            return JSONResponse({"status": "expired"})
        if activation.status == "denied":
            del self._activations[key]
            return JSONResponse({"status": "denied"})
        if activation.status == "approved":
            del self._activations[key]  # delivered once
            return JSONResponse({"status": "approved", **activation.result})
        now = time.time()
        too_fast = now - activation.last_poll < POLL_SECONDS / 2
        activation.last_poll = now
        return JSONResponse({"status": "slow_down" if too_fast else "pending", "interval": POLL_SECONDS})

    # ------------------------------------------------------- owner page

    async def _activate_page(self, request: Request) -> Response:
        self._expire()
        if request.method == "GET":
            return self._code_form(code=request.query_params.get("code", ""))

        form = await request.form()
        user_code = str(form.get("user_code", ""))
        activation = self._by_user_code(user_code)
        action = form.get("action")
        if action == "lookup":
            if activation is None:
                return self._code_form(
                    code=user_code, error="That code is not valid or has expired. Check the installer window.",
                    status=404,
                )
            return self._approval_form(activation)

        if activation is None:
            return self._page("This activation has expired. Run the installer again.", status=400)
        if not secrets.compare_digest(str(form.get("form_token", "")), activation.form_token):
            return self._page("Invalid form submission.", status=400)
        if action == "deny":
            activation.status = "denied"
            self._log("device_activation_denied", device=activation.name, user_code=activation.user_code)
            return self._page(f"Denied. {activation.name} was not added.")

        address = self._client_address(request)
        failure = self.store.verify_owner(str(form.get("passphrase", "")), str(form.get("totp", "")), client=address)
        if failure is not None:
            self._log("device_activation_failed", device=activation.name, reason=failure, peer=address)
            if failure == "locked":
                minutes = max(1, round((self.store.locked_until(address) - time.time()) / 60))
                return self._page(f"Too many failed attempts. Approval is locked for about {minutes} minutes.", status=429)
            return self._approval_form(activation, error="Wrong passphrase or authenticator code.", status=401)
        scopes = [s for s in ALL_SCOPES if s in form.getlist("scope")]
        if not scopes:
            return self._approval_form(activation, error="Choose at least one permission.", status=400)
        try:
            record = self.registry.register(activation.name, activation.public_key, scopes, activation.info)
        except RegistryError as exc:
            return self._approval_form(activation, error=f"Cannot add this device: {exc}.", status=409)
        activation.status = "approved"
        activation.result = {
            "device_id": record.device_id,
            "name": record.name,
            "gateway_id": self.registry.gateway_id,
            "scopes": scopes,
            **({"agents_url": self.agents_url} if self.agents_url else {}),
        }
        self._log(
            "device_enrolled", device=record.name, device_id=record.device_id, scopes=scopes, via="activation",
            peer=activation.address, fingerprint=key_fingerprint(activation.public_key),
        )
        return self._page(
            f"Approved. {record.name} is being added; the installer on that machine will finish on its own."
        )

    def _code_form(self, *, code: str = "", error: str = "", status: int = 200) -> Response:
        body = f"""
<h1>Activate a device</h1>
<p>Enter the code the ContextBridge installer is showing.</p>
{f'<p class="error">{html.escape(error)}</p>' if error else ""}
<form method="post" action="/activate">
<label>Code <input name="user_code" value="{html.escape(normalize_user_code(code))}" autocomplete="off"
 autocapitalize="characters" spellcheck="false" required></label>
<button name="action" value="lookup">Continue</button>
</form>"""
        return self._page(body, status=status, raw=True)

    def _approval_form(self, activation: Activation, *, error: str = "", status: int = 200) -> Response:
        scope_rows = "".join(
            f'<label><input type="checkbox" name="scope" value="{html.escape(s)}"'
            f'{" checked" if s == SCOPE_READ else ""}> <code>{html.escape(s)}</code> — '
            f"{html.escape(self._scope_descriptions.get(s, s))}</label>"
            for s in ALL_SCOPES
        )
        info = activation.info
        details = "".join(
            f"<tr><th>{html.escape(label)}</th><td>{html.escape(value)}</td></tr>"
            for label, value in (
                ("Device name", activation.name),
                ("Computer", info.get("hostname", "unknown")),
                ("System", info.get("platform", "unknown")),
                ("Agent version", info.get("agent_version", "unknown")),
                ("Key fingerprint", key_fingerprint(activation.public_key)),
                ("Requested from", activation.address or "unknown"),
            )
        )
        minutes = max(1, round((activation.expires_at - time.time()) / 60))
        body = f"""
<h1>Add this device?</h1>
<p>A ContextBridge installer asked to add a device. Approve only if you started it yourself
and the fingerprint matches the one the installer shows. This request expires in about {minutes} minutes.</p>
{f'<p class="error">{html.escape(error)}</p>' if error else ""}
<table>{details}</table>
<form method="post" action="/activate">
<input type="hidden" name="user_code" value="{html.escape(activation.user_code)}">
<input type="hidden" name="form_token" value="{html.escape(activation.form_token)}">
<fieldset><legend>What assistants may do on this device</legend>{scope_rows}
<p class="small">The device's own settings can narrow this further. Each assistant's access is chosen
separately when it signs in.</p></fieldset>
<fieldset><legend>Confirm it is you</legend>
<label>Passphrase <input type="password" name="passphrase" autocomplete="current-password" required></label>
<label>Authenticator code <input name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" required></label>
</fieldset>
<button name="action" value="approve">Approve</button>
<button name="action" value="deny" formnovalidate>Deny</button>
</form>"""
        return self._page(body, status=status, raw=True)
