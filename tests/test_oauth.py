"""Phase 5: the OAuth-protected remote MCP endpoint (ChatGPT, Claude, other remote clients)."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import anyio
import httpx
import pytest
import yaml
from fastmcp import Client
from fastmcp.exceptions import ToolError
from helpers import IS_WINDOWS, call, cli, free_port, isolated_env, read_log, serve

from contextbridge.computer.audit import ComputerAuditLog
from contextbridge.computer.dispatch import available_tools
from contextbridge.computer.server import (
    ALL_SCOPES,
    LIST_DEVICES_TOOL,
    SCOPE_EXECUTE,
    SCOPE_READ,
    SCOPE_WRITE,
    TOOL_SCOPES,
    AuthorizationError,
    RemoteListenerConfig,
    build_router,
    create_computer_server,
)
from contextbridge.computer.server import main as computer_main
from contextbridge.oauth import totp
from contextbridge.oauth.google import AUTH_ENDPOINT, TOKEN_ENDPOINT, GoogleLogin, GoogleSettings
from contextbridge.oauth.provider import RemoteSettings
from contextbridge.oauth.remote import create_remote_server
from contextbridge.oauth.store import (
    MAX_CLIENTS,
    OAuthStateError,
    OAuthStore,
    token_hash,
)
from contextbridge.remote.admin import main as admin_main

PASSPHRASE = "correct horse battery staple"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PUBLIC = "http://127.0.0.1:8793"
COMPUTER_TOKEN = "computer-" + "c" * 40


def next_code(store: OAuthStore) -> str:
    """A valid TOTP code the store has not accepted yet (codes are single use)."""
    owner = store.state["owner"]
    counter = max(owner["totp_last_counter"] + 1, totp.counter_at())
    assert counter <= totp.counter_at() + 1, "more consents in one 30 s step than the test can mint"
    return totp.code_at(owner["totp_secret"], counter)


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def form_fields(html: str) -> dict[str, str]:
    return dict(re.findall(r'name="(request|form_token)" value="([^"]+)"', html))


# ------------------------------------------------------------------ TOTP


RFC6238_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.mark.parametrize(
    ("when", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_totp_matches_rfc6238_vectors(when, expected):
    assert totp.code_at(RFC6238_SECRET, totp.counter_at(when), digits=8) == expected


def test_totp_accepts_one_step_of_drift_and_never_the_same_step_twice():
    secret = totp.new_secret()
    now = 1_700_000_000
    step = totp.counter_at(now)
    assert totp.verify(secret, totp.code_at(secret, step - 1), last_counter=0, when=now) == step - 1
    assert totp.verify(secret, totp.code_at(secret, step + 1), last_counter=0, when=now) == step + 1
    assert totp.verify(secret, totp.code_at(secret, step - 2), last_counter=0, when=now) is None
    assert totp.verify(secret, totp.code_at(secret, step), last_counter=step, when=now) is None  # replay
    assert totp.verify(secret, "12345a", last_counter=0, when=now) is None
    assert totp.verify(secret, "", last_counter=0, when=now) is None
    assert "secret=" + secret in totp.provisioning_uri(secret, account="friday")


# ----------------------------------------------------------------- store


@pytest.fixture
def store(tmp_path: Path) -> OAuthStore:
    store = OAuthStore(tmp_path / "state" / "oauth.json")
    store.set_owner(PASSPHRASE, totp.new_secret())
    return store


def test_owner_needs_passphrase_and_fresh_totp(store):
    assert store.owner_initialized()
    code = next_code(store)
    assert store.verify_owner("wrong passphrase!", code) == "bad_credentials"
    assert store.verify_owner(PASSPHRASE, "000000" if code != "000000" else "111111") == "bad_credentials"
    assert store.verify_owner(PASSPHRASE, code) is None
    assert store.verify_owner(PASSPHRASE, code) == "bad_credentials"  # the same code cannot approve twice


def test_short_passphrase_is_refused(tmp_path):
    with pytest.raises(OAuthStateError, match="at least 12"):
        OAuthStore(tmp_path / "oauth.json").set_owner("short", totp.new_secret())


def test_repeated_failures_lock_consent_until_unlocked(store):
    for _ in range(4):
        assert store.verify_owner("nope", "000000") == "bad_credentials"
    assert store.verify_owner("nope", "000000") == "locked"
    assert store.locked_until() > time.time() + 14 * 60
    assert store.verify_owner(PASSPHRASE, next_code(store)) == "locked"  # even the right credentials
    store.unlock()
    assert store.verify_owner(PASSPHRASE, next_code(store)) is None


def test_google_mode_checks_totp_alone_and_pins_the_first_account(store):
    code = next_code(store)
    assert store.verify_totp(code) is None
    assert store.verify_totp(code) == "bad_totp"  # single use, as with the passphrase
    assert store.state["lockout"]["failures"]  # kept until a Google sign-in completes the approval

    assert store.verify_google_owner("owner@example.com", "sub-1") == (None, True)
    assert not store.state["lockout"]["failures"]
    assert store.verify_google_owner("owner@example.com", "sub-1") == (None, False)
    assert store.verify_google_owner("owner@example.com", "sub-2") == ("google_account_changed", False)
    assert store.verify_google_owner("new@example.com", "sub-2") == (None, True)  # owner_email changed in config

    store.set_owner(PASSPHRASE, totp.new_secret())  # owner-init --force clears the pin
    assert "google" not in store.state["owner"]


def test_google_failures_count_toward_the_lockout(store):
    for _ in range(4):
        assert store.record_failure("wrong_google_account") == "wrong_google_account"
    assert store.record_failure("wrong_google_account") == "locked"
    assert store.verify_totp(next_code(store)) == "locked"
    assert store.verify_google_owner("owner@example.com", "sub-1") == ("locked", False)


def _grant(store: OAuthStore, client_id: str = "c1") -> tuple[str, str, str]:
    store.save_client({"client_id": client_id, "redirect_uris": [REDIRECT]})
    code = "code-" + secrets.token_hex(8)
    store.save_code(code, {"client_id": client_id, "expires_at": time.time() + 60})
    return store.create_grant(
        client_id=client_id,
        scopes=[SCOPE_READ],
        devices=["local"],
        resource=PUBLIC + "/mcp",
        code=code,
        access_seconds=60,
        refresh_seconds=600,
    )


def test_grant_lifecycle_rotation_and_reuse(store):
    grant_id, access, refresh = _grant(store)
    assert store.find_access(access)[0] == grant_id
    assert store.find_refresh(refresh) == (grant_id, store.state["grants"][grant_id], False)

    access2, refresh2 = store.rotate(grant_id, refresh, scopes=[SCOPE_READ], access_seconds=60, refresh_seconds=600)
    assert store.find_refresh(refresh)[2] is True  # rotated token is recognised as reuse
    assert store.find_refresh(refresh2)[2] is False
    with pytest.raises(OAuthStateError):
        store.rotate(grant_id, refresh, scopes=[SCOPE_READ], access_seconds=60, refresh_seconds=600)

    store.revoke_grant(grant_id)
    assert store.find_access(access) is None and store.find_access(access2) is None
    assert store.find_refresh(refresh2) is None


def test_codes_are_single_use(store):
    store.save_client({"client_id": "c1", "redirect_uris": [REDIRECT]})
    store.save_code("abc", {"client_id": "c1", "expires_at": time.time() + 60})
    kwargs = {
        "client_id": "c1",
        "scopes": [SCOPE_READ],
        "devices": ["local"],
        "resource": None,
        "access_seconds": 60,
        "refresh_seconds": 60,
    }
    store.create_grant(code="abc", **kwargs)
    with pytest.raises(OAuthStateError, match="already used"):
        store.create_grant(code="abc", **kwargs)


def test_state_holds_no_reusable_secret_and_is_private(store):
    _, access, refresh = _grant(store)
    raw = store.path.read_text(encoding="utf-8")
    assert access not in raw and refresh not in raw and PASSPHRASE not in raw
    assert token_hash(access) in raw
    if not IS_WINDOWS:
        assert oct(store.path.stat().st_mode & 0o777) == "0o600"
    assert not store.temp_path.exists()


def test_a_revocation_by_another_process_applies_immediately(store):
    _, access, _ = _grant(store)
    assert store.find_access(access) is not None
    cli_view = OAuthStore(store.path)  # e.g. contextbridge-admin oauth-revoke
    assert cli_view.revoke_client("c1") == 1
    assert store.find_access(access) is None


def test_full_client_table_evicts_unapproved_clients_first(store):
    for i in range(MAX_CLIENTS):
        store.save_client({"client_id": f"c{i}", "redirect_uris": [REDIRECT]})
    store.save_code("x", {"client_id": "c1", "expires_at": time.time() + 60})  # c1 is approved
    store.save_client({"client_id": "new", "redirect_uris": [REDIRECT]})
    ids = {c["client_id"] for c in store.clients()}
    assert "new" in ids and "c1" in ids and "c0" not in ids and len(ids) == MAX_CLIENTS


# ------------------------------------------------- per-device authorization


def test_device_grant_limits_tools_and_listing(policy, tmp_path):
    audit = ComputerAuditLog(tmp_path / "audit.jsonl", echo=False)

    def authorize(tool: str) -> str:
        if TOOL_SCOPES[tool] != SCOPE_READ:
            raise AuthorizationError("no")
        return "remote-client"

    async def scenario(granted):
        server = create_computer_server(policy, audit=audit, authorize=authorize, devices=lambda: granted)
        async with Client(server) as client:
            tools = {t.name for t in await client.list_tools()}
            devices = (await client.call_tool(LIST_DEVICES_TOOL, {})).structured_content["devices"]
            try:
                await client.call_tool("read_file", {"path": "docs/notes.md"})
                read = "ok"
            except ToolError as exc:
                read = str(exc)
            return tools, [d["device"] for d in devices], read

    tools, devices, read = anyio.run(scenario, frozenset({"local"}))
    assert tools == {t for t in available_tools(policy) if TOOL_SCOPES[t] == SCOPE_READ} | {LIST_DEVICES_TOOL}
    assert devices == ["local"] and read == "ok"

    tools, devices, read = anyio.run(scenario, frozenset({"thanatos"}))
    assert tools == {LIST_DEVICES_TOOL} and devices == [] and "not authorized for device 'local'" in read


# --------------------------------------------- authorization server (ASGI)


def _remote_app(policy, tmp_path: Path, store: OAuthStore, *, google=None) -> SimpleNamespace:
    audit_path = tmp_path / "audit.jsonl"
    audit = ComputerAuditLog(audit_path, echo=False)
    settings = RemoteSettings(
        public_url=PUBLIC,
        allow_scopes=(SCOPE_READ, SCOPE_WRITE),
        allow_devices=("local",),
        allowed_redirect_hosts=("claude.ai", "localhost"),
        google=google,
    )
    server = create_remote_server(build_router(policy, audit=audit), audit=audit, settings=settings, store=store)
    fake_google = None
    if google is not None:
        fake_google = FakeGoogle()
        server.auth.google = GoogleLogin(
            google, server.auth.google.redirect_uri, transport=httpx.MockTransport(fake_google.handler)
        )
    app = server.http_app()

    async def client() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=PUBLIC)

    return SimpleNamespace(client=client, store=store, audit_path=audit_path, google=fake_google)


@pytest.fixture
def remote(policy, tmp_path, store):
    return _remote_app(policy, tmp_path, store)


async def register(http: httpx.AsyncClient, *, redirect: str = REDIRECT, name: str = "Claude", **extra) -> httpx.Response:
    body = {
        "redirect_uris": [redirect],
        "client_name": name,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        **extra,
    }
    return await http.post("/register", json=body)


async def start_authorization(http: httpx.AsyncClient, client_id: str, *, scope: str | None = None, state="s1"):
    verifier, challenge = pkce()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "resource": PUBLIC + "/mcp",
    }
    if scope:
        params["scope"] = scope
    response = await http.get("/authorize", params=params)
    assert response.status_code == 302, response.text
    consent = urlsplit(response.headers["location"])
    assert consent.path == "/consent"
    page = await http.get(f"/consent?{consent.query}")
    return verifier, page


async def approve(http, page, store, *, scopes=(SCOPE_READ,), devices=("local",), passphrase=PASSPHRASE, code=None):
    data = {
        **form_fields(page.text),
        "scope": list(scopes),
        "device": list(devices),
        "passphrase": passphrase,
        "totp": code or next_code(store),
        "action": "approve",
    }
    return await http.post("/consent", data=data)


async def exchange(http, client_id: str, verifier: str, code: str) -> httpx.Response:
    return await http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": PUBLIC + "/mcp",
        },
    )


def test_discovery_metadata_points_at_this_server(remote):
    async def scenario():
        async with await remote.client() as http:
            server = (await http.get("/.well-known/oauth-authorization-server")).json()
            resource = (await http.get("/.well-known/oauth-protected-resource/mcp")).json()
            unauthenticated = await http.post("/mcp", json={})
            return server, resource, unauthenticated

    server, resource, unauthenticated = anyio.run(scenario)
    assert server["issuer"].rstrip("/") == PUBLIC
    assert server["authorization_endpoint"] == PUBLIC + "/authorize"
    assert server["registration_endpoint"] == PUBLIC + "/register"
    assert server["code_challenge_methods_supported"] == ["S256"]
    assert resource["resource"] == PUBLIC + "/mcp"
    assert set(resource["scopes_supported"]) == set(ALL_SCOPES)
    assert unauthenticated.status_code == 401
    assert "resource_metadata=" in unauthenticated.headers["www-authenticate"]


@pytest.mark.parametrize(
    "redirect", ["https://evil.example/callback", "http://claude.ai/callback", "https://claude.ai.evil.example/cb"]
)
def test_registration_only_for_allowed_https_redirects(remote, redirect):
    async def scenario():
        async with await remote.client() as http:
            return await register(http, redirect=redirect)

    response = anyio.run(scenario)
    assert response.status_code == 400 and response.json()["error"] == "invalid_redirect_uri"
    assert remote.store.clients() == []


def test_consent_flow_issues_tokens_limited_to_approved_scopes_and_devices(remote):
    async def scenario():
        async with await remote.client() as http:
            client_id = (await register(http, name="<script>alert(1)</script>")).json()["client_id"]
            verifier, page = await start_authorization(http, client_id, scope=" ".join(ALL_SCOPES))
            wrong = await approve(http, page, remote.store, code="12345x")
            # execute is not allowed remotely and thanatos is not offered: both are dropped silently.
            granted = await approve(
                http, page, remote.store, scopes=(SCOPE_READ, SCOPE_EXECUTE), devices=("local", "thanatos")
            )
            location = urlsplit(granted.headers["location"])
            query = parse_qs(location.query)
            bad_pkce = await exchange(http, client_id, "x" * 50, query["code"][0])
            tokens = await exchange(http, client_id, verifier, query["code"][0])
            replay = await exchange(http, client_id, verifier, query["code"][0])
            return page, wrong, granted, location, query, bad_pkce, tokens, replay

    page, wrong, granted, location, query, bad_pkce, tokens, replay = anyio.run(scenario)
    assert page.status_code == 200
    assert "&lt;script&gt;" in page.text and "<script>" not in page.text
    csp = page.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "default-src 'none'" in csp and "https://claude.ai" in csp
    assert page.headers["x-frame-options"] == "DENY" and page.headers["cache-control"] == "no-store"
    assert 'value="computer:execute"' not in page.text  # not offered: outside remote.allow_scopes
    assert re.search(r'value="computer:read" checked', page.text)
    assert not re.search(r'value="computer:write" checked', page.text)  # more than read is a deliberate tick

    assert wrong.status_code == 401 and "Wrong passphrase or authenticator code" in wrong.text
    assert granted.status_code == 302
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT
    assert query["state"] == ["s1"]
    assert bad_pkce.json()["error"] == "invalid_grant"  # FastMCP answers 401 for invalid_grant
    assert tokens.status_code == 200, tokens.text
    body = tokens.json()
    assert body["scope"] == SCOPE_READ and body["refresh_token"] and body["expires_in"] == 3600
    assert replay.json()["error"] == "invalid_grant"

    (grant,) = remote.store.state["grants"].values()
    assert grant["scopes"] == [SCOPE_READ] and grant["devices"] == ["local"]
    events = [json.loads(line)["event"] for line in remote.audit_path.read_text().splitlines()]
    for event in ("oauth_client_registered", "oauth_authorization_requested", "oauth_consent_failed",
                  "oauth_consent_granted", "oauth_token_issued"):
        assert event in events


def test_owner_can_deny(remote):
    async def scenario():
        async with await remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            _, page = await start_authorization(http, client_id)
            return await http.post("/consent", data={**form_fields(page.text), "action": "deny"})

    response = anyio.run(scenario)
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert response.status_code == 302 and query["error"] == ["access_denied"] and "code" not in query


def test_consent_requires_the_form_token_and_a_live_request(remote):
    async def scenario():
        async with await remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            _, page = await start_authorization(http, client_id)
            fields = form_fields(page.text)
            forged = await http.post("/consent", data={**fields, "form_token": "forged", "action": "deny"})
            unknown = await http.get("/consent?request=nope")
            empty = await approve(http, page, remote.store, scopes=(), devices=("local",))
            return forged, unknown, empty

    forged, unknown, empty = anyio.run(scenario)
    assert forged.status_code == 400 and unknown.status_code == 400
    assert empty.status_code == 400 and "at least one permission and one device" in empty.text


def test_consent_locks_after_repeated_failures(remote):
    async def scenario():
        async with await remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            _, page = await start_authorization(http, client_id)
            statuses = [
                (await approve(http, page, remote.store, passphrase="guess " * 3, code="123456")).status_code
                for _ in range(5)
            ]
            locked = await approve(http, page, remote.store)
            return statuses, locked

    statuses, locked = anyio.run(scenario)
    assert statuses == [401, 401, 401, 401, 429]
    assert locked.status_code == 429 and "locked" in locked.text


def test_refresh_rotates_and_reuse_revokes_the_grant(remote):
    async def scenario():
        async with await remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            verifier, page = await start_authorization(http, client_id)
            code = parse_qs(urlsplit((await approve(http, page, remote.store)).headers["location"]).query)["code"][0]
            first = (await exchange(http, client_id, verifier, code)).json()

            async def refresh(token):
                return await http.post(
                    "/token", data={"grant_type": "refresh_token", "refresh_token": token, "client_id": client_id}
                )

            second = await refresh(first["refresh_token"])
            reused = await refresh(first["refresh_token"])
            after = await refresh(second.json()["refresh_token"])
            return first, second, reused, after

    first, second, reused, after = anyio.run(scenario)
    assert second.status_code == 200 and second.json()["refresh_token"] != first["refresh_token"]
    assert reused.json()["error"] == after.json()["error"] == "invalid_grant"  # the whole grant is gone
    assert remote.store.find_access(second.json()["access_token"]) is None
    events = [json.loads(line)["event"] for line in remote.audit_path.read_text().splitlines()]
    assert "oauth_refresh_reuse_detected" in events


def test_tunnel_host_passes_the_guard_and_strangers_do_not(policy, tmp_path, store):
    from contextbridge.computer.server import RemoteListenerConfig

    remote_cfg = RemoteListenerConfig(
        {"port": 8793, "public_url": "https://friday.example.ts.net", "state": "oauth.json"}, tmp_path, tmp_path
    )
    options = remote_cfg.http_options()
    audit = ComputerAuditLog(tmp_path / "audit.jsonl", echo=False)
    server = create_remote_server(
        build_router(policy, audit=audit), audit=audit, settings=remote_cfg.settings(), store=store
    )
    app = server.http_app(middleware=options["middleware"])

    async def scenario():
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8793") as http:
            tunnel = {"host": "friday.example.ts.net", "origin": "https://friday.example.ts.net"}
            ok = await http.get("/.well-known/oauth-authorization-server", headers=tunnel)
            consent = await http.post("/consent", headers=tunnel, data={"request": "x"})
            rebinding = await http.get("/.well-known/oauth-authorization-server", headers={"host": "evil.example"})
            foreign = await http.post("/consent", headers={**tunnel, "origin": "https://evil.example"})
            return ok, consent, rebinding, foreign

    ok, consent, rebinding, foreign = anyio.run(scenario)
    assert options["host"] == "127.0.0.1" and options["port"] == 8793
    assert ok.status_code == 200 and ok.json()["issuer"].startswith("https://friday.example.ts.net")
    assert consent.status_code == 400  # reached the consent handler (unknown request), not the guard
    assert rebinding.status_code == 421
    assert foreign.status_code == 403


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"host": "127.0.0.1:8791"}, 200),
        ({"host": "[::1]:8791"}, 200),
        ({"host": "localhost:8791", "origin": "http://localhost:6274"}, 200),  # a local browser tool
        ({"host": "friday.example.ts.net"}, 200),
        ({"host": "FRIDAY.example.ts.net:443", "origin": "https://friday.example.ts.net"}, 200),
        ({"host": "evil.example"}, 421),
        ({"host": "127.0.0.1.evil.example"}, 421),
        ({"host": "127.0.0.1:8791", "origin": "https://evil.example"}, 403),
        ({"host": "127.0.0.1:8791", "origin": "null"}, 403),
    ],
)
def test_host_origin_guard(headers, status):
    from contextbridge.net import HostOriginGuard

    async def ok(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = HostOriginGuard(ok, hosts=["friday.example.ts.net"], origins=["https://friday.example.ts.net"])

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as http:
            return (await http.get("/", headers=headers)).status_code

    assert anyio.run(scenario) == status


# ------------------------------------------------------ Google sign-in


GOOGLE_CLIENT = "1234-test.apps.googleusercontent.com"
OWNER_EMAIL = "owner@example.com"
OWNER_SUB = "108000000000000000001"
GOOGLE = GoogleSettings(client_id=GOOGLE_CLIENT, owner_email=OWNER_EMAIL, client_secret="google-client-secret")


def _b64url(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


class FakeGoogle:
    """Google's token endpoint: checks the code exchange, then answers with an ID token.

    The test sets ``expect`` from the authorization URL (nonce, PKCE challenge) and
    ``claims`` to override what the ID token says.
    """

    def __init__(self) -> None:
        self.expect: dict[str, str] = {}
        self.claims: dict = {}
        self.status = 200
        self.exchanges: list[dict[str, list[str]]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert str(request.url) == TOKEN_ENDPOINT and request.method == "POST"
        form = parse_qs(request.content.decode())
        self.exchanges.append(form)
        if self.status != 200:
            return httpx.Response(self.status, json={"error": "server_error"})
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"][0].encode()).digest()).rstrip(b"=")
        if challenge.decode() != self.expect["challenge"] or form["code"] != ["google-code"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        now = int(time.time())
        claims = {
            "iss": "https://accounts.google.com",
            "aud": GOOGLE_CLIENT,
            "azp": GOOGLE_CLIENT,
            "sub": OWNER_SUB,
            "email": OWNER_EMAIL,
            "email_verified": True,
            "nonce": self.expect["nonce"],
            "iat": now,
            "exp": now + 3600,
            **self.claims,
        }
        id_token = f"{_b64url({'alg': 'RS256', 'kid': 'k1'})}.{_b64url(claims)}.c2ln"
        return httpx.Response(200, json={"access_token": "ya29.x", "id_token": id_token, "token_type": "Bearer"})


@pytest.fixture
def google_remote(policy, tmp_path, store):
    return _remote_app(policy, tmp_path, store, google=GOOGLE)


async def leave_for_google(http, page, store, *, code=None, scopes=(SCOPE_READ,)):
    data = {**form_fields(page.text), "scope": list(scopes), "device": ["local"], "totp": code or next_code(store),
            "action": "approve"}
    return await http.post("/consent", data=data)


async def back_from_google(http, remote, leave: httpx.Response, *, params=None, **claims) -> httpx.Response:
    """Play the owner signing in at Google: Google redirects the browser back with a code."""
    query = parse_qs(urlsplit(leave.headers["location"]).query)
    remote.google.expect = {"nonce": query["nonce"][0], "challenge": query["code_challenge"][0]}
    remote.google.claims = claims
    params = params or {"code": "google-code", "state": query["state"][0]}
    return await http.get("/consent/google", params=params)


def events(remote) -> list[dict]:
    return [json.loads(line) for line in remote.audit_path.read_text().splitlines()]


def test_google_signin_replaces_the_passphrase(google_remote):
    async def scenario():
        async with await google_remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            verifier, page = await start_authorization(http, client_id, scope=f"{SCOPE_READ} {SCOPE_WRITE}")
            leave = await leave_for_google(http, page, google_remote.store, scopes=(SCOPE_READ, SCOPE_WRITE))
            back = await back_from_google(http, google_remote, leave)
            state = parse_qs(urlsplit(leave.headers["location"]).query)["state"][0]
            replay = await http.get("/consent/google", params={"code": "google-code", "state": state})
            code = parse_qs(urlsplit(back.headers["location"]).query)["code"][0]
            tokens = await exchange(http, client_id, verifier, code)
            return page, leave, back, replay, tokens

    page, leave, back, replay, tokens = anyio.run(scenario)
    assert 'name="passphrase"' not in page.text and 'name="totp"' in page.text
    assert "Continue with Google" in page.text and OWNER_EMAIL in page.text
    form_action = page.headers["content-security-policy"].split("form-action")[1]
    assert "https://accounts.google.com" in form_action and "https://claude.ai" in form_action

    assert leave.status_code == 303
    location = urlsplit(leave.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == AUTH_ENDPOINT
    query = {k: v[0] for k, v in parse_qs(location.query).items()}
    assert query["client_id"] == GOOGLE_CLIENT and query["redirect_uri"] == PUBLIC + "/consent/google"
    assert query["response_type"] == "code" and query["scope"] == "openid email"
    assert query["code_challenge_method"] == "S256" and query["login_hint"] == OWNER_EMAIL
    assert "access_type" not in query and "prompt" not in query  # sign-in only: no refresh token from Google
    cookie = leave.headers["set-cookie"].lower()
    assert "cb_google_signin=" in cookie and "httponly" in cookie and "path=/consent/google" in cookie
    assert "samesite=lax" in cookie

    assert back.status_code == 302, back.text
    redirect = urlsplit(back.headers["location"])
    assert f"{redirect.scheme}://{redirect.netloc}{redirect.path}" == REDIRECT
    assert parse_qs(redirect.query)["state"] == ["s1"]
    assert replay.status_code == 400 and "expired or was already used" in replay.text
    assert tokens.status_code == 200 and tokens.json()["scope"] == f"{SCOPE_READ} {SCOPE_WRITE}"

    (sent,) = google_remote.google.exchanges
    assert sent["grant_type"] == ["authorization_code"] and sent["client_id"] == [GOOGLE_CLIENT]
    assert sent["client_secret"] == ["google-client-secret"] and sent["redirect_uri"] == [PUBLIC + "/consent/google"]
    assert google_remote.store.state["owner"]["google"]["sub"] == OWNER_SUB
    names = [e["event"] for e in events(google_remote)]
    for event in ("oauth_google_signin_started", "oauth_google_owner_pinned", "oauth_consent_granted"):
        assert event in names
    assert "google-client-secret" not in google_remote.audit_path.read_text()


@pytest.mark.parametrize(
    ("claims", "reason"),
    [
        ({"email": "someone.else@example.com"}, "wrong_google_account"),
        ({"email_verified": False}, "google_email_not_verified"),
        ({"aud": "another-app.apps.googleusercontent.com"}, "invalid_id_token"),
        ({"azp": "another-app.apps.googleusercontent.com"}, "invalid_id_token"),
        ({"iss": "https://accounts.example.com"}, "invalid_id_token"),
        ({"exp": 1_000_000_000}, "invalid_id_token"),
        ({"nonce": "from-another-sign-in"}, "invalid_id_token"),
    ],
)
def test_google_signin_refuses_other_accounts_and_bad_id_tokens(google_remote, claims, reason):
    async def scenario():
        async with await google_remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            _, page = await start_authorization(http, client_id)
            leave = await leave_for_google(http, page, google_remote.store)
            return await back_from_google(http, google_remote, leave, **claims)

    back = anyio.run(scenario)
    assert back.status_code == 401 and "That Google account cannot approve requests" in back.text
    assert form_fields(back.text)  # the form is shown again for another try
    assert not google_remote.store.state["grants"] and not google_remote.store.state["codes"]
    assert len(google_remote.store.state["lockout"]["failures"]) == 1  # counts toward the lockout
    assert reason in [e.get("reason") for e in events(google_remote)]


def test_a_new_google_account_at_the_owner_address_is_refused(google_remote):
    async def scenario():
        async with await google_remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            results = []
            for sub in (OWNER_SUB, "108999999999999999999"):
                _, page = await start_authorization(http, client_id)
                leave = await leave_for_google(http, page, google_remote.store)
                results.append(await back_from_google(http, google_remote, leave, sub=sub))
            return results

    first, second = anyio.run(scenario)
    assert first.status_code == 302 and second.status_code == 401
    assert google_remote.store.state["owner"]["google"]["sub"] == OWNER_SUB
    assert "google_account_changed" in [e.get("reason") for e in events(google_remote)]


def test_google_signin_needs_the_totp_code_first(google_remote):
    async def scenario():
        async with await google_remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            _, page = await start_authorization(http, client_id)
            wrong = [(await leave_for_google(http, page, google_remote.store, code="000000")).status_code
                     for _ in range(5)]
            locked = await leave_for_google(http, page, google_remote.store)
            return wrong, locked

    wrong, locked = anyio.run(scenario)
    assert wrong[:4] == [401] * 4 and wrong[4] == 429
    assert locked.status_code == 429
    assert not google_remote.google.exchanges  # never left for Google


def test_google_callback_needs_the_same_browser_and_a_live_sign_in(google_remote):
    async def scenario():
        async with await google_remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            _, page = await start_authorization(http, client_id)
            unknown = await http.get("/consent/google", params={"code": "google-code", "state": "made-up"})
            leave = await leave_for_google(http, page, google_remote.store)
            state = parse_qs(urlsplit(leave.headers["location"]).query)["state"][0]
            http.cookies.clear()  # Google's answer arrives in a browser that never saw the consent page
            other_browser = await back_from_google(http, google_remote, leave)
            again = await http.get("/consent/google", params={"code": "google-code", "state": state})
            return unknown, other_browser, again

    unknown, other_browser, again = anyio.run(scenario)
    assert unknown.status_code == 400
    assert other_browser.status_code == 400 and "browser that opened the approval page" in other_browser.text
    assert again.status_code == 400  # the sign-in was spent on the wrong browser
    assert not google_remote.google.exchanges and not google_remote.store.state["codes"]


def test_a_cancelled_google_signin_can_be_retried(google_remote):
    async def scenario():
        async with await google_remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            _, page = await start_authorization(http, client_id)
            leave = await leave_for_google(http, page, google_remote.store)
            state = parse_qs(urlsplit(leave.headers["location"]).query)["state"][0]
            cancelled = await back_from_google(http, google_remote, leave, params={"error": "access_denied", "state": state})
            failures = list(google_remote.store.state["lockout"]["failures"])
            leave = await leave_for_google(http, page, google_remote.store)
            return cancelled, failures, await back_from_google(http, google_remote, leave)

    cancelled, failures, finished = anyio.run(scenario)
    assert cancelled.status_code == 400 and "cancelled" in cancelled.text and form_fields(cancelled.text)
    assert not failures  # cancelling is not a wrong answer
    assert finished.status_code == 302


def test_google_unreachable_is_not_counted_as_a_failure(google_remote):
    async def scenario():
        async with await google_remote.client() as http:
            client_id = (await register(http)).json()["client_id"]
            _, page = await start_authorization(http, client_id)
            google_remote.google.status = 500
            leave = await leave_for_google(http, page, google_remote.store)
            return await back_from_google(http, google_remote, leave)

    down = anyio.run(scenario)
    assert down.status_code == 502 and "did not complete" in down.text and form_fields(down.text)
    assert not google_remote.store.state["lockout"]["failures"] and not google_remote.store.state["codes"]


# ------------------------------------------------------------- startup


@pytest.fixture
def remote_config(tmp_path, workspace, monkeypatch):
    monkeypatch.setenv("CONTEXTBRIDGE_COMPUTER_TOKEN", COMPUTER_TOKEN)

    def write(**remote):
        cfg = {
            "serve": {"host": "127.0.0.1", "port": 8791, "audit_log": str(tmp_path / "audit.jsonl")},
            "filesystem": {"roots": [str(workspace)]},
            "remote": {
                "enabled": True,
                "port": 8793,
                "public_url": "https://friday.example.ts.net",
                "state": str(tmp_path / "state" / "oauth.json"),
                **remote,
            },
        }
        path = tmp_path / "computer.yaml"
        path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        return str(path)

    return write


@pytest.mark.parametrize(
    ("remote", "message"),
    [
        ({}, "owner-init"),
        ({"host": "0.0.0.0"}, "remote.host must be a loopback"),
        ({"port": 8791}, "must all differ"),
        ({"public_url": "http://friday.example.ts.net"}, "public_url"),
        ({"public_url": "https://friday.example.ts.net/mcp"}, "public_url"),
        ({"allow_scopes": ["computer:root"]}, "unknown scope"),
        ({"allow_scopes": []}, "non-empty list"),
        ({"state": None}, "remote.state is required"),
        ({"refresh_token_days": 0}, "refresh_token_days"),
        ({"google": "yes"}, "remote.google must be a mapping"),
        ({"google": {"enabled": True, "owner_email": OWNER_EMAIL}}, "remote.google.client_id"),
        ({"google": {"enabled": True, "client_id": GOOGLE_CLIENT, "owner_email": "owner"}}, "remote.google.owner_email"),
    ],
)
def test_remote_misconfiguration_fails_startup(remote_config, remote, message):
    with pytest.raises(SystemExit, match=message):
        computer_main(["--config", remote_config(**remote)])


def test_google_signin_needs_its_client_secret_but_the_admin_cli_does_not(remote_config, monkeypatch, capsys):
    config = Path(remote_config(google={"enabled": True, "client_id": GOOGLE_CLIENT, "owner_email": "Owner@Example.com"}))
    section = yaml.safe_load(config.read_text(encoding="utf-8"))["remote"]
    OAuthStore(section["state"]).set_owner(PASSPHRASE, totp.new_secret())
    monkeypatch.delenv("CONTEXTBRIDGE_GOOGLE_CLIENT_SECRET", raising=False)
    with pytest.raises(SystemExit, match="CONTEXTBRIDGE_GOOGLE_CLIENT_SECRET is not set"):
        computer_main(["--config", str(config)])
    admin_main(["--config", str(config), "oauth-clients"])  # no Google secret in the admin's shell
    assert "no remote clients registered" in capsys.readouterr().out

    monkeypatch.setenv("CONTEXTBRIDGE_GOOGLE_CLIENT_SECRET", "google-client-secret")
    remote = RemoteListenerConfig(section, config.parent, config)
    assert remote.settings().google == GoogleSettings(
        client_id=GOOGLE_CLIENT, owner_email="owner@example.com", client_secret="google-client-secret"
    )
    assert remote.google_redirect_uri == "https://friday.example.ts.net/consent/google"
    assert "google-client-secret" not in repr(remote.settings())


# ------------------------------------------------------------ end to end


def test_remote_endpoint_end_to_end(tmp_path, workspace):
    """Owner setup, client registration, consent, token use, refresh, and revocation via the shipped CLIs."""
    local_port, remote_port = free_port(), free_port()
    public = f"http://127.0.0.1:{remote_port}"
    resource = public + "/mcp"
    state = workspace / "state" / "oauth.json"  # inside a readable root: the file tools must still refuse it
    config = tmp_path / "computer.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "serve": {"host": "127.0.0.1", "port": local_port, "audit_log": "audit/computer.jsonl"},
                "filesystem": {"roots": [str(workspace)], "writable_roots": [str(workspace / "work")]},
                "commands": {"mode": "allowlist", "allow": ["echo"]},
                "remote": {
                    "enabled": True,
                    "host": "127.0.0.1",
                    "port": remote_port,
                    "public_url": public,
                    "state": str(state),
                    "allow_scopes": [SCOPE_READ, SCOPE_WRITE],
                    "allow_devices": ["local"],
                    "allowed_redirect_hosts": ["claude.ai"],
                },
            }
        ),
        encoding="utf-8",
    )
    env = isolated_env()
    admin = ("contextbridge.remote.admin", "--config", str(config))
    gateway_env = isolated_env(CONTEXTBRIDGE_COMPUTER_TOKEN=COMPUTER_TOKEN)

    # Remote mode fails closed until the owner exists.
    early = cli("contextbridge.computer", "--config", str(config), env=gateway_env)
    assert early.returncode != 0 and "owner-init" in early.stderr

    init = subprocess.run(
        [sys.executable, "-m", *admin, "owner-init", "--passphrase-stdin", "--no-confirm"],
        input=PASSPHRASE + "\n",
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert init.returncode == 0, init.stderr
    secret = re.search(r"secret: ([A-Z2-7]+)", init.stdout).group(1)
    assert "otpauth://totp/" in init.stdout
    store = OAuthStore(state)
    assert store.state["owner"]["totp_secret"] == secret

    with serve("contextbridge.computer", config, local_port, gateway_env) as local_url:
        _wait_for_port(remote_port, config)
        http = httpx.Client(base_url=public, timeout=30)

        def authorize_client(scopes: list[str]) -> tuple[str, dict]:
            client_id = http.post(
                "/register",
                json={"redirect_uris": [REDIRECT], "client_name": "Claude", "token_endpoint_auth_method": "none"},
            ).json()["client_id"]
            verifier, challenge = pkce()
            consent = http.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": REDIRECT,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "xyz",
                    "resource": resource,
                },
            ).headers["location"]
            page = http.get(consent)
            fields = {**form_fields(page.text), "scope": scopes, "device": ["local"], "action": "approve"}
            wrong = http.post("/consent", data={**fields, "passphrase": PASSPHRASE, "totp": "12345x"})
            assert wrong.status_code == 401
            approved = http.post("/consent", data={**fields, "passphrase": PASSPHRASE, "totp": next_code(store)})
            assert approved.status_code == 302, approved.text
            code = parse_qs(urlsplit(approved.headers["location"]).query)["code"][0]
            tokens = http.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT,
                    "client_id": client_id,
                    "code_verifier": verifier,
                    "resource": resource,
                },
            )
            assert tokens.status_code == 200, tokens.text
            return client_id, tokens.json()

        assert http.post("/mcp", json={}).status_code == 401
        client_id, tokens = authorize_client([SCOPE_READ])
        access = tokens["access_token"]

        async def use(client):
            tools = {t.name for t in await client.list_tools()}
            devices = (await client.call_tool("list_devices", {})).structured_content["devices"]
            text = (await client.call_tool("read_file", {"path": "docs/notes.md"})).structured_content
            failures = {}
            for name, args in {
                "write": ("write_file", {"path": "work/x.txt", "content": "x"}),
                "execute": ("run_command", {"command": "echo hi"}),
                "device": ("read_file", {"path": "docs/notes.md", "device": "thanatos"}),
                "state": ("read_file", {"path": "state/oauth.json"}),
            }.items():
                with pytest.raises(ToolError) as info:
                    await client.call_tool(*args)
                failures[name] = str(info.value)
            return tools, devices, text, failures

        tools, devices, text, failures = call(resource, access, use)
        assert tools and all(TOOL_SCOPES[t] == SCOPE_READ for t in tools)
        assert "write_file" not in tools and "run_command" not in tools
        assert [d["device"] for d in devices] == ["local"]
        assert text["content"] == "alpha\nbeta\ngamma\n"
        assert "needs computer:write" in failures["write"]
        assert "execute" in failures["execute"]
        assert "not authorized for device 'thanatos'" in failures["device"]
        assert "denied path" in failures["state"]

        # Each listener accepts only its own kind of credential.
        with pytest.raises(Exception, match="401|Unauthorized"):
            call(resource, COMPUTER_TOKEN, lambda c: c.list_tools())
        with pytest.raises(Exception, match="401|Unauthorized"):
            call(local_url, access, lambda c: c.list_tools())
        assert call(local_url, COMPUTER_TOKEN, lambda c: c.list_tools())
        # Both listeners refuse a foreign Host header (DNS rebinding), even before authentication.
        rebound = {"host": "evil.example"}
        assert httpx.post(local_url, headers=rebound, json={}).status_code == 421
        assert http.get("/.well-known/oauth-authorization-server", headers=rebound).status_code == 421

        # Refresh rotates; the owner revokes from the CLI and the token dies on its next request.
        refreshed = http.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id},
        )
        assert refreshed.status_code == 200, refreshed.text
        access = refreshed.json()["access_token"]
        assert call(resource, access, lambda c: c.list_tools())

        listed = cli(*admin, "oauth-clients", env=env)
        assert listed.returncode == 0 and client_id in listed.stdout and "scopes=computer:read" in listed.stdout
        revoked = cli(*admin, "oauth-revoke", client_id, env=env)
        assert revoked.returncode == 0 and "1 grant" in revoked.stdout, revoked.stdout + revoked.stderr
        with pytest.raises(Exception, match="401|Unauthorized"):
            call(resource, access, lambda c: c.list_tools())
        http.close()

    events = [json.loads(line) for line in (tmp_path / "audit" / "computer.jsonl").read_text().splitlines()]
    remote_reads = [e for e in events if e["event"] == "requested" and e.get("listener") == "remote"]
    assert remote_reads and all(e["listener"] == "remote" for e in remote_reads)
    started = {e["request_id"]: e for e in events if e["event"] == "started"}
    assert any(started[e["request_id"]]["client"] == client_id for e in remote_reads if e["request_id"] in started)
    kinds = {e["event"] for e in events}
    assert {"oauth_consent_failed", "oauth_consent_granted", "oauth_token_issued", "oauth_token_refreshed"} <= kinds
    assert access not in state.read_text(encoding="utf-8")


def _wait_for_port(port: int, config: Path) -> None:
    deadline = time.monotonic() + 30
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            if time.monotonic() > deadline:
                log = config.with_name(f"{config.stem}.contextbridge.computer.stderr.log")
                raise AssertionError(f"remote listener never opened:\n{read_log(log)}") from None
            time.sleep(0.1)
