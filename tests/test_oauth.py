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
    build_router,
    create_computer_server,
)
from contextbridge.computer.server import main as computer_main
from contextbridge.oauth import totp
from contextbridge.oauth.provider import RemoteSettings
from contextbridge.oauth.remote import create_remote_server
from contextbridge.oauth.store import (
    MAX_CLIENTS,
    OAuthStateError,
    OAuthStore,
    token_hash,
)

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


def _remote(policy, tmp_path, store, redirect_hosts):
    audit_path = tmp_path / "audit.jsonl"
    audit = ComputerAuditLog(audit_path, echo=False)
    settings = RemoteSettings(
        public_url=PUBLIC,
        allow_scopes=(SCOPE_READ, SCOPE_WRITE),
        allow_devices=("local",),
        allowed_redirect_hosts=redirect_hosts,
    )
    server = create_remote_server(build_router(policy, audit=audit), audit=audit, settings=settings, store=store)
    app = server.http_app()

    async def client() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=PUBLIC)

    return SimpleNamespace(client=client, store=store, audit_path=audit_path)


@pytest.fixture
def remote(policy, tmp_path, store):
    return _remote(policy, tmp_path, store, ("claude.ai", "localhost"))


@pytest.fixture
def remote_local_apps(policy, tmp_path, store):
    """A gateway that also lets desktop apps (OpenCode, local agents) sign in through a loopback redirect."""
    return _remote(policy, tmp_path, store, ("claude.ai", "127.0.0.1", "::1"))


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


async def start_authorization(
    http: httpx.AsyncClient,
    client_id: str,
    *,
    scope: str | None = None,
    state="s1",
    resource=PUBLIC + "/mcp",
    redirect: str = REDIRECT,
):
    verifier, challenge = pkce()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "resource": resource,
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


async def exchange(http, client_id: str, verifier: str, code: str, *, redirect: str = REDIRECT) -> httpx.Response:
    return await http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect,
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


@pytest.mark.parametrize(
    "redirect",
    ["http://127.0.0.1:53682/callback", "http://127.0.0.1:1/cb", "http://[::1]:8000/oauth/callback"],
)
def test_listed_loopback_hosts_let_desktop_apps_register_on_any_port(remote_local_apps, redirect):
    async def scenario():
        async with await remote_local_apps.client() as http:
            return await register(http, redirect=redirect, name="OpenCode")

    response = anyio.run(scenario)
    assert response.status_code == 201, response.text
    assert [c["client_name"] for c in remote_local_apps.store.clients()] == ["OpenCode"]


@pytest.mark.parametrize(
    "redirect",
    [
        "http://127.0.0.2:5000/cb",  # loopback, but not a listed host
        "http://127.0.0.1.evil.example:5000/cb",
        "http://claude.ai/callback",  # a listed host, but plain http off loopback
        "file:///tmp/cb",
    ],
)
def test_loopback_redirects_are_exact_listed_hosts_and_http_only_there(remote_local_apps, redirect):
    async def scenario():
        async with await remote_local_apps.client() as http:
            return await register(http, redirect=redirect)

    response = anyio.run(scenario)
    assert response.status_code == 400 and response.json()["error"] == "invalid_redirect_uri"
    assert remote_local_apps.store.clients() == []


def test_loopback_redirects_are_refused_unless_listed(remote):
    async def scenario():
        async with await remote.client() as http:
            return await register(http, redirect="http://127.0.0.1:53682/callback")

    response = anyio.run(scenario)
    assert response.status_code == 400 and response.json()["error"] == "invalid_redirect_uri"


def test_desktop_app_gets_its_code_on_loopback_after_owner_consent(remote_local_apps):
    redirect = "http://127.0.0.1:53682/callback"

    async def scenario():
        async with await remote_local_apps.client() as http:
            client_id = (await register(http, redirect=redirect, name="OpenCode")).json()["client_id"]
            verifier, page = await start_authorization(http, client_id, redirect=redirect)
            approved = await approve(http, page, remote_local_apps.store)
            location = urlsplit(approved.headers["location"])
            code = parse_qs(location.query)["code"][0]
            token = await exchange(http, client_id, verifier, code, redirect=redirect)
            return page, approved, location, token

    page, approved, location, token = anyio.run(scenario)
    assert page.status_code == 200 and "127.0.0.1:53682" in page.text  # the consent page names where the code goes
    assert approved.status_code == 302
    assert (location.scheme, location.netloc, location.path) == ("http", "127.0.0.1:53682", "/callback")
    assert token.status_code == 200 and token.json()["access_token"]


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


@pytest.fixture
def tunnel_app(policy, tmp_path, store):
    """The remote app as served behind a tunnel: loopback listener, public URL, HostOriginGuard in front."""
    from contextbridge.computer.server import RemoteListenerConfig

    remote_cfg = RemoteListenerConfig(
        {"port": 8793, "public_url": "https://friday.example.ts.net", "state": "oauth.json"}, tmp_path, tmp_path
    )
    options = remote_cfg.http_options()
    audit_path = tmp_path / "audit.jsonl"
    audit = ComputerAuditLog(audit_path, echo=False)
    server = create_remote_server(
        build_router(policy, audit=audit), audit=audit, settings=remote_cfg.settings(), store=store
    )
    app = server.http_app(middleware=options["middleware"])

    def client(**kwargs) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        return httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8793", **kwargs)

    return SimpleNamespace(client=client, options=options, store=store, audit_path=audit_path)


def test_tunnel_host_passes_the_guard_and_strangers_do_not(tunnel_app):
    options = tunnel_app.options

    async def scenario():
        async with tunnel_app.client() as http:
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


def test_custom_cloudflare_hostname_uses_configured_public_origin(policy, tmp_path, store):
    """A custom tunnel hostname must be accepted without weakening DNS-rebinding protection."""
    from contextbridge.computer.server import RemoteListenerConfig

    public = "https://mcp.contextbridge.app"
    config = RemoteListenerConfig(
        {"port": 8793, "public_url": public, "state": "oauth.json"}, tmp_path, tmp_path
    )
    audit = ComputerAuditLog(tmp_path / "audit.jsonl", echo=False)
    server = create_remote_server(
        build_router(policy, audit=audit), audit=audit, settings=config.settings(), store=store
    )
    app = server.http_app(middleware=config.http_options()["middleware"])

    async def scenario():
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8793") as http:
            headers = {"host": "mcp.contextbridge.app"}
            protected = await http.get("/.well-known/oauth-protected-resource/mcp", headers=headers)
            authorization = await http.get("/.well-known/oauth-authorization-server", headers=headers)
            unauthorized = await http.get("/mcp", headers=headers)
            stale = await http.get("/mcp", headers={"host": "friday.example.ts.net"})  # the previous public name
            return protected, authorization, unauthorized, stale

    protected, authorization, unauthorized, stale = anyio.run(scenario)
    assert protected.status_code == 200
    assert protected.json()["resource"] == public + "/mcp"
    assert protected.json()["authorization_servers"] == [public + "/"]
    assert authorization.status_code == 200
    metadata = authorization.json()
    assert metadata["issuer"] == public + "/"
    for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
        assert metadata[key].startswith(public + "/")
    assert unauthorized.status_code == 401
    assert public + "/.well-known/oauth-protected-resource/mcp" in unauthorized.headers["www-authenticate"]
    assert stale.status_code == 421


def test_browser_approval_through_the_tunnel_reaches_the_client(tunnel_app):
    """Regression: every browser approval behind the tunnel used to fail with 403 Forbidden Origin."""
    public_origin = "https://friday.example.ts.net"

    async def scenario():
        async with tunnel_app.client(headers={"host": "friday.example.ts.net"}) as http:
            client_id = (await register(http)).json()["client_id"]
            _, page = await start_authorization(http, client_id, resource=public_origin + "/mcp")
            data = {
                **form_fields(page.text),
                "scope": [SCOPE_READ],
                "device": ["local"],
                "passphrase": PASSPHRASE,
                "totp": next_code(tunnel_app.store),
                "action": "approve",
            }
            # What a browser sends for the form POST when the page's referrer policy is no-referrer.
            null_origin = await http.post("/consent", headers={"origin": "null"}, data=data)
            # What it sends under same-origin: the page's own origin.
            approved = await http.post("/consent", headers={"origin": public_origin}, data=data)
            return page, null_origin, approved

    page, null_origin, approved = anyio.run(scenario)
    assert page.status_code == 200
    assert page.headers["referrer-policy"] == "same-origin"
    assert null_origin.status_code == 403  # the guard still refuses Origin: null
    assert approved.status_code == 302, approved.text
    location = urlsplit(approved.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT
    query = parse_qs(location.query)
    assert query["code"] and query["state"] == ["s1"]
    events = [json.loads(line)["event"] for line in tunnel_app.audit_path.read_text().splitlines()]
    assert "oauth_consent_granted" in events


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
    ],
)
def test_remote_misconfiguration_fails_startup(remote_config, remote, message):
    with pytest.raises(SystemExit, match=message):
        computer_main(["--config", remote_config(**remote)])


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
