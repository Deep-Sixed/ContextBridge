"""The owner dashboard at /devices."""

from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_oauth import PASSPHRASE, PUBLIC, next_code

from contextbridge.computer.audit import ComputerAuditLog
from contextbridge.computer.scopes import SCOPE_READ, SCOPE_WRITE
from contextbridge.computer.server import build_router
from contextbridge.oauth import totp
from contextbridge.oauth.dashboard import OwnerDashboard, ago
from contextbridge.oauth.provider import RemoteSettings
from contextbridge.oauth.remote import create_remote_server
from contextbridge.oauth.store import OAuthStore, new_token
from contextbridge.remote.agent import Identity
from contextbridge.remote.hub import AgentHub
from contextbridge.remote.registry import DeviceRegistry


def public_key() -> str:
    return Identity("", "x", "", Ed25519PrivateKey.generate()).public_key


@pytest.fixture
def dash(policy, tmp_path):
    store = OAuthStore(tmp_path / "state" / "oauth.json")
    store.set_owner(PASSPHRASE, totp.new_secret())
    registry = DeviceRegistry(tmp_path / "state" / "devices.json")
    registry.refresh()
    hermes = registry.register("hermes", public_key(), [SCOPE_READ], {"hostname": "Hermes"})
    registry.register("raven", public_key(), [SCOPE_READ, SCOPE_WRITE])
    audit_path = tmp_path / "audit.jsonl"
    audit = ComputerAuditLog(audit_path, echo=False)
    hub = AgentHub(registry, audit)
    hub._last_seen_wall[hermes.device_id] = time.time() - 10 * 3600  # last heartbeat 10 hours ago
    settings = RemoteSettings(
        public_url=PUBLIC, allow_scopes=(SCOPE_READ, SCOPE_WRITE), allow_devices=("*",),
        allowed_redirect_hosts=("chatgpt.com",), client_ip_header="CF-Connecting-IP",
    )
    server = create_remote_server(
        build_router(policy, audit=audit, hub=hub), audit=audit, settings=settings, store=store, registry=registry,
    )
    transport = httpx.ASGITransport(app=server.http_app())

    def client() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport, base_url=PUBLIC)

    class D:
        pass

    d = D()
    d.store, d.registry, d.client, d.audit_path = store, registry, client, audit_path
    return d


def grant(store: OAuthStore, *, client_id="chatgpt-1", name="ChatGPT", devices=("hermes",)) -> str:
    store.save_client({"client_id": client_id, "client_name": name, "redirect_uris": ["https://chatgpt.com/cb"]})
    code = new_token()
    store.save_code(code, {"client_id": client_id, "expires_at": time.time() + 60})
    grant_id, _, _ = store.create_grant(
        client_id=client_id, scopes=[SCOPE_READ], devices=list(devices), resource=PUBLIC + "/mcp", code=code,
        access_seconds=3600, refresh_seconds=86400,
    )
    return grant_id


async def sign_in(http: httpx.AsyncClient, store: OAuthStore, **form) -> httpx.Response:
    data = {"passphrase": PASSPHRASE, "totp": next_code(store), **form}
    return await http.post("/devices/login", data=data, headers={"CF-Connecting-IP": "203.0.113.5"})


def csrf(page: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


def test_signed_out_dashboard_shows_only_a_sign_in_form(dash):
    async def scenario():
        async with dash.client() as http:
            home = await http.get("/devices")
            add = await http.get("/devices/add")
            remove = await http.post("/devices/remove", data={"device": "hermes", "confirm": "yes"})
            wrong = await sign_in(http, dash.store, passphrase="nope")
            return home, add, remove, wrong

    home, add, remove, wrong = asyncio.run(scenario())
    assert home.status_code == 200 and "Sign in" in home.text and "hermes" not in home.text
    assert add.status_code == 303 and remove.status_code == 303
    assert dash.registry.by_name("hermes") is not None  # nothing happened without a session
    assert wrong.status_code == 401 and "Wrong passphrase" in wrong.text and "set-cookie" not in wrong.headers


def test_dashboard_lists_devices_by_name_then_last_seen_and_each_grant(dash):
    grant(dash.store, devices=("hermes", "raven"))

    async def scenario():
        async with dash.client() as http:
            signed_in = await sign_in(http, dash.store)
            return signed_in, await http.get("/devices"), await http.get("/devices/add")

    signed_in, page, add = asyncio.run(scenario())
    cookie = signed_in.headers["set-cookie"]
    assert signed_in.status_code == 303 and "httponly" in cookie.lower() and "samesite=strict" in cookie.lower()
    text = page.text
    # Each device: its name, then when it was last seen.
    assert re.search(r'class="name">hermes</div>\s*<div class="seen">Last seen 10 hours ago</div>', text)
    assert re.search(r'class="name">raven</div>\s*<div class="seen">Not seen since the gateway started</div>', text)
    assert 'class="name">local<' not in text
    assert "Devices: hermes, raven" in text and "ChatGPT" in text and "chatgpt.com" in text
    assert PUBLIC + "/mcp" in text
    assert f"curl -fsSL {PUBLIC}/install/remote-linux.sh | sh" in add.text and 'href="/activate"' in add.text
    assert page.headers["cache-control"] == "no-store" and "frame-ancestors 'none'" in page.headers["content-security-policy"]


def test_remove_asks_first_then_revokes_the_device(dash):
    async def scenario():
        async with dash.client() as http:
            await sign_in(http, dash.store)
            token = csrf((await http.get("/devices")).text)
            forged = await http.post("/devices/remove", data={"device": "hermes", "confirm": "yes", "csrf": "x"})
            ask = await http.post("/devices/remove", data={"device": "hermes", "csrf": token})
            still = dash.registry.by_name("hermes") is not None
            done = await http.post("/devices/remove", data={"device": "hermes", "confirm": "yes", "csrf": token})
            return forged, ask, still, done

    forged, ask, still, done = asyncio.run(scenario())
    assert forged.status_code == 303  # a wrong CSRF token is treated as signed out
    assert ask.status_code == 200 and "Remove hermes?" in ask.text and still
    assert done.status_code == 200 and "Removed hermes." in done.text
    assert dash.registry.by_name("hermes") is None and dash.registry.by_name("raven") is not None
    assert "device_revoked_by_owner" in dash.audit_path.read_text(encoding="utf-8")


def test_revoke_asks_first_then_ends_only_that_grant(dash):
    first = grant(dash.store, client_id="chatgpt-old", devices=("hermes", "raven"))
    second = grant(dash.store, client_id="claude-1", name="Claude", devices=("hermes",))

    async def scenario():
        async with dash.client() as http:
            await sign_in(http, dash.store)
            token = csrf((await http.get("/devices")).text)
            ask = await http.post("/devices/revoke-grant", data={"grant": first, "csrf": token})
            done = await http.post("/devices/revoke-grant", data={"grant": first, "confirm": "yes", "csrf": token})
            again = await http.post("/devices/revoke-grant", data={"grant": first, "confirm": "yes", "csrf": token})
            return ask, done, again

    ask, done, again = asyncio.run(scenario())
    assert "Revoke ChatGPT" in ask.text and "hermes, raven" in ask.text
    assert "Revoked ChatGPT" in done.text and "Devices: hermes, raven" not in done.text and "Claude" in done.text
    assert again.status_code == 404
    grants = dash.store.state["grants"]
    assert grants[first]["revoked_at"] is not None and grants[second]["revoked_at"] is None


def test_sessions_expire_and_sign_out_ends_them(dash, monkeypatch):
    from contextbridge.oauth import dashboard as module

    async def scenario():
        async with dash.client() as http:
            await sign_in(http, dash.store)
            token = csrf((await http.get("/devices")).text)
            await http.post("/devices/logout", data={"csrf": token})
            after_logout = await http.get("/devices")
            await sign_in(http, dash.store)
            real = time.time
            monkeypatch.setattr(module.time, "time", lambda: real() + module.SESSION_SECONDS + 1)
            after_expiry = await http.get("/devices")
            return after_logout, after_expiry

    after_logout, after_expiry = asyncio.run(scenario())
    assert "Sign in" in after_logout.text and "Sign in" in after_expiry.text


def test_cookie_is_host_prefixed_and_secure_over_https(tmp_path):
    def make(url):
        return OwnerDashboard(
            public_url=url, registry=None, store=None, audit=None, describe=list,
            client_address=lambda r: None, page=None,
        )

    secure, plain = make("https://mcp.example.com"), make("http://127.0.0.1:8793")
    assert secure.cookie == "__Host-cb_owner" and secure._secure
    assert plain.cookie == "cb_owner" and not plain._secure


def test_last_seen_reads_naturally():
    now = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
    assert ago(now - timedelta(seconds=20), now) == "just now"
    assert ago(now - timedelta(minutes=1), now) == "1 minute ago"
    assert ago(now - timedelta(hours=10), now) == "10 hours ago"
    assert ago(now - timedelta(days=7, hours=3), now) == "7 days ago"
    assert ago(None, now) == "not since the gateway started"
