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
            return (
                signed_in, await http.get("/devices"), await http.get("/devices/add"),
                await http.get("/devices/endpoints"), await http.get("/devices/add?os=linux"),
            )

    signed_in, page, add, endpoints, linux = asyncio.run(scenario())
    cookie = signed_in.headers["set-cookie"]
    assert signed_in.status_code == 303 and "httponly" in cookie.lower() and "samesite=strict" in cookie.lower()
    text = page.text
    # Each device: its name, then when it was last seen.
    assert re.search(r'class="name">hermes</span>\s*<span class="seen[^"]*">Last seen 10 hours ago</span>', text)
    assert re.search(r'class="name">raven</span>\s*<span class="seen[^"]*">Not seen since the gateway started</span>', text)
    assert 'class="name">local<' not in text
    assert 'aria-current=page><svg' in text and "Endpoints" in text and "Usage" in text and "Settings" in text
    assert "ChatGPT" in endpoints.text and "chatgpt.com · 2 devices" in endpoints.text
    assert PUBLIC + "/mcp" in endpoints.text
    assert f"irm -ErrorAction Stop '{PUBLIC}/install/remote-windows.ps1' | iex" in add.text
    assert f"curl -fsSL {PUBLIC}/install/remote-linux.sh | sh" in linux.text and 'href="/activate"' in add.text
    assert "eight-character activation code" in add.text and "No pairing code" not in add.text
    assert "remote.public_url</code>" in text  # PUBLIC is a loopback test URL, so the dashboard flags it
    for response in (page, add, endpoints):
        csp = response.headers["content-security-policy"]
        assert response.headers["cache-control"] == "no-store" and "frame-ancestors 'none'" in csp
        assert "script-src" not in csp and "<script" not in response.text  # default-src 'none': no scripts at all


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
    assert "Revoked ChatGPT" in done.text and "chatgpt.com · 2 devices" not in done.text and "Claude" in done.text
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


def test_warns_when_no_device_is_connected_here_but_some_were_just_seen(dash):
    # hermes heard from a minute ago (the state file a live hub in another process keeps), nothing connected here.
    hub_rows = [
        {"device": "hermes", "online": False, "last_seen": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()},
        {"device": "raven", "online": False},
    ]
    warning = OwnerDashboard._elsewhere_warning(hub_rows)
    assert "hermes" in warning and "another ContextBridge" in warning and "raven" not in warning
    assert OwnerDashboard._elsewhere_warning([{**hub_rows[0], "online": True}]) == ""
    stale = [{"device": "hermes", "online": False, "last_seen": "2026-01-01T00:00:00Z"}]
    assert OwnerDashboard._elsewhere_warning(stale) == ""


def test_loopback_public_url_is_flagged_not_silently_advertised():
    def make(url):
        return OwnerDashboard(
            public_url=url, registry=None, store=None, audit=None, describe=list,
            client_address=lambda r: None, page=None,
        )

    assert "only this" in make("http://127.0.0.1:8799")._loopback_warning()
    assert "remote.public_url" in make("http://localhost:8799")._loopback_warning()
    assert make("https://mcp.contextbridge.app")._loopback_warning() == ""


# ------------------------------------------------- per-device assistant access


def test_saving_the_grid_narrows_and_widens_per_device_and_records_who_and_what(dash):
    gid = grant(dash.store, devices=("hermes", "raven"))  # token scopes: read only

    async def scenario():
        async with dash.client() as http:
            await sign_in(http, dash.store)
            page = await http.get("/devices/endpoints")
            token = csrf(page.text)
            saved = await http.post("/devices/grant-access", data={
                "csrf": token, "grant": gid,
                # raven: read + write (write is beyond the token); hermes dropped; forged entries ignored.
                "perm": ["raven|computer:read", "raven|computer:write", "hermes|computer:write",
                         "thanatos|computer:read", "raven|computer:execute"],
            })
            forged = await http.post("/devices/grant-access", data={"csrf": "x", "grant": gid, "perm": []})
            return page, saved, forged

    page, saved, forged = asyncio.run(scenario())
    # hermes only allows read (its registry grant), so write is "—" and has no checkbox.
    assert 'value="hermes|computer:read" checked' in page.text and 'value="hermes|computer:write"' not in page.text
    assert 'value="raven|computer:write"' in page.text and 'class="beyond"' in page.text
    assert saved.status_code == 200 and "Saved 2 changes for ChatGPT" in saved.text
    assert "need re-authorization" in saved.text and "Needs re-authorization" in saved.text
    assert forged.status_code == 303
    stored = dash.store.state["grants"][gid]
    assert stored["devices"] == ["raven"]
    assert stored["device_scopes"] == {"raven": [SCOPE_READ, SCOPE_WRITE]}
    assert stored["scopes"] == [SCOPE_READ]  # the token ceiling never moves from the dashboard
    assert [(h["by"], h["text"]) for h in stored["history"]] == [
        ("owner", "removed hermes"), ("owner", "allowed write on raven"),
        ("consent", "Paired · read on hermes, raven"),
    ]
    log = dash.audit_path.read_text(encoding="utf-8")
    assert '"event":"oauth_grant_changed"' in log and '"by":"owner_dashboard"' in log


def test_request_reauthorization_marks_the_grant_and_stops_its_refresh(dash):
    gid = grant(dash.store, devices=("raven",))
    dash.store.set_device_scopes(gid, {"raven": [SCOPE_READ, SCOPE_WRITE]}, changes=["allowed write on raven"])

    async def scenario():
        async with dash.client() as http:
            await sign_in(http, dash.store)
            token = csrf((await http.get("/devices/endpoints")).text)
            return await http.post("/devices/reauth", data={"csrf": token, "grant": gid})

    done = asyncio.run(scenario())
    assert done.status_code == 200 and "Requested re-authorization" in done.text
    assert "consent page on next connection" in done.text
    stored = dash.store.state["grants"][gid]
    assert stored["reauth_requested_at"] and stored["history"][0]["text"] == "Requested re-authorization for write"
    assert dash.store.reauth_request("chatgpt-1")[0] == gid
    assert "Cancel request" in done.text and "loses access" in done.text

    async def cancel():
        async with dash.client() as http:
            await sign_in(http, dash.store)
            token = csrf((await http.get("/devices/endpoints")).text)
            return await http.post("/devices/cancel-reauth", data={"csrf": token, "grant": gid})

    cancelled = asyncio.run(cancel())
    assert cancelled.status_code == 200 and "keeps its current access" in cancelled.text
    stored = dash.store.state["grants"][gid]
    assert "reauth_requested_at" not in stored and dash.store.reauth_request("chatgpt-1") is None
    assert stored["history"][0]["text"] == "Cancelled the re-authorization request"
    assert "Request re-authorization" in cancelled.text  # still beyond the token, so it can be asked again


def test_usage_page_counts_tool_calls_from_the_audit_log(dash):
    import json

    now = datetime.now(timezone.utc)
    lines = [{"ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "event": "requested", "tool": "read_file"}] * 7
    lines += [{"ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "event": "completed"}]
    with open(dash.audit_path, "a", encoding="utf-8") as fh:
        fh.write("".join(json.dumps(line) + "\n" for line in lines))

    async def scenario():
        async with dash.client() as http:
            await sign_in(http, dash.store)
            return await http.get("/devices/usage")

    page = asyncio.run(scenario())
    assert page.status_code == 200 and '<span class="big">7</span>' in page.text
    assert "7 tool calls this month" in page.text and f"{now:%b}: 7 calls" in page.text


def test_usage_counter_reads_only_what_was_appended(tmp_path):
    from datetime import date

    from contextbridge.oauth.usage import UsageCounter

    log = tmp_path / "audit.jsonl"
    log.write_text('{"ts":"2026-11-02T10:00:00Z","event":"requested"}\n{"ts":"2026-10-30T10:00:00Z","event":"requested"}\n')
    counter = UsageCounter(log)
    first = counter.summary(today=date(2026, 11, 19))
    with open(log, "a") as fh:
        fh.write('{"ts":"2026-11-19T10:00:00Z","event":"requested"}\n{"ts":"2026-11-19T10:00:01Z","event":"denied"}\n'
                 '{"ts":"2026-11-19T10:00:02Z","event":"requ')  # half-written line waits
    second = counter.summary(today=date(2026, 11, 19))
    assert first["this_month"] == 1 and second["this_month"] == 2 and second["daily_average"] == 0
    assert second["months"][-2:] == [("Oct", 1), ("Nov", 2)] and len(second["months"]) == 6
    assert UsageCounter(None).summary()["this_month"] == 0


def test_change_passphrase_needs_the_current_one_and_a_code(dash, monkeypatch):
    from contextbridge.oauth import totp as totp_module

    new = "a much longer passphrase"
    # Each code works once; step the clock so the test can mint as many as it needs.
    clock = [time.time()]

    def tick():
        clock[0] += 30
        return clock[0]

    monkeypatch.setattr(totp_module.time, "time", lambda: clock[0])

    async def scenario():
        async with dash.client() as http, dash.client() as other:
            await sign_in(http, dash.store)
            await sign_in(other, dash.store)
            token = csrf((await http.get("/devices/settings")).text)
            short = await http.post("/devices/passphrase", data={"csrf": token, "current": PASSPHRASE,
                                    "totp": "000000", "new": "short", "repeat": "short"})
            wrong = await http.post("/devices/passphrase", data={"csrf": token, "current": "nope",
                                    "totp": "000000", "new": new, "repeat": new})
            tick()
            done = await http.post("/devices/passphrase", data={"csrf": token, "current": PASSPHRASE,
                                   "totp": next_code(dash.store), "new": new, "repeat": new})
            return short, wrong, done, await other.get("/devices"), await http.get("/devices")

    short, wrong, done, other, mine = asyncio.run(scenario())
    assert short.status_code == 400 and wrong.status_code == 401
    assert done.status_code == 200 and "Passphrase changed" in done.text
    assert "Sign in" in other.text and "Your devices" in mine.text  # other sessions end, this one stays
    tick()
    assert dash.store.verify_owner(new, next_code(dash.store)) is None
    assert "owner_passphrase_changed" in dash.audit_path.read_text(encoding="utf-8")


def test_theme_is_remembered_in_a_cookie(dash):
    async def scenario():
        async with dash.client() as http:
            await sign_in(http, dash.store)
            token = csrf((await http.get("/devices/settings")).text)
            switched = await http.post("/devices/theme", data={"csrf": token, "theme": "light"})
            return switched, await http.get("/devices/settings")

    switched, page = asyncio.run(scenario())
    assert switched.status_code == 303 and "cb_theme=light" in switched.headers["set-cookie"]
    assert 'data-theme="light"' in page.text and 'value="light" aria-pressed="true"' in page.text


def test_connections_group_by_name_and_renaming_splits_a_second_account(dash):
    old = grant(dash.store, client_id="gpt-1", devices=("hermes",))
    dash.store.set_label(old, "for now")  # so the next grant does not replace it
    new = grant(dash.store, client_id="gpt-2", devices=("hermes", "raven"))
    # What grants from before named connections look like: several active "ChatGPT" grants from chatgpt.com.
    with dash.store.update() as state:
        for g in state["grants"].values():
            g.pop("label", None)

    async def scenario():
        async with dash.client() as http:
            await sign_in(http, dash.store)
            page = await http.get("/devices/endpoints")
            token = csrf(page.text)
            renamed = await http.post("/devices/label", data={"csrf": token, "grant": old, "label": "ChatGPT (Dana)"})
            ask = await http.post("/devices/revoke-older", data={"csrf": token, "grant": new})
            return page, renamed, ask

    page, renamed, ask = asyncio.run(scenario())
    assert page.text.count('class="grant"') == 1 and "2 connections" in page.text and page.text.count("tag-accent\">In use") == 2
    assert renamed.status_code == 200 and renamed.text.count('class="grant"') == 2
    assert ">ChatGPT (Dana)</span>" in renamed.text
    assert dash.store.state["grants"][old]["label"] == "ChatGPT (Dana)"
    assert "has no idle connections" in ask.text  # after the split each connection has one grant
