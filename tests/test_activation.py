"""Browser activation of new devices: the installer asks, the owner approves in a browser."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import httpx
import pytest
import yaml
from test_oauth import PASSPHRASE, PUBLIC, approve, next_code, register, start_authorization

from contextbridge.computer.audit import ComputerAuditLog
from contextbridge.computer.scopes import SCOPE_EXECUTE, SCOPE_READ, SCOPE_WRITE
from contextbridge.computer.server import build_router
from contextbridge.oauth import activation as activation_module
from contextbridge.oauth import totp
from contextbridge.oauth.activation import key_fingerprint, normalize_user_code
from contextbridge.oauth.provider import RemoteSettings
from contextbridge.oauth.remote import create_remote_server
from contextbridge.oauth.store import OAuthStore
from contextbridge.remote.agent import FatalAgentError, Identity, activate, load_agent_config
from contextbridge.remote.registry import DeviceRegistry

AGENTS_URL = "wss://agents.example.test"
DEVICE = "raven"


@pytest.fixture(autouse=True)
def fast_polling(monkeypatch):
    monkeypatch.setattr(activation_module, "POLL_SECONDS", 1)


@pytest.fixture
def gw(policy, tmp_path):
    store = OAuthStore(tmp_path / "state" / "oauth.json")
    store.set_owner(PASSPHRASE, totp.new_secret())
    registry = DeviceRegistry(tmp_path / "state" / "devices.json")
    registry.refresh()
    audit = ComputerAuditLog(tmp_path / "audit.jsonl", echo=False)
    settings = RemoteSettings(
        public_url=PUBLIC,
        allow_scopes=(SCOPE_READ, SCOPE_WRITE),
        allow_devices=("*",),
        allowed_redirect_hosts=("claude.ai",),
        client_ip_header="CF-Connecting-IP",
    )
    server = create_remote_server(
        build_router(policy, audit=audit), audit=audit, settings=settings, store=store,
        registry=registry, agents_url=AGENTS_URL,
    )
    app = server.http_app()
    return type("GW", (), {
        "store": store,
        "registry": registry,
        "transport": httpx.ASGITransport(app=app),
        "client": lambda self: httpx.AsyncClient(transport=self.transport, base_url=PUBLIC),
    })()


def agent_config(tmp_path: Path, workspace: Path, name: str = DEVICE):
    path = tmp_path / f"{name}.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "name": name,
                "gateway": {"url": AGENTS_URL},
                "identity": str(tmp_path / f"{name}-state" / "identity.json"),
                "audit_log": str(tmp_path / f"{name}-audit.jsonl"),
                "filesystem": {"roots": [str(workspace)]},
            }
        ),
        encoding="utf-8",
    )
    return load_agent_config(path)


async def owner_acts(gw, codes: asyncio.Queue, *, action="approve", scopes=(SCOPE_READ, SCOPE_EXECUTE), **form):
    """Play the owner: wait for the installer's code, open the page, and approve or deny."""
    user_code = await codes.get()
    async with gw.client() as http:
        start = await http.get(f"/activate?code={user_code.replace('-', '').lower()}")
        assert start.status_code == 200 and f'value="{user_code}"' in start.text
        page = await http.post("/activate", data={"user_code": user_code, "action": "lookup"})
        assert page.status_code == 200, page.text
        token = re.search(r'name="form_token" value="([^"]+)"', page.text).group(1)
        data = {
            "user_code": user_code,
            "form_token": token,
            "scope": list(scopes),
            "passphrase": PASSPHRASE,
            "totp": next_code(gw.store),
            "action": action,
            **form,
        }
        return page, await http.post("/activate", data=data, headers={"CF-Connecting-IP": "203.0.113.9"})


def installer(gw, config, codes: asyncio.Queue, messages: list[str]):
    def notify(text: str) -> None:
        messages.append(text)
        match = re.search(r"enter the code ([A-Z]{4}-[A-Z]{4})", text)
        if match:
            codes.put_nowait(match.group(1))

    return activate(config, PUBLIC, notify=notify, transport=gw.transport)


def test_owner_approval_enrolls_the_device_with_the_chosen_scopes(gw, tmp_path, workspace):
    config = agent_config(tmp_path, workspace)

    async def scenario():
        codes: asyncio.Queue = asyncio.Queue()
        messages: list[str] = []
        identity, (page, done) = await asyncio.gather(
            installer(gw, config, codes, messages), owner_acts(gw, codes)
        )
        return identity, page, done, messages

    identity, page, done, messages = asyncio.run(scenario())
    assert done.status_code == 200 and "Approved" in done.text
    record = gw.registry.by_name(DEVICE)
    assert record is not None and record.device_id == identity.device_id
    assert record.scopes == [SCOPE_READ, SCOPE_EXECUTE]
    assert identity.gateway_id == gw.registry.gateway_id
    assert record.public_key == identity.public_key  # the key the installer generated, never sent anywhere else
    # The owner saw the same fingerprint the installer printed, and the host it came from.
    fingerprint = key_fingerprint(identity.public_key)
    assert fingerprint in page.text and fingerprint in messages[0]
    assert re.search(r'value="computer:read" checked', page.text)
    assert not re.search(r'value="computer:execute" checked', page.text)  # more than read is a deliberate tick
    # The identity file is the same one `enroll` writes: the agent can run with it as is.
    assert Identity.load(config.identity_path).device_id == record.device_id
    assert not any("Note:" in m for m in messages)  # the config already points at the gateway's agent address


def test_owner_denial_stops_the_installer_and_enrolls_nothing(gw, tmp_path, workspace):
    config = agent_config(tmp_path, workspace)

    async def scenario():
        codes: asyncio.Queue = asyncio.Queue()
        results = await asyncio.gather(
            installer(gw, config, codes, []), owner_acts(gw, codes, action="deny"), return_exceptions=True
        )
        return results

    refused, (_, denied) = asyncio.run(scenario())
    assert isinstance(refused, FatalAgentError) and "denied" in str(refused)
    assert "Denied" in denied.text
    assert gw.registry.by_name(DEVICE) is None and not config.identity_path.exists()


def test_wrong_owner_credentials_enroll_nothing(gw, tmp_path, workspace):
    config = agent_config(tmp_path, workspace)

    async def scenario():
        codes: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(installer(gw, config, codes, []))
        _, refused = await owner_acts(gw, codes, passphrase="not the passphrase")
        task.cancel()
        return refused

    refused = asyncio.run(scenario())
    assert refused.status_code == 401 and "Wrong passphrase" in refused.text
    assert gw.registry.by_name(DEVICE) is None


def test_start_refuses_bad_requests_and_names_already_in_use(gw):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Identity("", DEVICE, "", Ed25519PrivateKey.generate()).public_key
    other = Identity("", DEVICE, "", Ed25519PrivateKey.generate()).public_key

    async def scenario():
        async with gw.client() as http:
            bad_name = await http.post("/activate/start", json={"name": "Not A Name", "public_key": key})
            bad_key = await http.post("/activate/start", json={"name": DEVICE, "public_key": "abc"})
            not_json = await http.post("/activate/start", content=b"[]")
            first = await http.post("/activate/start", json={"name": DEVICE, "public_key": key})
            twice = await http.post("/activate/start", json={"name": DEVICE, "public_key": other})
            gw.registry.create_enrollment("friday", [SCOPE_READ])
            pending = await http.post("/activate/start", json={"name": "friday", "public_key": other})
            unknown = await http.post("/activate/poll", json={"device_code": "nope"})
            waiting = await http.post("/activate/poll", json={"device_code": first.json()["device_code"]})
            hurried = await http.post("/activate/poll", json={"device_code": first.json()["device_code"]})
            return bad_name, bad_key, not_json, first, twice, pending, unknown, waiting, hurried

    bad_name, bad_key, not_json, first, twice, pending, unknown, waiting, hurried = asyncio.run(scenario())
    assert bad_name.status_code == bad_key.status_code == not_json.status_code == 400
    assert first.status_code == 200 and re.fullmatch(r"[B-Z]{4}-[B-Z]{4}", first.json()["user_code"])
    assert first.json()["verification_uri"] == PUBLIC + "/activate"
    assert twice.status_code == 409 and pending.status_code == 409
    assert unknown.json() == {"status": "expired"}
    assert waiting.json()["status"] == "pending" and hurried.json()["status"] == "slow_down"


def test_each_address_may_start_only_a_few_activations(gw):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    async def scenario():
        async with gw.client() as http:
            statuses = []
            for i in range(activation_module.MAX_STARTS_PER_ADDRESS + 1):
                key = Identity("", "x", "", Ed25519PrivateKey.generate()).public_key
                r = await http.post(
                    "/activate/start", json={"name": f"dev-{i}", "public_key": key},
                    headers={"CF-Connecting-IP": "198.51.100.7"},
                )
                statuses.append(r.status_code)
            key = Identity("", "x", "", Ed25519PrivateKey.generate()).public_key
            elsewhere = await http.post(
                "/activate/start", json={"name": "dev-other", "public_key": key},
                headers={"CF-Connecting-IP": "198.51.100.8"},
            )
            return statuses, elsewhere.status_code

    statuses, elsewhere = asyncio.run(scenario())
    assert statuses[:-1] == [200] * activation_module.MAX_STARTS_PER_ADDRESS and statuses[-1] == 429
    assert elsewhere == 200


def test_an_unknown_code_on_the_page_reveals_nothing(gw):
    async def scenario():
        async with gw.client() as http:
            return await http.post("/activate", data={"user_code": "BCDF-GHJK", "action": "lookup"})

    page = asyncio.run(scenario())
    assert page.status_code == 404 and "not valid or has expired" in page.text
    assert page.headers["X-Frame-Options"] == "DENY"


def test_activation_needs_an_https_server(tmp_path, workspace):
    config = agent_config(tmp_path, workspace)
    with pytest.raises(FatalAgentError, match="https"):
        asyncio.run(activate(config, "http://gateway.example.test"))


def test_user_codes_normalize_however_they_are_typed():
    assert normalize_user_code("bcdf ghjk") == "BCDF-GHJK"
    assert normalize_user_code("BCDF-GHJK") == "BCDF-GHJK"
    assert normalize_user_code("bcd") == "BCD"


def test_consent_never_preselects_a_device_even_when_only_one_is_offered(gw):
    async def scenario():
        async with gw.client() as http:
            client_id = (await register(http)).json()["client_id"]
            _, page = await start_authorization(http, client_id)
            unticked = await approve(http, page, gw.store, devices=())
            return page, unticked

    page, unticked = asyncio.run(scenario())
    assert 'name="device" value="local"' in page.text
    assert not re.search(r'name="device" value="[^"]+" checked', page.text)
    assert unticked.status_code == 400 and "at least one permission and one device" in unticked.text
