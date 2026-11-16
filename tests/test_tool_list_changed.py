"""The gateway tells connected MCP clients when the tools it offers change (tools/list_changed).

The gateway advertises ``tools.listChanged``, so a client may cache the tool list until told
otherwise. Devices come and go, and their MCP servers start late, so the list does change.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket

import mcp.types
from fastmcp import Client
from fastmcp.client.messages import MessageHandler
from helpers import free_port
from test_federation import FAKE_TOOLS, _late_server
from test_remote import DEVICE, allow_scopes, connected_agent, gateway, wait_for

from contextbridge.computer import federation as fed
from contextbridge.computer.audit import ComputerAuditLog
from contextbridge.computer.dispatch import build_federation
from contextbridge.computer.federation import load_mcp_servers
from contextbridge.computer.server import ALL_SCOPES, build_router, create_computer_server


class Recorder(MessageHandler):
    def __init__(self) -> None:
        super().__init__()
        self.changes = 0

    async def on_tool_list_changed(self, message: mcp.types.ToolListChangedNotification) -> None:
        self.changes += 1


def client_for(server) -> tuple[Client, Recorder]:
    recorder = Recorder()
    return Client(server, message_handler=recorder), recorder


def remote_server(gw):
    return create_computer_server(
        None, audit=ComputerAuditLog(gw.audit_path, echo=False), hub=gw.hub, authorize=allow_scopes(*ALL_SCOPES)
    )


def test_clients_hear_when_a_device_connects_and_disconnects(tmp_path, workspace):
    async def scenario():
        async with gateway(tmp_path) as gw:
            client, recorder = client_for(remote_server(gw))
            async with client:
                before = {t.name for t in await client.list_tools()}
                async with connected_agent(tmp_path, workspace, gw):
                    await wait_for(lambda: recorder.changes >= 1)
                    online = {t.name for t in await client.list_tools()}
                    seen = recorder.changes
                await wait_for(lambda: recorder.changes > seen)
                after = {t.name for t in await client.list_tools()}
            return before, online, after

    before, online, after = asyncio.run(scenario())
    assert before == {"list_devices"} and "read_file" in online and after == {"list_devices"}


def test_clients_hear_when_a_connected_device_gains_mcp_tools(tmp_path, workspace, monkeypatch):
    monkeypatch.setattr(fed, "RETRY_START_SECONDS", 0.2)
    ready = tmp_path / "ready"

    async def scenario():
        async with gateway(tmp_path) as gw, connected_agent(
            tmp_path, workspace, gw, mcp_servers=_late_server(ready)
        ):
            client, recorder = client_for(remote_server(gw))
            async with client:
                assert not FAKE_TOOLS & {t.name for t in await client.list_tools()}
                ready.write_text("", encoding="utf-8")
                await wait_for(lambda: recorder.changes >= 1, timeout=60)
                return {t.name for t in await client.list_tools()}

    assert FAKE_TOOLS <= asyncio.run(scenario())


def test_clients_hear_when_the_gateways_own_mcp_server_starts_late(policy, tmp_path, monkeypatch):
    monkeypatch.setattr(fed, "RETRY_START_SECONDS", 0.2)
    ready = tmp_path / "ready"
    federation = build_federation(load_mcp_servers({"mcp_servers": _late_server(ready)}), policy)
    audit = ComputerAuditLog(tmp_path / "audit.jsonl", echo=False)
    router = build_router(policy, audit=audit, federation=federation)
    server = create_computer_server(None, audit=audit, router=router, authorize=allow_scopes(*ALL_SCOPES))

    async def scenario():
        client, recorder = client_for(server)
        async with client:
            federation.start()
            assert not FAKE_TOOLS & {t.name for t in await client.list_tools()}
            ready.write_text("", encoding="utf-8")
            await wait_for(lambda: recorder.changes >= 1, timeout=60)
            return {t.name for t in await client.list_tools()}

    try:
        assert FAKE_TOOLS <= asyncio.run(scenario())
    finally:
        federation.close()


def test_only_a_change_to_the_offered_tools_notifies(tmp_path, workspace):
    # Only a change to what is offered is worth a notification; a heartbeat or a call is not.
    async def scenario():
        async with gateway(tmp_path) as gw:
            client, recorder = client_for(remote_server(gw))
            async with client:
                await client.list_tools()
                async with connected_agent(tmp_path, workspace, gw):
                    await wait_for(lambda: recorder.changes >= 1)
                    await client.call_tool("list_devices", {})
                    await asyncio.sleep(0.5)
                    return recorder.changes

    assert asyncio.run(scenario()) == 1


def test_notifications_reach_a_client_over_streamable_http(tmp_path, workspace):
    # Remote clients (Claude, ChatGPT) connect over HTTP, where a notification that answers no
    # request travels on the client's standing GET stream.
    port = free_port()

    async def scenario():
        async with gateway(tmp_path) as gw:
            server = remote_server(gw)
            serving = asyncio.create_task(
                server.run_http_async(host="127.0.0.1", port=port, show_banner=False, log_level="warning")
            )
            try:
                await wait_for(lambda: _listening(port), timeout=30)
                recorder = Recorder()
                async with Client(f"http://127.0.0.1:{port}/mcp", message_handler=recorder) as client:
                    await client.list_tools()
                    async with connected_agent(tmp_path, workspace, gw):
                        await wait_for(lambda: recorder.changes >= 1, timeout=10)
                        return {t.name for t in await client.list_tools()}
            finally:
                serving.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await serving

    assert "read_file" in asyncio.run(scenario())


def _listening(port: int) -> bool:
    with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=0.2):
        return True
    return False
