"""Gateway side of the agent channel.

Agents dial in over WebSocket (TLS whenever the listener is not loopback),
enroll once with a one-time code, and afterwards prove their identity on every
connection by signing a fresh challenge with their Ed25519 key. The hub then
routes tool calls to them and tracks liveness.

The hub never trusts an agent with more than its registry record allows, and an
agent never trusts the hub with more than its own local policy allows.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import secrets
import ssl
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed

from ..computer.audit import AuditError, CallAudit, ComputerAuditLog
from ..computer.dispatch import ENGINE_TOOLS
from ..computer.policy import PolicyViolation
from .protocol import (
    HANDSHAKE_TIMEOUT_SECONDS,
    MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    auth_payload,
    b64d,
    b64e,
    decode,
    encode,
    error,
)
from .registry import DeviceRecord, DeviceRegistry, EnrollmentRejected, RegistryError
from .tailnet import TailnetAdmissionDenied, verify_local_tailnet_peer

MONITOR_INTERVAL_SECONDS = 0.5
FAILED_ENROLL_DELAY_SECONDS = 1.0
_MAX_ERROR_TEXT = 2000
_INFO_KEYS = ("hostname", "platform", "agent_version", "python")
_RESERVED_AUDIT_KEYS = frozenset({"request_id", "tool", "device", "client", "event", "ts", "route"})


class DeviceUnavailable(RuntimeError):
    """The device is unknown to the hub's live connections (offline or disconnected)."""


class RemoteDenied(PolicyViolation):
    """The agent refused the call under its own local policy."""


class RemoteFailed(RuntimeError):
    """The call failed on the agent, or the agent did not answer."""

    def __init__(self, message: str, *, started: bool) -> None:
        super().__init__(message)
        self.started = started


def _clean_info(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {k: str(raw[k])[:200] for k in _INFO_KEYS if k in raw}


@dataclass
class _Pending:
    future: asyncio.Future[dict[str, Any]]
    call: CallAudit | None


@dataclass
class AgentConnection:
    device: DeviceRecord
    ws: ServerConnection
    tools: frozenset[str]
    info: dict[str, str]
    policy: dict[str, Any]
    connected_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.monotonic)
    pending: dict[str, _Pending] = field(default_factory=dict)
    dropped: bool = False
    _seq: itertools.count = field(default_factory=lambda: itertools.count(1))
    _send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def send(self, message: dict[str, Any]) -> None:
        async with self._send_lock:
            await self.ws.send(encode(message))

    async def send_call(self, message: dict[str, Any]) -> None:
        # seq is assigned under the send lock, so frames leave in seq order.
        async with self._send_lock:
            message["seq"] = next(self._seq)
            await self.ws.send(encode(message))

    async def reject(self, code: str, message: str) -> None:
        with contextlib.suppress(ConnectionClosed, OSError):
            await self.send(error(code, message))
        await self.ws.close(code=4001 if code == "revoked" else 1000, reason=message[:120])


class AgentHub:
    def __init__(
        self,
        registry: DeviceRegistry,
        audit: ComputerAuditLog,
        *,
        heartbeat_seconds: float = 15.0,
        call_timeout_seconds: float = 660.0,
        allowed_tailnet_node_ids: frozenset[str] | None = None,
    ) -> None:
        self.registry = registry
        self.allowed_tailnet_node_ids = allowed_tailnet_node_ids
        self.audit = audit
        self.heartbeat_seconds = heartbeat_seconds
        self.call_timeout_seconds = call_timeout_seconds
        self._connections: dict[str, AgentConnection] = {}
        self._last_seen_wall: dict[str, float] = {}
        self._server: Server | None = None
        self._monitor_task: asyncio.Task[None] | None = None
        self._background: set[asyncio.Task[None]] = set()
        self.port: int | None = None

    # ------------------------------------------------------------ lifecycle

    async def start(self, host: str, port: int, ssl_context: ssl.SSLContext | None = None) -> int:
        self.registry.refresh()
        self._server = await serve(
            self._handle,
            host,
            port,
            ssl=ssl_context,
            max_size=MAX_MESSAGE_BYTES,
            open_timeout=HANDSHAKE_TIMEOUT_SECONDS,
            ping_interval=20,
            ping_timeout=20,
        )
        self.port = self._server.sockets[0].getsockname()[1]
        self._monitor_task = asyncio.create_task(self._monitor())
        return self.port

    async def close(self) -> None:
        if self._monitor_task is not None:
            self._monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor_task
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    # -------------------------------------------------------------- queries

    def connection(self, name: str) -> AgentConnection | None:
        for conn in self._connections.values():
            if conn.device.name == name:
                return conn
        return None

    def online_tools(self, devices: frozenset[str] | None = None) -> frozenset[str]:
        """Tools offered by connected devices (only those named in ``devices``, unless None)."""
        tools: set[str] = set()
        for conn in self._connections.values():
            if devices is None or conn.device.name in devices:
                tools |= conn.tools
        return frozenset(tools)

    def describe(self) -> list[dict[str, Any]]:
        rows = []
        for device in sorted(self.registry.devices(), key=lambda d: d.name):
            if not device.active:
                continue
            conn = self._connections.get(device.device_id)
            row: dict[str, Any] = {
                "device": device.name,
                "device_id": device.device_id,
                "online": conn is not None,
                "scopes": device.scopes,
                "enrolled_at": device.created_at,
            }
            last = self._last_seen_wall.get(device.device_id)
            if last is not None:
                row["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(last))
            if conn is not None:
                row["connected_since"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(conn.connected_at))
                row["tools"] = sorted(conn.tools)
                row["info"] = conn.info
                row["policy"] = conn.policy
            rows.append(row)
        return rows

    # --------------------------------------------------------------- calls

    async def call(self, name: str, tool: str, args: dict[str, Any], call: CallAudit | None) -> dict[str, Any]:
        conn = self.connection(name)
        if conn is None:
            raise DeviceUnavailable(f"Device '{name}' is offline.")
        if tool not in conn.tools:
            raise RemoteDenied(f"Tool '{tool}' is not enabled on device '{name}'.")
        request_id = call.request_id if call is not None else uuid.uuid4().hex[:16]
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        conn.pending[request_id] = _Pending(future, call)
        message: dict[str, Any] = {"type": "call", "request_id": request_id, "tool": tool, "args": args}
        if call is not None and call.caller is not None:
            # The agent binds sessions to it. all_sessions is not forwarded: on a remote device
            # every caller, the owner's token included, reaches only its own sessions.
            message["caller"] = call.caller
        try:
            await conn.send_call(message)
            reply = await asyncio.wait_for(future, self.call_timeout_seconds)
        except TimeoutError:
            raise RemoteFailed(
                f"Device '{name}' did not answer within {self.call_timeout_seconds:g}s.",
                started=bool(call and call.started),
            ) from None
        except ConnectionClosed:
            raise DeviceUnavailable(f"Device '{name}' disconnected.") from None
        finally:
            conn.pending.pop(request_id, None)
        if reply.get("ok") is True and isinstance(reply.get("result"), dict):
            return reply["result"]
        problem = reply.get("error") if isinstance(reply.get("error"), dict) else {}
        message = f"Device '{name}': {str(problem.get('message', 'call failed'))[:_MAX_ERROR_TEXT]}"
        if problem.get("kind") == "denied":
            raise RemoteDenied(message)
        raise RemoteFailed(message, started=bool(reply.get("started")) or bool(call and call.started))

    # ------------------------------------------------------------ handshake

    async def _handle(self, ws: ServerConnection) -> None:
        peer = str(ws.remote_address[0]) if ws.remote_address else None
        if self.allowed_tailnet_node_ids is not None:
            try:
                if peer is None:
                    raise TailnetAdmissionDenied("unknown peer address")
                await asyncio.to_thread(
                    verify_local_tailnet_peer, peer, self.allowed_tailnet_node_ids
                )
            except TailnetAdmissionDenied:
                self._log("tailnet_admission_denied", peer=peer)
                await self._refuse(ws, "tailnet_denied", "tailnet admission denied")
                return
        try:
            first = decode(
                await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT_SECONDS), expect=("enroll", "hello")
            )
            if first.get("version") != PROTOCOL_VERSION:
                await self._refuse(ws, "version", f"protocol version {PROTOCOL_VERSION} required")
                return
            if first["type"] == "enroll":
                await self._enroll(ws, first, peer)
                return
            conn = await self._authenticate(ws, first, peer)
        except (TimeoutError, ProtocolError) as exc:
            await self._refuse(ws, "protocol", str(exc) or "handshake timed out")
            return
        except ConnectionClosed:
            return
        if conn is None:
            return
        reason = "closed"
        try:
            reason = await self._serve(conn)
        except ConnectionClosed:
            reason = "connection lost"
        finally:
            self._drop(conn, reason)

    async def _refuse(self, ws: ServerConnection, code: str, message: str) -> None:
        with contextlib.suppress(ConnectionClosed, OSError):
            await ws.send(encode(error(code, message)))
            await ws.close(code=1008, reason=message[:120])

    async def _enroll(self, ws: ServerConnection, msg: dict[str, Any], peer: str | None) -> None:
        try:
            self.registry.refresh()
            record = self.registry.redeem(msg.get("code"), msg.get("public_key"), _clean_info(msg.get("info")))
        except (EnrollmentRejected, RegistryError, TypeError) as exc:
            self._log("device_enroll_rejected", peer=peer, reason=str(exc))
            await asyncio.sleep(FAILED_ENROLL_DELAY_SECONDS)
            await self._refuse(ws, "bad_code", "enrollment refused")
            return
        self._log("device_enrolled", device=record.name, device_id=record.device_id, peer=peer, scopes=record.scopes)
        with contextlib.suppress(ConnectionClosed):
            await ws.send(
                encode(
                    {
                        "type": "enrolled",
                        "device_id": record.device_id,
                        "name": record.name,
                        "gateway_id": self.registry.gateway_id,
                    }
                )
            )
            await ws.close()

    async def _authenticate(
        self, ws: ServerConnection, msg: dict[str, Any], peer: str | None
    ) -> AgentConnection | None:
        self.registry.refresh()
        device_id = msg.get("device_id")
        device = self.registry.get(device_id) if isinstance(device_id, str) else None
        if device is None or not device.active:
            code = "unknown_device" if device is None else "revoked"
            self._log("device_auth_failed", device_id=device_id, peer=peer, reason=code)
            await self._refuse(ws, code, "device is not enrolled" if device is None else "device has been revoked")
            return None
        nonce = secrets.token_bytes(32)
        gateway_id = self.registry.gateway_id
        await ws.send(encode({"type": "challenge", "nonce": b64e(nonce), "gateway_id": gateway_id}))
        reply = decode(await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT_SECONDS), expect="auth")
        if reply["type"] != "auth":
            raise ProtocolError("expected auth")
        signature = b64d(reply.get("signature"), field="signature")
        if not device.verify(signature, auth_payload(gateway_id, device.device_id, nonce)):
            self._log(
                "device_auth_failed", device=device.name, device_id=device.device_id, peer=peer, reason="bad_signature"
            )
            await self._refuse(ws, "bad_signature", "signature verification failed")
            return None
        caps = reply.get("capabilities") if isinstance(reply.get("capabilities"), dict) else {}
        reported = caps.get("tools") if isinstance(caps.get("tools"), list) else []
        conn = AgentConnection(
            device=device,
            ws=ws,
            tools=frozenset(t for t in reported if t in ENGINE_TOOLS),
            info=_clean_info(caps.get("info")),
            policy=caps.get("policy") if isinstance(caps.get("policy"), dict) else {},
        )
        previous = self._connections.get(device.device_id)
        if previous is not None:
            self._disconnect(previous, "replaced", "a newer connection for this device was accepted")
        self._connections[device.device_id] = conn
        self._last_seen_wall[device.device_id] = time.time()
        await conn.send({"type": "welcome", "heartbeat_seconds": self.heartbeat_seconds})
        self._log(
            "device_connected",
            device=device.name,
            device_id=device.device_id,
            peer=peer,
            tools=sorted(conn.tools),
            info=conn.info,
        )
        return conn

    # ------------------------------------------------------------- traffic

    async def _serve(self, conn: AgentConnection) -> str:
        async for raw in conn.ws:
            try:
                msg = decode(raw)
            except ProtocolError as exc:
                await conn.reject("protocol", str(exc))
                return f"protocol error: {exc}"
            conn.last_seen = time.monotonic()
            self._last_seen_wall[conn.device.device_id] = time.time()
            kind = msg["type"]
            if kind == "heartbeat":
                continue
            if kind == "started":
                self._on_started(conn, msg)
            elif kind == "result":
                pending = conn.pending.get(str(msg.get("request_id")))
                if pending is not None and not pending.future.done():
                    pending.future.set_result(msg)
            elif kind == "event" and msg.get("event") == "exited":
                fields = {k: msg.get(k) for k in ("session_id", "pid", "command", "exit_code", "timed_out", "caller")}
                self._log("exited", tool="session", device=conn.device.name, success=msg.get("success"), **fields)
            else:
                await conn.reject("protocol", f"unexpected message {kind!r}")
                return f"unexpected message {kind!r}"
        return "closed by agent"

    def _on_started(self, conn: AgentConnection, msg: dict[str, Any]) -> None:
        pending = conn.pending.get(str(msg.get("request_id")))
        if pending is None or pending.call is None:
            return
        fields = msg.get("fields") if isinstance(msg.get("fields"), dict) else {}
        try:
            pending.call.mark_started(**{str(k): v for k, v in fields.items() if k not in _RESERVED_AUDIT_KEYS})
        except AuditError as exc:
            print(f"[computer] could not audit remote start: {exc}", file=sys.stderr, flush=True)

    def _drop(self, conn: AgentConnection, reason: str) -> None:
        if conn.dropped:
            return
        conn.dropped = True
        if self._connections.get(conn.device.device_id) is conn:
            del self._connections[conn.device.device_id]
        for pending in conn.pending.values():
            if not pending.future.done():
                pending.future.set_exception(DeviceUnavailable(f"Device '{conn.device.name}' disconnected."))
        self._log("device_disconnected", device=conn.device.name, device_id=conn.device.device_id, reason=reason)

    def _disconnect(self, conn: AgentConnection, code: str, message: str) -> None:
        """Make the device unusable now; finish the close handshake in the background."""
        self._drop(conn, message)
        task = asyncio.create_task(conn.reject(code, message))
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    # ------------------------------------------------------------- monitor

    async def _monitor(self) -> None:
        while True:
            await asyncio.sleep(MONITOR_INTERVAL_SECONDS)
            try:
                self.registry.refresh()
            except RegistryError as exc:
                print(f"[computer] device registry unreadable: {exc}", file=sys.stderr, flush=True)
                continue
            now = time.monotonic()
            for conn in list(self._connections.values()):
                record = self.registry.get(conn.device.device_id)
                if record is None or not record.active:
                    self._log("device_revoked", device=conn.device.name, device_id=conn.device.device_id)
                    self._disconnect(conn, "revoked", "device has been revoked")
                elif now - conn.last_seen > self.heartbeat_seconds * 3:
                    self._log("device_heartbeat_lost", device=conn.device.name, device_id=conn.device.device_id)
                    self._disconnect(conn, "heartbeat", "no heartbeat received")

    def _log(self, event: str, **fields: Any) -> None:
        try:
            self.audit.record(event, **fields)
        except AuditError as exc:
            print(f"[computer] could not audit {event}: {exc}", file=sys.stderr, flush=True)
