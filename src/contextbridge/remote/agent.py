"""ContextBridge agent — runs on each machine and dials out to the gateway.

The agent is the authority for its machine: it executes only what its own local
policy allows and keeps its own fail-closed audit log, whatever the gateway asks.
It refuses replayed calls (sequence numbers must increase on every connection
and request ids are never accepted twice), reconnects with backoff, and stops
for good when the gateway says it has been revoked.

    python -m contextbridge.remote.agent enroll --config configs/agent.yaml --code ABCD-EFGH-IJKL-MNOP
    python -m contextbridge.remote.agent run --config configs/agent.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
from contextlib import contextmanager
import json
import os
import platform
import random
import signal
import socket
import ssl
import subprocess
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidURI

from .. import __version__
from ..computer.audit import (
    AuditError,
    CallAudit,
    ComputerAuditLog,
    bind_call,
    outcome_fields,
    summarize_args,
    unbind_call,
)
from ..computer.dispatch import Engine, call_succeeded
from ..computer.policy import ComputerPolicy, PolicyError, PolicyViolation, load_policy
from ..net import is_loopback
from .protocol import (
    FATAL_ERRORS,
    HANDSHAKE_TIMEOUT_SECONDS,
    MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    auth_payload,
    b64d,
    b64e,
    decode,
    encode,
)
from .registry import validate_name
from .tls import PinMismatch, client_context, normalize_fingerprint, verify_pin

SEEN_REQUEST_IDS = 10_000
MAX_BACKOFF_SECONDS = 60.0
STARTED_NOTIFY_TIMEOUT_SECONDS = 10.0
_MAX_ERROR_TEXT = 2000


class AgentError(RuntimeError):
    """A recoverable problem; the agent reconnects."""


class FatalAgentError(RuntimeError):
    """The agent must stop: revoked, unknown, misconfigured, or the gateway identity is wrong."""


# ------------------------------------------------------------------ file ACLs


def _system32(program: str) -> str:
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", program)


def _current_user_sid() -> str:
    out = subprocess.run(
        [_system32("whoami.exe"), "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        check=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    ).stdout
    sid = out.strip().rsplit(",", 1)[-1].strip().strip('"')
    if not sid.startswith("S-1-"):
        raise OSError(f"could not determine the current user's SID from {out!r}")
    return sid


def restrict_to_owner(path: Path) -> None:
    """Make ``path`` readable only by the current user (and SYSTEM on Windows).

    POSIX: mode 0600. Windows: inherited ACEs are removed and only the current
    user and LocalSystem keep access.
    """
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    sid = _current_user_sid()
    subprocess.run(
        [_system32("icacls.exe"), str(path), "/inheritance:r", "/grant:r", f"*{sid}:F", "*S-1-5-18:F"],
        capture_output=True,
        text=True,
        check=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


# --------------------------------------------------------------------- config


@dataclass
class AgentConfig:
    path: Path
    name: str
    gateway_url: str
    fingerprint: str | None
    ca_file: Path | None
    identity_path: Path
    audit_path: Path
    policy: ComputerPolicy
    max_concurrent_calls: int = 8

    @property
    def tls(self) -> bool:
        return self.gateway_url.startswith("wss://")

    def ssl_context(self) -> ssl.SSLContext | None:
        if not self.tls:
            return None
        return client_context(fingerprint=self.fingerprint, ca_file=self.ca_file)


def _resolve(base: Path, value: Any, key: str) -> Path:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{key} is required")
    path = Path(value).expanduser()
    return path if path.is_absolute() else base / path


def load_agent_config(path: str | Path) -> AgentConfig:
    config_path = Path(path).expanduser().resolve()
    with config_path.open(encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    base = config_path.parent
    name = validate_name(cfg.get("name", ""))
    gateway = cfg.get("gateway") or {}
    url = gateway.get("url")
    if not isinstance(url, str):
        raise PolicyError("gateway.url is required")
    parts = urlsplit(url)
    if parts.scheme not in ("ws", "wss") or not parts.hostname:
        raise PolicyError("gateway.url must be wss://host:port")
    if parts.scheme == "ws" and not is_loopback(parts.hostname):
        raise PolicyError("gateway.url must use wss:// (TLS) unless the gateway is on this machine")
    fingerprint = gateway.get("fingerprint")
    if fingerprint:
        fingerprint = normalize_fingerprint(fingerprint)
    ca_file = _resolve(base, gateway["ca_file"], "gateway.ca_file") if gateway.get("ca_file") else None
    identity = _resolve(base, cfg.get("identity"), "identity")
    audit = _resolve(base, cfg.get("audit_log"), "audit_log")
    policy = load_policy(cfg, protected=(config_path, audit), hidden=(identity,))
    max_calls = cfg.get("max_concurrent_calls", 8)
    if not isinstance(max_calls, int) or max_calls < 1:
        raise PolicyError("max_concurrent_calls must be a positive integer")
    return AgentConfig(config_path, name, url, fingerprint, ca_file, identity, audit, policy, max_calls)


# ------------------------------------------------------------------- identity


@dataclass
class Identity:
    device_id: str
    name: str
    gateway_id: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> str:
        raw = self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return b64e(raw)

    def sign(self, payload: bytes) -> str:
        return b64e(self.private_key.sign(payload))

    def save(self, path: Path) -> None:
        raw = self.private_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        data = {"device_id": self.device_id, "name": self.name, "gateway_id": self.gateway_id, "private_key": b64e(raw)}
        path.parent.mkdir(parents=True, exist_ok=True)
        # Create the file empty, lock it down, and only then write the key into it.
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        try:
            restrict_to_owner(path)
            with path.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except (OSError, subprocess.CalledProcessError) as exc:
            with contextlib.suppress(OSError):
                path.unlink()
            raise FatalAgentError(f"could not store the device key securely at {path}: {exc}") from None

    @classmethod
    def load(cls, path: Path) -> Identity:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            key = Ed25519PrivateKey.from_private_bytes(b64d(data["private_key"], field="private_key"))
            return cls(data["device_id"], data["name"], data["gateway_id"], key)
        except FileNotFoundError:
            raise FatalAgentError(f"{path} not found; enroll this device first") from None
        except (KeyError, ValueError, TypeError, ProtocolError) as exc:
            raise FatalAgentError(f"{path} is not a valid agent identity: {exc}") from None


def _host_info() -> dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "agent_version": __version__,
        "python": platform.python_version(),
    }


async def _open(config: AgentConfig) -> ClientConnection:
    ws = await connect(
        config.gateway_url,
        ssl=config.ssl_context(),
        max_size=MAX_MESSAGE_BYTES,
        open_timeout=HANDSHAKE_TIMEOUT_SECONDS,
        ping_interval=20,
        ping_timeout=20,
        close_timeout=5,
    )
    if config.tls and config.fingerprint:
        try:
            verify_pin(ws.transport.get_extra_info("ssl_object"), config.fingerprint)
        except PinMismatch:
            await ws.close()
            raise
    return ws


async def _expect(ws: ClientConnection, kind: str) -> dict[str, Any]:
    msg = decode(await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT_SECONDS), expect=kind)
    if msg["type"] == "error":
        text = f"gateway refused: {msg.get('code')}: {msg.get('message')}"
        if msg.get("code") in FATAL_ERRORS:
            raise FatalAgentError(text)
        raise AgentError(text)
    return msg


async def enroll(config: AgentConfig, code: str) -> Identity:
    """Register this machine with the gateway using a one-time code; writes the identity file."""
    if config.identity_path.exists():
        raise FatalAgentError(f"{config.identity_path} already exists; this device is already enrolled")
    key = Ed25519PrivateKey.generate()
    pending = Identity("", config.name, "", key)
    ws = await _open(config)
    try:
        await ws.send(
            encode(
                {
                    "type": "enroll",
                    "version": PROTOCOL_VERSION,
                    "code": code,
                    "name": config.name,
                    "public_key": pending.public_key,
                    "info": _host_info(),
                }
            )
        )
        reply = await _expect(ws, "enrolled")
    finally:
        await ws.close()
    if reply.get("name") != config.name:
        raise FatalAgentError(
            f"the code was issued for device {reply.get('name')!r}, but this agent is configured as {config.name!r}"
        )
    identity = Identity(str(reply["device_id"]), config.name, str(reply["gateway_id"]), key)
    identity.save(config.identity_path)
    return identity


# ---------------------------------------------------------------------- agent


class Agent:
    def __init__(self, config: AgentConfig, identity: Identity, *, audit: ComputerAuditLog) -> None:
        if identity.name != config.name:
            raise FatalAgentError(f"identity belongs to {identity.name!r}, config says {config.name!r}")
        self.config = config
        self.identity = identity
        self.audit = audit
        self.engine = Engine(config.policy, on_exit=self._on_exit)
        self.connected = asyncio.Event()
        self._ws: ClientConnection | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._send_lock = asyncio.Lock()
        self._calls = asyncio.Semaphore(config.max_concurrent_calls)
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._last_seq = 0
        self._tasks: set[asyncio.Task[None]] = set()
        self._stopping = asyncio.Event()
        self._backoff = 1.0

    def stop(self) -> None:
        self._stopping.set()
        if self._ws is not None:
            task = asyncio.ensure_future(self._ws.close())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    # ----------------------------------------------------------- connection

    async def run(self) -> None:
        """Stay connected until stopped; raises FatalAgentError when the gateway refuses us for good."""
        self._loop = asyncio.get_running_loop()
        self._backoff = 1.0
        try:
            while not self._stopping.is_set():
                try:
                    await self._session()
                except FatalAgentError:
                    raise
                except PinMismatch as exc:
                    raise FatalAgentError(str(exc)) from None
                except (OSError, ConnectionClosed, InvalidHandshake, TimeoutError, ProtocolError, AgentError) as exc:
                    self._log("gateway_unreachable", reason=f"{type(exc).__name__}: {exc}"[:300])
                if self._stopping.is_set():
                    break
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stopping.wait(), self._backoff * random.uniform(0.5, 1.0))
                self._backoff = min(self._backoff * 2, MAX_BACKOFF_SECONDS)
        finally:
            self.engine.shutdown()

    async def _session(self) -> None:
        ws = await _open(self.config)
        try:
            await ws.send(encode({"type": "hello", "version": PROTOCOL_VERSION, "device_id": self.identity.device_id}))
            challenge = await _expect(ws, "challenge")
            if challenge.get("gateway_id") != self.identity.gateway_id:
                raise FatalAgentError("gateway identity does not match the one this device enrolled with")
            nonce = b64d(challenge.get("nonce"), field="nonce")
            if len(nonce) != 32:
                raise ProtocolError("challenge nonce must be 32 bytes")
            signature = self.identity.sign(auth_payload(self.identity.gateway_id, self.identity.device_id, nonce))
            capabilities = {
                "tools": sorted(self.engine.tools),
                "policy": self.config.policy.summary(),
                "info": _host_info(),
            }
            await ws.send(encode({"type": "auth", "signature": signature, "capabilities": capabilities}))
            welcome = await _expect(ws, "welcome")
            heartbeat = min(max(float(welcome.get("heartbeat_seconds") or 15), 1.0), 300.0)

            self._ws = ws
            self._last_seq = 0
            # However the session ends, its loss is a fresh outage, not more of an earlier one.
            self._backoff = 1.0
            self.connected.set()
            self._log("gateway_connected", gateway=self.config.gateway_url, tools=sorted(self.engine.tools))
            beat = asyncio.create_task(self._heartbeats(ws, heartbeat))
            try:
                async for raw in ws:
                    msg = decode(raw)
                    if msg["type"] == "call":
                        self._accept_call(msg)
                    elif msg["type"] == "error":
                        text = f"gateway closed the session: {msg.get('code')}: {msg.get('message')}"
                        if msg.get("code") in FATAL_ERRORS:
                            raise FatalAgentError(text)
                        raise AgentError(text)
                    else:
                        raise ProtocolError(f"unexpected message {msg['type']!r}")
            finally:
                beat.cancel()
                self._ws = None
                self.connected.clear()
                self._log("gateway_disconnected", gateway=self.config.gateway_url)
        finally:
            await ws.close()

    async def _heartbeats(self, ws: ClientConnection, interval: float) -> None:
        with contextlib.suppress(ConnectionClosed, asyncio.CancelledError):
            while True:
                await asyncio.sleep(interval)
                await self._send({"type": "heartbeat"})

    async def _send(self, message: dict[str, Any]) -> None:
        ws = self._ws
        if ws is None:
            raise ConnectionClosed(None, None)
        async with self._send_lock:
            await ws.send(encode(message))

    # ---------------------------------------------------------------- calls

    def _accept_call(self, msg: dict[str, Any]) -> None:
        request_id = msg.get("request_id")
        seq = msg.get("seq")
        reason = None
        if not isinstance(request_id, str) or not request_id or len(request_id) > 64:
            reason = "call has no valid request_id"
        elif not isinstance(seq, int) or isinstance(seq, bool) or seq <= self._last_seq:
            reason = "replayed or out-of-order call (sequence number did not increase)"
        elif request_id in self._seen:
            reason = "replayed call (request_id already used)"
        if reason is None:
            self._last_seq = seq
            self._seen[request_id] = None
            if len(self._seen) > SEEN_REQUEST_IDS:
                self._seen.popitem(last=False)
            self._spawn(self._run_call(request_id, msg.get("tool"), msg.get("args")))
            return
        self._log("denied", request_id=str(request_id)[:64], tool=str(msg.get("tool"))[:64], reason=reason)
        if isinstance(request_id, str):
            self._spawn(self._reply(request_id, ok=False, kind="denied", message=reason, started=False))

    def _spawn(self, coro: Any) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run_call(self, request_id: str, tool: Any, args: Any) -> None:
        client = f"gateway:{self.identity.gateway_id}"
        tool_name = tool if isinstance(tool, str) else "<invalid>"
        try:
            self.audit.record("requested", request_id=request_id, tool=tool_name, client=client, **summarize_args(args))
        except AuditError:
            await self._reply(request_id, ok=False, kind="failed", message="agent audit log unavailable", started=False)
            return
        if not isinstance(tool, str) or not isinstance(args, dict):
            self.audit.record("denied", request_id=request_id, tool=tool_name, client=client, reason="malformed call")
            await self._reply(request_id, ok=False, kind="denied", message="malformed call", started=False)
            return

        loop = asyncio.get_running_loop()

        def notify_gateway(fields: dict[str, Any]) -> None:
            # Runs in the worker thread. The operation does not start unless the gateway was told.
            future = asyncio.run_coroutine_threadsafe(
                self._send({"type": "started", "request_id": request_id, "fields": fields}), loop
            )
            future.result(timeout=STARTED_NOTIFY_TIMEOUT_SECONDS)

        call = CallAudit(self.audit, request_id, tool, client, on_started=notify_gateway)
        async with self._calls:
            binding = bind_call(call)
            try:
                result = await asyncio.to_thread(self.engine.execute, tool, args)
            except Exception as exc:
                if call.started:
                    event, kind = "completed", "failed"
                elif isinstance(exc, PolicyViolation):
                    event, kind = "denied", "denied"
                else:
                    event, kind = "failed", "failed"
                message = str(exc)[:_MAX_ERROR_TEXT] or type(exc).__name__
                with contextlib.suppress(AuditError):
                    call.emit(
                        event,
                        success=False if event == "completed" else None,
                        detail=type(exc).__name__,
                        reason=message,
                    )
                await self._reply(request_id, ok=False, kind=kind, message=message, started=call.started)
                return
            finally:
                unbind_call(binding)
        with contextlib.suppress(AuditError):
            call.emit("completed", success=call_succeeded(tool, result), **outcome_fields(result))
        await self._reply(request_id, ok=True, result=result, started=True)

    async def _reply(self, request_id: str, *, ok: bool, started: bool, **body: Any) -> None:
        message: dict[str, Any] = {"type": "result", "request_id": request_id, "ok": ok, "started": started}
        if ok:
            message["result"] = body["result"]
        else:
            message["error"] = {"kind": body["kind"], "message": body["message"]}
        try:
            await self._send(message)
        except (ConnectionClosed, OSError):
            self._log("result_undelivered", request_id=request_id)

    def _on_exit(self, status: dict[str, Any]) -> None:
        fields = {k: status[k] for k in ("session_id", "pid", "command", "exit_code", "timed_out")}
        success = status["exit_code"] == 0 and not status["timed_out"]
        self.audit.record("exited", tool="session", success=success, **fields)
        loop = self._loop
        if loop is not None and not loop.is_closed():
            event = {"type": "event", "event": "exited", "success": success, **fields}
            asyncio.run_coroutine_threadsafe(self._send(event), loop)

    def _log(self, event: str, **fields: Any) -> None:
        try:
            self.audit.record(event, **fields)
        except AuditError as exc:
            print(f"[agent] could not audit {event}: {exc}", file=sys.stderr, flush=True)


@contextmanager
def single_agent_instance(identity_path: Path):
    """Prevent two CLI agents with the same identity competing for a gateway slot.

    The lock is held for the full running lifetime, not just startup.
    Its companion file is not an identity or a secret; stale files are safe.
    """
    lock_path = identity_path.with_name(identity_path.name + ".run.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock:
        try:
            if os.name == "nt":
                import msvcrt

                lock.seek(0)
                if lock.read(1) == b"":
                    lock.write(b"\0")
                    lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise FatalAgentError(
                f"another ContextBridge agent is already running with identity {identity_path}"
            ) from exc
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


# ------------------------------------------------------------------------ CLI


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="ContextBridge agent")
    sub = ap.add_subparsers(dest="command", required=True)
    enroll_cmd = sub.add_parser("enroll", help="register this machine with the gateway")
    enroll_cmd.add_argument("--config", required=True)
    enroll_cmd.add_argument("--code", required=True, help="one-time code from `contextbridge-admin pair`")
    run_cmd = sub.add_parser("run", help="connect to the gateway and serve tool calls")
    run_cmd.add_argument("--config", required=True)
    run_cmd.add_argument("--log-file", help="append diagnostics here (for services with no console)")
    args = ap.parse_args(argv)

    if getattr(args, "log_file", None):
        log_path = Path(args.log_file).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        sys.stderr = log_path.open("a", buffering=1, encoding="utf-8")

    try:
        config = load_agent_config(args.config)
    except (PolicyError, ValueError, OSError) as exc:
        raise SystemExit(f"{args.config}: {exc}") from None

    if args.command == "enroll":
        try:
            identity = asyncio.run(enroll(config, args.code))
        except (FatalAgentError, AgentError, PinMismatch) as exc:
            raise SystemExit(f"enrollment failed: {exc}") from None
        except (OSError, InvalidHandshake, InvalidURI, TimeoutError) as exc:
            raise SystemExit(f"could not reach the gateway: {exc}") from None
        print(f"[agent] enrolled as {identity.name} ({identity.device_id}); identity saved to {config.identity_path}")
        return

    try:
        identity = Identity.load(config.identity_path)
        audit = ComputerAuditLog(config.audit_path, route="agent")
    except (FatalAgentError, AuditError) as exc:
        raise SystemExit(str(exc)) from None

    async def serve() -> None:
        agent = Agent(config, identity, audit=audit)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):  # Windows
                loop.add_signal_handler(sig, agent.stop)
        audit.record("agent_started", device=config.name, gateway=config.gateway_url, policy=config.policy.summary())
        print(f"[agent] {config.name} connecting to {config.gateway_url}", file=sys.stderr, flush=True)
        await agent.run()

    try:
        with single_agent_instance(config.identity_path):
            asyncio.run(serve())
    except FatalAgentError as exc:
        raise SystemExit(f"[agent] stopped: {exc}") from None
    except KeyboardInterrupt:
        print("[agent] stopped", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
