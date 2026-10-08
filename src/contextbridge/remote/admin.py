"""Gateway administration: TLS setup, device pairing, listing, and revocation.

Runs on the gateway host and works directly on the files named in the
``agents`` section of the gateway config. Pairing is deliberately not an MCP
tool: whoever holds an MCP token must not be able to enroll new machines.

    contextbridge-admin --config configs/computer.yaml tls-init --hostname friday --ip 100.101.102.103
    contextbridge-admin --config configs/computer.yaml pair thanatos
    contextbridge-admin --config configs/computer.yaml devices
    contextbridge-admin --config configs/computer.yaml revoke thanatos
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import yaml

from ..computer.server import ALL_SCOPES, AgentListenerConfig
from .registry import DEFAULT_ENROLLMENT_MINUTES, DeviceRegistry, RegistryError
from .tls import cert_fingerprint, generate_self_signed


def _listener(config: str) -> AgentListenerConfig:
    path = Path(config).expanduser().resolve()
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    agents = cfg.get("agents") or {}
    if not agents:
        raise SystemExit(f"{path}: no agents section")
    return AgentListenerConfig(agents, path.parent, path)


def _fingerprint(listener: AgentListenerConfig) -> str | None:
    if listener.tls_cert and listener.tls_cert.exists():
        return cert_fingerprint(listener.tls_cert)
    return None


def cmd_tls_init(listener: AgentListenerConfig, args: argparse.Namespace) -> None:
    if not listener.tls_cert or not listener.tls_key:
        raise SystemExit("set agents.tls_cert and agents.tls_key in the gateway config first")
    if (listener.tls_cert.exists() or listener.tls_key.exists()) and not args.force:
        raise SystemExit(f"{listener.tls_cert} already exists; pass --force to replace it (agents must re-pin)")
    hostnames = args.hostname or ["contextbridge"]
    fingerprint = generate_self_signed(listener.tls_cert, listener.tls_key, hostnames=hostnames, ips=args.ip or [])
    print(f"certificate: {listener.tls_cert}")
    print(f"private key: {listener.tls_key} (mode 0600)")
    print(f"fingerprint: {fingerprint}")


def cmd_pair(listener: AgentListenerConfig, args: argparse.Namespace) -> None:
    scopes = args.scopes.split(",") if args.scopes else list(ALL_SCOPES)
    unknown = [s for s in scopes if s not in ALL_SCOPES]
    if unknown:
        raise SystemExit(f"unknown scope(s) {unknown}; valid: {list(ALL_SCOPES)}")
    registry = DeviceRegistry(listener.registry)
    try:
        code, expires = registry.create_enrollment(args.name, scopes, minutes=args.minutes)
    except RegistryError as exc:
        raise SystemExit(str(exc)) from None
    fingerprint = _fingerprint(listener)
    scheme = "wss" if fingerprint else "ws"
    print(f"Enrollment code for {args.name}: {code}")
    print(f"Expires: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(expires))} (single use)")
    print(f"Scopes:  {', '.join(scopes)}")
    print()
    print(f"On {args.name}, set in its agent config:")
    print(f"  name: {args.name}")
    print("  gateway:")
    print(f"    url: {scheme}://<gateway address>:{listener.port}")
    if fingerprint:
        print(f"    fingerprint: {fingerprint}")
    print("then run:")
    print(f"  contextbridge-agent enroll --config <agent config> --code {code}")


def cmd_devices(listener: AgentListenerConfig, args: argparse.Namespace) -> None:
    registry = DeviceRegistry(listener.registry)
    devices = registry.devices()
    if not devices and not registry.pending_enrollments():
        print("no devices enrolled")
    for device in sorted(devices, key=lambda d: (d.revoked_at is not None, d.name)):
        status = f"revoked {device.revoked_at}" if device.revoked_at else "active"
        host = device.info.get("hostname", "?")
        print(f"{device.name:<20} {device.device_id:<22} {status:<30} {','.join(device.scopes)}  host={host}")
    for pending in registry.pending_enrollments():
        print(f"{pending['name']:<20} {'(pending enrollment)':<22} expires {pending['expires_at']:<22}")


def cmd_revoke(listener: AgentListenerConfig, args: argparse.Namespace) -> None:
    try:
        what = DeviceRegistry(listener.registry).revoke(args.name)
    except RegistryError as exc:
        raise SystemExit(str(exc)) from None
    print(f"revoked {what}; a running gateway disconnects it within a second")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="ContextBridge gateway administration")
    ap.add_argument("--config", required=True, help="gateway config (configs/computer.yaml)")
    sub = ap.add_subparsers(dest="command", required=True)

    tls = sub.add_parser("tls-init", help="create the agent listener's self-signed certificate")
    tls.add_argument("--hostname", action="append", help="DNS name agents use (repeatable)")
    tls.add_argument("--ip", action="append", help="IP address agents use (repeatable)")
    tls.add_argument("--force", action="store_true")
    tls.set_defaults(fn=cmd_tls_init)

    pair = sub.add_parser("pair", help="issue a one-time enrollment code for a new device")
    pair.add_argument("name")
    pair.add_argument("--scopes", help=f"comma-separated, default all: {','.join(ALL_SCOPES)}")
    pair.add_argument("--minutes", type=float, default=DEFAULT_ENROLLMENT_MINUTES, help="code lifetime")
    pair.set_defaults(fn=cmd_pair)

    devices = sub.add_parser("devices", help="list enrolled devices and pending enrollments")
    devices.set_defaults(fn=cmd_devices)

    revoke = sub.add_parser("revoke", help="revoke a device (or cancel a pending enrollment)")
    revoke.add_argument("name")
    revoke.set_defaults(fn=cmd_revoke)

    args = ap.parse_args(argv)
    args.fn(_listener(args.config), args)


if __name__ == "__main__":
    main()
