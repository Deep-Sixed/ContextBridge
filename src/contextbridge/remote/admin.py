"""Gateway administration: devices, TLS, and remote-client (OAuth) access.

Runs on the gateway host and works directly on the files named in the
``agents`` and ``remote`` sections of the gateway config. None of this is an
MCP tool: whoever holds an MCP token must not be able to enroll machines,
approve clients, or change the owner credentials.

    contextbridge-admin --config configs/computer.yaml tls-init --hostname friday --ip 100.101.102.103
    contextbridge-admin --config configs/computer.yaml pair thanatos
    contextbridge-admin --config configs/computer.yaml devices
    contextbridge-admin --config configs/computer.yaml revoke thanatos

    contextbridge-admin --config configs/computer.yaml owner-init
    contextbridge-admin --config configs/computer.yaml oauth-clients
    contextbridge-admin --config configs/computer.yaml oauth-revoke <client_id> | --all
    contextbridge-admin --config configs/computer.yaml oauth-unlock
"""

from __future__ import annotations

import argparse
import getpass
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from ..computer.server import ALL_SCOPES, AgentListenerConfig, RemoteListenerConfig
from ..oauth import totp
from ..oauth.store import MIN_PASSPHRASE_LENGTH, OAuthStateError, OAuthStore
from .registry import DEFAULT_ENROLLMENT_MINUTES, DeviceRegistry, RegistryError
from .tls import cert_fingerprint, generate_self_signed


def _section(config: str, name: str) -> tuple[dict[str, Any], Path]:
    path = Path(config).expanduser().resolve()
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    section = cfg.get(name) or {}
    if not section:
        raise SystemExit(f"{path}: no {name} section")
    return section, path


def _listener(config: str) -> AgentListenerConfig:
    section, path = _section(config, "agents")
    return AgentListenerConfig(section, path.parent, path)


def _remote(config: str) -> RemoteListenerConfig:
    section, path = _section(config, "remote")
    return RemoteListenerConfig(section, path.parent, path)


def _store(remote: RemoteListenerConfig) -> OAuthStore:
    assert remote.state is not None
    return OAuthStore(remote.state)


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
    url = listener.public_url or f"{scheme}://<gateway address>:{listener.port}"
    print(f"    url: {url}")
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


def _when(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts)) if ts else "-"


def _read_passphrase(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("New owner passphrase (12+ characters): ")
    if getpass.getpass("Repeat it: ") != first:
        raise SystemExit("passphrases do not match")
    return first


def cmd_owner_init(remote: RemoteListenerConfig, args: argparse.Namespace) -> None:
    store = _store(remote)
    try:
        if store.owner_initialized() and not args.force:
            raise SystemExit("owner credentials already exist; pass --force to replace them (grants are kept)")
        passphrase = _read_passphrase(args.passphrase_stdin)
        if len(passphrase) < MIN_PASSPHRASE_LENGTH:
            raise SystemExit(f"the passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters")
        secret = totp.new_secret()
        uri = totp.provisioning_uri(secret, account=remote.public_host or "owner")
        print("Add this account to your authenticator app (scan the URI as a QR code, or type the secret):")
        print(f"  secret: {secret}")
        print(f"  uri:    {uri}")
        print(f"  (to show a QR code in this terminal: qrencode -t ansiutf8 '{uri}')", flush=True)
        if not args.no_confirm:
            code = input("Enter the 6-digit code it shows now: ") if sys.stdin.isatty() else sys.stdin.readline()
            if totp.verify(secret, code.strip(), last_counter=-1, window=1) is None:
                raise SystemExit("that code does not match; nothing was saved. Run owner-init again.")
        store.set_owner(passphrase, secret)
    except OAuthStateError as exc:
        raise SystemExit(str(exc)) from None
    print(f"Owner credentials saved to {remote.state}. Approving a remote client now needs the passphrase and a code.")


def cmd_oauth_clients(remote: RemoteListenerConfig, args: argparse.Namespace) -> None:
    try:
        clients = _store(remote).clients()
    except OAuthStateError as exc:
        raise SystemExit(str(exc)) from None
    if not clients:
        print("no remote clients registered")
    for client in sorted(clients, key=lambda c: c["registered_at"]):
        hosts = sorted({u.split("/")[2] for u in client.get("redirect_uris", []) if "://" in u})
        state = "approved" if client.get("authorized") else "never approved"
        print(f"{client['client_id']}  {client.get('client_name') or '(unnamed)'}  [{state}]  redirects to {', '.join(hosts)}")
        for grant in client["grants"]:
            print(
                f"    {grant['grant_id']}: scopes={','.join(grant['scopes'])} devices={','.join(grant['devices'])} "
                f"since {_when(grant['created_at'])}, refresh expires {_when(grant['refresh_expires_at'])}"
            )


def cmd_oauth_revoke(remote: RemoteListenerConfig, args: argparse.Namespace) -> None:
    store = _store(remote)
    try:
        targets = [c["client_id"] for c in store.clients()] if args.all else [args.client_id]
        if not args.all and store.get_client(args.client_id) is None:
            raise SystemExit(f"no client {args.client_id!r}; see oauth-clients")
        grants = sum(store.revoke_client(cid) for cid in targets)
    except OAuthStateError as exc:
        raise SystemExit(str(exc)) from None
    print(f"revoked {len(targets)} client(s) and {grants} grant(s); their tokens stop working on the next request")


def cmd_oauth_unlock(remote: RemoteListenerConfig, args: argparse.Namespace) -> None:
    try:
        _store(remote).unlock()
    except OAuthStateError as exc:
        raise SystemExit(str(exc)) from None
    print("consent lockout cleared")


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

    owner = sub.add_parser("owner-init", help="set the passphrase and authenticator that approve remote clients")
    owner.add_argument("--force", action="store_true", help="replace existing owner credentials")
    owner.add_argument("--passphrase-stdin", action="store_true", help="read the passphrase from stdin's first line")
    owner.add_argument("--no-confirm", action="store_true", help="save without checking a code from the authenticator")
    owner.set_defaults(fn=cmd_owner_init, section="remote")

    clients = sub.add_parser("oauth-clients", help="list remote clients and what each was granted")
    clients.set_defaults(fn=cmd_oauth_clients, section="remote")

    oauth_revoke = sub.add_parser("oauth-revoke", help="revoke a remote client's tokens and registration")
    target = oauth_revoke.add_mutually_exclusive_group(required=True)
    target.add_argument("client_id", nargs="?")
    target.add_argument("--all", action="store_true", help="revoke every remote client")
    oauth_revoke.set_defaults(fn=cmd_oauth_revoke, section="remote")

    unlock = sub.add_parser("oauth-unlock", help="clear the lockout after repeated failed approvals")
    unlock.set_defaults(fn=cmd_oauth_unlock, section="remote")

    args = ap.parse_args(argv)
    section = _remote if getattr(args, "section", "agents") == "remote" else _listener
    args.fn(section(args.config), args)


if __name__ == "__main__":
    main()
