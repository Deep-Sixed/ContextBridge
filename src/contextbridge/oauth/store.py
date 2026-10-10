"""Persistent OAuth state: owner credentials, clients, authorization codes, and grants.

One JSON file (mode 0600), read-modify-written under an exclusive lock so the
gateway and the admin CLI can both change it; the gateway reloads it when it
changes, so a revocation from the CLI applies to the next request. Writes go
through a fixed ``<name>.tmp`` file (safe under the lock) so the gateway can
hide all three paths -- state, ``.lock``, ``.tmp`` -- from the file tools.

The owner passphrase is an scrypt hash, and authorization codes, access tokens,
and refresh tokens are SHA-256 hashes. The TOTP secret and any client secrets
issued at registration are kept as issued (verifying them needs the original);
a client secret alone grants nothing without a code or refresh token.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from . import totp

try:
    import fcntl
except ImportError:  # the gateway runs on Linux
    fcntl = None  # type: ignore[assignment]

STATE_VERSION = 1
LOCKOUT_FAILURES = 5
LOCKOUT_WINDOW_SECONDS = 15 * 60
LOCKOUT_SECONDS = 15 * 60
MIN_PASSPHRASE_LENGTH = 12
UNUSED_CLIENT_SECONDS = 24 * 3600
MAX_CLIENTS = 50
_SCRYPT = {"n": 2**14, "r": 8, "p": 1}


class OAuthStateError(ValueError):
    """Raised when the OAuth state is missing, unreadable, or misused."""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_passphrase(passphrase: str) -> str:
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise OAuthStateError(f"the passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, dklen=32, **_SCRYPT)
    params = f"{_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}"
    return f"scrypt${params}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def check_passphrase(passphrase: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        actual = hashlib.scrypt(
            passphrase.encode("utf-8"), salt=base64.b64decode(salt), dklen=32, n=int(n), r=int(r), p=int(p)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, base64.b64decode(digest))


class OAuthStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._state: dict[str, Any] | None = None
        self._stamp: tuple[int, int, int] | None = None

    # -------------------------------------------------------------- storage

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {
            "version": STATE_VERSION,
            "owner": None,
            "lockout": {"failures": [], "locked_until": 0},
            "clients": {},
            "codes": {},
            "grants": {},
        }

    def _file_stamp(self) -> tuple[int, int, int] | None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return None
        return (st.st_ino, st.st_mtime_ns, st.st_size)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty()
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise OAuthStateError(f"cannot read OAuth state {self.path}: {exc}") from None
        if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
            raise OAuthStateError(f"{self.path} is not a version {STATE_VERSION} OAuth state file")
        return state

    @property
    def lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    @property
    def temp_path(self) -> Path:
        return self.path.with_name(self.path.name + ".tmp")

    def _write(self, state: dict[str, Any]) -> None:
        tmp = self.temp_path
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, indent=1, sort_keys=True)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        self._state = state
        self._stamp = self._file_stamp()

    @contextlib.contextmanager
    def update(self) -> Iterator[dict[str, Any]]:
        """Read-modify-write under an exclusive lock shared with other processes."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "a") as lock:
            if fcntl is not None:
                fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                state = self._read()
                self._prune(state)
                yield state
                self._write(state)
            finally:
                if fcntl is not None:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def refresh(self) -> None:
        stamp = self._file_stamp()
        if self._state is None or stamp != self._stamp:
            self._state = self._read()
            self._stamp = stamp

    @property
    def state(self) -> dict[str, Any]:
        self.refresh()
        assert self._state is not None
        return self._state

    @staticmethod
    def _prune(state: dict[str, Any]) -> None:
        now = time.time()
        state["codes"] = {k: v for k, v in state["codes"].items() if v["expires_at"] > now}
        for grant in state["grants"].values():
            grant["access"] = {k: exp for k, exp in grant["access"].items() if exp > now}
        state["grants"] = {
            gid: g
            for gid, g in state["grants"].items()
            if g["revoked_at"] is None and g["refresh_expires_at"] > now
        }
        authorized = {g["client_id"] for g in state["grants"].values()}
        state["clients"] = {
            cid: c
            for cid, c in state["clients"].items()
            if cid in authorized or c.get("authorized") or now - c["registered_at"] < UNUSED_CLIENT_SECONDS
        }

    # ---------------------------------------------------------------- owner

    def owner_initialized(self) -> bool:
        owner = self.state.get("owner")
        return bool(owner and owner.get("passphrase") and owner.get("totp_secret"))

    def set_owner(self, passphrase: str, totp_secret: str) -> None:
        hashed = hash_passphrase(passphrase)
        with self.update() as state:
            state["owner"] = {"passphrase": hashed, "totp_secret": totp_secret, "totp_last_counter": 0}
            state["lockout"] = {"failures": [], "locked_until": 0}

    def locked_until(self) -> float:
        until = float(self.state["lockout"].get("locked_until", 0))
        return until if until > time.time() else 0.0

    def unlock(self) -> None:
        with self.update() as state:
            state["lockout"] = {"failures": [], "locked_until": 0}

    def verify_owner(self, passphrase: str, code: str) -> str | None:
        """Check the passphrase and TOTP code. Returns None on success, else the reason it failed.

        Failures count toward a lockout; a TOTP code is accepted only once.
        """
        with self.update() as state:
            now = time.time()
            lockout = state["lockout"]
            if lockout.get("locked_until", 0) > now:
                return "locked"
            owner = state.get("owner") or {}
            ok_pass = check_passphrase(passphrase or "", owner.get("passphrase", ""))
            counter = totp.verify(owner.get("totp_secret", ""), code, last_counter=owner.get("totp_last_counter", 0))
            if ok_pass and counter is not None:
                owner["totp_last_counter"] = counter
                lockout["failures"] = []
                return None
            failures = [t for t in lockout.get("failures", []) if now - t < LOCKOUT_WINDOW_SECONDS] + [now]
            lockout["failures"] = failures
            if len(failures) >= LOCKOUT_FAILURES:
                lockout["locked_until"] = now + LOCKOUT_SECONDS
                lockout["failures"] = []
                return "locked"
            return "bad_credentials"

    # -------------------------------------------------------------- clients

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        return self.state["clients"].get(client_id)

    def save_client(self, client: dict[str, Any]) -> None:
        """Store a newly registered client. When full, the oldest never-approved client makes room."""
        with self.update() as state:
            clients = state["clients"]
            if client["client_id"] not in clients and len(clients) >= MAX_CLIENTS:
                unapproved = sorted((c["registered_at"], cid) for cid, c in clients.items() if not c.get("authorized"))
                if not unapproved:
                    raise OAuthStateError(f"too many registered clients (limit {MAX_CLIENTS}); revoke some first")
                del clients[unapproved[0][1]]
            clients[client["client_id"]] = {**client, "registered_at": time.time(), "authorized": False}

    def clients(self) -> list[dict[str, Any]]:
        grants = self.state["grants"]
        rows = []
        for client in self.state["clients"].values():
            mine = [{"grant_id": gid, **g} for gid, g in grants.items() if g["client_id"] == client["client_id"]]
            rows.append({**client, "grants": mine})
        return rows

    # ---------------------------------------------------------------- codes

    def save_code(self, code: str, record: dict[str, Any]) -> None:
        with self.update() as state:
            state["codes"][token_hash(code)] = record
            client = state["clients"].get(record["client_id"])
            if client is not None:
                client["authorized"] = True

    def get_code(self, code: str) -> dict[str, Any] | None:
        record = self.state["codes"].get(token_hash(code))
        if record is None or record["expires_at"] <= time.time():
            return None
        return record

    # --------------------------------------------------------------- grants

    def create_grant(
        self, *, client_id: str, scopes: list[str], devices: list[str], resource: str | None,
        code: str, access_seconds: int, refresh_seconds: int,
    ) -> tuple[str, str, str]:
        """Consume ``code`` and create a grant. Returns (grant_id, access_token, refresh_token)."""
        access, refresh = new_token(), new_token()
        now = time.time()
        with self.update() as state:
            if state["codes"].pop(token_hash(code), None) is None:
                raise OAuthStateError("authorization code already used or expired")
            grant_id = "grant_" + secrets.token_hex(8)
            state["grants"][grant_id] = {
                "client_id": client_id,
                "scopes": scopes,
                "devices": devices,
                "resource": resource,
                "created_at": now,
                "refresh_hash": token_hash(refresh),
                "refresh_expires_at": now + refresh_seconds,
                "used_refresh": [],
                "access": {token_hash(access): now + access_seconds},
                "revoked_at": None,
            }
        return grant_id, access, refresh

    def find_access(self, token: str) -> tuple[str, dict[str, Any], float] | None:
        digest = token_hash(token)
        now = time.time()
        for grant_id, grant in self.state["grants"].items():
            expires = grant["access"].get(digest)
            if expires is not None and expires > now and grant["revoked_at"] is None:
                return grant_id, grant, expires
        return None

    def find_refresh(self, token: str) -> tuple[str, dict[str, Any], bool] | None:
        """Return (grant_id, grant, reused). ``reused`` means an already-rotated token was presented."""
        digest = token_hash(token)
        now = time.time()
        for grant_id, grant in self.state["grants"].items():
            if grant["revoked_at"] is not None:
                continue
            if hmac.compare_digest(grant["refresh_hash"], digest) and grant["refresh_expires_at"] > now:
                return grant_id, grant, False
            if digest in grant["used_refresh"]:
                return grant_id, grant, True
        return None

    def rotate(
        self, grant_id: str, old_refresh: str, *, scopes: list[str], access_seconds: int, refresh_seconds: int
    ) -> tuple[str, str]:
        """Swap a refresh token for a new access + refresh pair; the old refresh token stops working."""
        access, refresh = new_token(), new_token()
        now = time.time()
        with self.update() as state:
            grant = state["grants"].get(grant_id)
            if grant is None or grant["revoked_at"] is not None:
                raise OAuthStateError("grant revoked")
            if not hmac.compare_digest(grant["refresh_hash"], token_hash(old_refresh)):
                raise OAuthStateError("refresh token already used")
            grant["used_refresh"] = (grant["used_refresh"] + [grant["refresh_hash"]])[-20:]
            grant["refresh_hash"] = token_hash(refresh)
            grant["refresh_expires_at"] = now + refresh_seconds
            grant["access"][token_hash(access)] = now + access_seconds
            grant["scopes"] = scopes
        return access, refresh

    def revoke_grant(self, grant_id: str) -> None:
        with self.update() as state:
            grant = state["grants"].get(grant_id)
            if grant is not None:
                grant["revoked_at"] = time.time()

    def revoke_client(self, client_id: str) -> int:
        """Revoke every grant a client holds and forget the client. Returns the number of grants revoked."""
        with self.update() as state:
            revoked = 0
            for grant in state["grants"].values():
                if grant["client_id"] == client_id and grant["revoked_at"] is None:
                    grant["revoked_at"] = time.time()
                    revoked += 1
            state["clients"].pop(client_id, None)
            return revoked
