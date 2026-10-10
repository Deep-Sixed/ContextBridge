"""Device registry: who may connect as an agent, with what key, and with what scopes.

Stored as one JSON file on the gateway host (mode 0600). The admin CLI creates
one-time enrollment codes and revokes devices; the gateway redeems codes and
re-reads the file whenever it changes, so a revocation takes effect on a running
gateway within about a second.

Enrollment codes are stored only as SHA-256 hashes, expire, and work once.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    import fcntl
except ImportError:  # Windows: the gateway runs on Linux; agents never touch the registry
    fcntl = None  # type: ignore[assignment]

NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
RESERVED_NAMES = frozenset({"local", "all", "gateway"})
DEFAULT_ENROLLMENT_MINUTES = 15
REGISTRY_VERSION = 1


class RegistryError(ValueError):
    """Raised for invalid registry operations."""


class EnrollmentRejected(PermissionError):
    """Raised when an enrollment code is unknown, expired, or already used."""


def _now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _code_hash(code: str) -> str:
    normalized = code.replace("-", "").replace(" ", "").upper()
    return hashlib.sha256(normalized.encode("ascii", errors="ignore")).hexdigest()


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_PATTERN.match(name) or name in RESERVED_NAMES:
        raise RegistryError(
            f"invalid device name {name!r}: use 1-63 lowercase letters, digits, or '-', not {sorted(RESERVED_NAMES)}"
        )
    return name


def load_public_key(text: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(text, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        raise RegistryError("public key must be a base64 raw Ed25519 key") from None


@dataclass
class DeviceRecord:
    device_id: str
    name: str
    public_key: str
    scopes: list[str]
    created_at: str
    revoked_at: str | None = None
    info: dict[str, Any] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def verify(self, signature: bytes, payload: bytes) -> bool:
        try:
            load_public_key(self.public_key).verify(signature, payload)
        except Exception:  # InvalidSignature, malformed key
            return False
        return True


class DeviceRegistry:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._state: dict[str, Any] | None = None
        self._stamp: tuple[int, int, int] | None = None

    # -------------------------------------------------------------- storage

    def _empty(self) -> dict[str, Any]:
        return {
            "version": REGISTRY_VERSION,
            "gateway_id": "gw_" + secrets.token_hex(8),
            "devices": {},
            "enrollments": {},
        }

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty()
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryError(f"cannot read device registry {self.path}: {exc}") from None
        if not isinstance(state, dict) or state.get("version") != REGISTRY_VERSION:
            raise RegistryError(f"{self.path} is not a version {REGISTRY_VERSION} device registry")
        return state

    def _write(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        self._state = state
        self._stamp = self._file_stamp()

    def _file_stamp(self) -> tuple[int, int, int] | None:
        """Identity of the file on disk; every atomic write replaces the inode."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return None
        return (st.st_ino, st.st_mtime_ns, st.st_size)

    @contextlib.contextmanager
    def _locked(self) -> Iterator[dict[str, Any]]:
        """Read-modify-write under an exclusive lock shared with other processes."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(self.path.name + ".lock")
        with open(lock_path, "a") as lock:
            if fcntl is not None:
                fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                state = self._read()
                yield state
                self._write(state)
            finally:
                if fcntl is not None:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def refresh(self) -> bool:
        """Reload if the file changed on disk. Returns True when it did."""
        stamp = self._file_stamp()
        if self._state is not None and stamp == self._stamp:
            return False
        if stamp is None:
            with self._locked():
                pass  # creates the file with a fresh gateway_id
            return True
        self._state = self._read()
        self._stamp = stamp
        return True

    @property
    def state(self) -> dict[str, Any]:
        if self._state is None:
            self.refresh()
        assert self._state is not None
        return self._state

    @property
    def gateway_id(self) -> str:
        return self.state["gateway_id"]

    # ------------------------------------------------------------- queries

    def devices(self) -> list[DeviceRecord]:
        return [DeviceRecord(**d) for d in self.state["devices"].values()]

    def get(self, device_id: str) -> DeviceRecord | None:
        raw = self.state["devices"].get(device_id)
        return DeviceRecord(**raw) if raw else None

    def by_name(self, name: str) -> DeviceRecord | None:
        for device in self.devices():
            if device.name == name and device.active:
                return device
        return None

    # ----------------------------------------------------------- mutations

    def create_enrollment(
        self, name: str, scopes: list[str], *, minutes: float = DEFAULT_ENROLLMENT_MINUTES
    ) -> tuple[str, float]:
        """Return a one-time code and its expiry (epoch seconds)."""
        validate_name(name)
        if not scopes:
            raise RegistryError("a device needs at least one scope")
        raw = base64.b32encode(secrets.token_bytes(10)).decode("ascii")
        code = "-".join(raw[i : i + 4] for i in range(0, 16, 4))
        expires = _now() + minutes * 60
        with self._locked() as state:
            self._prune(state)
            if any(d["name"] == name and d["revoked_at"] is None for d in state["devices"].values()):
                raise RegistryError(f"a device named {name!r} is already enrolled; revoke it first")
            if any(e["name"] == name for e in state["enrollments"].values()):
                raise RegistryError(f"an enrollment for {name!r} is already pending")
            state["enrollments"][_code_hash(code)] = {"name": name, "scopes": list(scopes), "expires_at": expires}
        return code, expires

    def redeem(self, code: str, public_key: str, info: dict[str, Any] | None = None) -> DeviceRecord:
        load_public_key(public_key)
        digest = _code_hash(code if isinstance(code, str) else "")
        with self._locked() as state:
            self._prune(state)
            match = next(
                (key for key in state["enrollments"] if hmac.compare_digest(key, digest)),
                None,
            )
            if match is None:
                raise EnrollmentRejected("enrollment code is invalid, expired, or already used")
            pending = state["enrollments"].pop(match)
            if any(d["public_key"] == public_key for d in state["devices"].values()):
                raise EnrollmentRejected("this device key is already enrolled")
            record = DeviceRecord(
                device_id="dev_" + secrets.token_hex(8),
                name=pending["name"],
                public_key=public_key,
                scopes=pending["scopes"],
                created_at=_iso(_now()),
                info=dict(info or {}),
            )
            state["devices"][record.device_id] = asdict(record)
        return record

    def revoke(self, name_or_id: str) -> str:
        """Revoke an active device, or cancel a pending enrollment. Returns what was revoked."""
        with self._locked() as state:
            for device_id, raw in state["devices"].items():
                if raw["revoked_at"] is None and name_or_id in (device_id, raw["name"]):
                    raw["revoked_at"] = _iso(_now())
                    return f"device {raw['name']} ({device_id})"
            removed = [h for h, e in state["enrollments"].items() if e["name"] == name_or_id]
            for h in removed:
                del state["enrollments"][h]
            if removed:
                return f"pending enrollment for {name_or_id}"
        raise RegistryError(f"no active device or pending enrollment named {name_or_id!r}")

    @staticmethod
    def _prune(state: dict[str, Any]) -> None:
        now = _now()
        for key in [k for k, e in state["enrollments"].items() if e["expires_at"] <= now]:
            del state["enrollments"][key]

    def pending_enrollments(self) -> list[dict[str, Any]]:
        now = _now()
        return [
            {"name": e["name"], "scopes": e["scopes"], "expires_at": _iso(e["expires_at"])}
            for e in self.state["enrollments"].values()
            if e["expires_at"] > now
        ]
