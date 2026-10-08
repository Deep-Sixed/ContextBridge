from __future__ import annotations

import base64
import os
import re
import ssl
import stat
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from contextbridge.remote.protocol import auth_payload
from contextbridge.remote.registry import DeviceRegistry, EnrollmentRejected, RegistryError
from contextbridge.remote.tls import fingerprint_der, generate_self_signed, normalize_fingerprint

ALL = ["computer:read", "computer:write", "computer:execute", "computer:process"]


def public_key(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


@pytest.fixture
def registry(tmp_path):
    return DeviceRegistry(tmp_path / "state" / "devices.json")


def test_registry_file_is_private_and_has_gateway_id(registry):
    assert registry.gateway_id.startswith("gw_")
    assert stat.S_IMODE(os.stat(registry.path).st_mode) == 0o600


def test_enrollment_code_is_single_use_and_case_insensitive(registry):
    code, expires = registry.create_enrollment("thanatos", ALL)
    assert re.fullmatch(r"[A-Z2-7]{4}(-[A-Z2-7]{4}){3}", code)
    assert expires > time.time()
    assert code not in registry.path.read_text()  # only the hash is stored
    record = registry.redeem(code.lower().replace("-", ""), public_key(Ed25519PrivateKey.generate()))
    assert record.name == "thanatos" and record.scopes == ALL and record.active
    with pytest.raises(EnrollmentRejected):
        registry.redeem(code, public_key(Ed25519PrivateKey.generate()))


def test_expired_and_unknown_codes_are_rejected(registry, monkeypatch):
    code, _ = registry.create_enrollment("thanatos", ALL, minutes=1)
    with pytest.raises(EnrollmentRejected):
        registry.redeem("AAAA-BBBB-CCCC-DDDD", public_key(Ed25519PrivateKey.generate()))
    real_time = time.time
    monkeypatch.setattr("contextbridge.remote.registry._now", lambda: real_time() + 120)
    with pytest.raises(EnrollmentRejected):
        registry.redeem(code, public_key(Ed25519PrivateKey.generate()))


def test_names_are_validated_and_unique(registry):
    for bad in ("local", "Thanatos", "-x", "a b", ""):
        with pytest.raises(RegistryError):
            registry.create_enrollment(bad, ALL)
    registry.create_enrollment("thanatos", ALL)
    with pytest.raises(RegistryError, match="pending"):
        registry.create_enrollment("thanatos", ALL)
    with pytest.raises(RegistryError, match="scope"):
        registry.create_enrollment("friday", [])


def test_revoke_and_reenroll(registry):
    code, _ = registry.create_enrollment("thanatos", ALL)
    first = registry.redeem(code, public_key(Ed25519PrivateKey.generate()))
    with pytest.raises(RegistryError, match="already enrolled"):
        registry.create_enrollment("thanatos", ALL)
    assert "thanatos" in registry.revoke("thanatos")
    assert registry.by_name("thanatos") is None
    assert not registry.get(first.device_id).active
    code, _ = registry.create_enrollment("thanatos", ALL)
    second = registry.redeem(code, public_key(Ed25519PrivateKey.generate()))
    assert second.device_id != first.device_id
    with pytest.raises(RegistryError):
        registry.revoke("nobody")


def test_revoke_cancels_pending_enrollment(registry):
    code, _ = registry.create_enrollment("thanatos", ALL)
    assert "pending" in registry.revoke("thanatos")
    with pytest.raises(EnrollmentRejected):
        registry.redeem(code, public_key(Ed25519PrivateKey.generate()))


def test_changes_by_another_process_are_detected(registry, tmp_path):
    code, _ = registry.create_enrollment("thanatos", ALL)
    record = registry.redeem(code, public_key(Ed25519PrivateKey.generate()))
    other = DeviceRegistry(registry.path)  # e.g. the admin CLI
    other.revoke("thanatos")
    assert registry.get(record.device_id).active  # cached until refreshed
    assert registry.refresh() is True
    assert not registry.get(record.device_id).active
    assert registry.refresh() is False


def test_invalid_public_key_and_duplicate_key(registry):
    code, _ = registry.create_enrollment("thanatos", ALL)
    with pytest.raises(RegistryError):
        registry.redeem(code, "not-a-key")
    key = public_key(Ed25519PrivateKey.generate())
    registry.redeem(code, key)
    code2, _ = registry.create_enrollment("friday", ALL)
    with pytest.raises(EnrollmentRejected, match="already enrolled"):
        registry.redeem(code2, key)


def test_device_signature_verification(registry):
    key = Ed25519PrivateKey.generate()
    code, _ = registry.create_enrollment("thanatos", ALL)
    record = registry.redeem(code, public_key(key))
    payload = auth_payload(registry.gateway_id, record.device_id, b"n" * 32)
    assert record.verify(key.sign(payload), payload)
    assert not record.verify(key.sign(payload), payload + b"x")
    assert not record.verify(Ed25519PrivateKey.generate().sign(payload), payload)


def test_self_signed_certificate(tmp_path):
    cert, key = tmp_path / "tls" / "gw.crt", tmp_path / "tls" / "gw.key"
    fingerprint = generate_self_signed(cert, key, hostnames=["friday"], ips=["127.0.0.1"])
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    assert normalize_fingerprint(fingerprint.lower().replace("sha256:", "")) == fingerprint
    assert fingerprint == fingerprint_der(ssl.PEM_cert_to_DER_cert(cert.read_text()))
    with pytest.raises(ValueError):
        normalize_fingerprint("sha256:XYZ")
