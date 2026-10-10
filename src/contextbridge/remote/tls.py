"""TLS for the agent channel: a self-signed gateway certificate pinned by fingerprint.

Agents either pin the gateway certificate's SHA-256 fingerprint (the default for
a home network) or verify it against a CA file. The pin is checked before the
agent sends anything.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class PinMismatch(ssl.SSLError):
    """Raised when the gateway's certificate does not match the pinned fingerprint."""


def fingerprint_der(der: bytes) -> str:
    digest = hashlib.sha256(der).hexdigest().upper()
    return "sha256:" + ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def normalize_fingerprint(value: str) -> str:
    text = value.strip()
    if text.lower().startswith("sha256:"):
        text = text[7:]
    hexdigits = text.replace(":", "").upper()
    if len(hexdigits) != 64 or any(c not in "0123456789ABCDEF" for c in hexdigits):
        raise ValueError("fingerprint must be a SHA-256 digest, e.g. sha256:AB:CD:…")
    return "sha256:" + ":".join(hexdigits[i : i + 2] for i in range(0, 64, 2))


def cert_fingerprint(cert_path: str | Path) -> str:
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    return fingerprint_der(cert.public_bytes(serialization.Encoding.DER))


def generate_self_signed(
    cert_path: Path, key_path: Path, *, hostnames: list[str], ips: list[str], days: int = 825
) -> str:
    """Write a P-256 key and self-signed certificate; return the certificate fingerprint."""
    key = ec.generate_private_key(ec.SECP256R1())
    names: list[x509.GeneralName] = [x509.DNSName(h) for h in hostnames]
    names += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0] if hostnames else "contextbridge")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return fingerprint_der(cert.public_bytes(serialization.Encoding.DER))


def server_context(cert_path: str | Path, key_path: str | Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


def client_context(*, fingerprint: str | None = None, ca_file: str | Path | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if fingerprint:
        # Trust comes from the pin, checked by verify_pin() right after the handshake.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif ca_file:
        ctx.load_verify_locations(cafile=str(ca_file))
    else:
        ctx.load_default_certs()
    return ctx


def verify_pin(ssl_object: ssl.SSLObject | ssl.SSLSocket | None, fingerprint: str) -> None:
    if ssl_object is None:
        raise PinMismatch("connection is not encrypted")
    der = ssl_object.getpeercert(binary_form=True)
    if not der or not hmac.compare_digest(fingerprint_der(der), normalize_fingerprint(fingerprint)):
        raise PinMismatch("gateway certificate does not match the pinned fingerprint")
