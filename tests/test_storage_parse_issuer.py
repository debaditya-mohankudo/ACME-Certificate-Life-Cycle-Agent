"""Tests for storage/filesystem.py's parse_issuer() — used by
main.get_domain_statuses() to surface the issuing CA in the TUI's Domain
Status screen and any other status consumer.
"""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from storage.filesystem import parse_issuer


def _make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_cert(issuer: x509.Name) -> str:
    key = _make_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_parse_issuer_returns_common_name_when_present():
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"),
            x509.NameAttribute(NameOID.COMMON_NAME, "R11"),
        ]
    )
    pem = _build_cert(issuer)
    assert parse_issuer(pem) == "R11"


def test_parse_issuer_falls_back_to_rfc4514_when_no_common_name():
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pebble")])
    pem = _build_cert(issuer)
    result = parse_issuer(pem)
    assert "Pebble" in result
