"""
PEM filesystem storage for certificate lifecycle management.

Directory layout per domain:
  ./certs/<domain>/
      cert.pem        — Leaf certificate
      chain.pem       — Intermediate CA chain
      fullchain.pem   — cert + chain (nginx uses this)
      privkey.pem     — Private key (mode 0o600)
      metadata.json   — Issued/expires/order metadata

All writes are atomic: temp file + fsync + atomic rename.
"""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from storage.atomic import atomic_write_text, atomic_write_bytes


# ─── Public helpers ────────────────────────────────────────────────────────────


def sanitize_domain_for_path(domain: str) -> str:
    """
    Sanitize a domain name for use as a filesystem directory name.
    
    Transformations:
      - Wildcards: "*.example.com" → "wildcard.example.com"
      - Path separators: Remove "/" and "\\" to prevent directory traversal
    
    Args:
        domain: Raw domain name (may contain wildcards or unsafe characters)
    
    Returns:
        Filesystem-safe directory name
    
    Examples:
        >>> sanitize_domain_for_path("*.example.com")
        'wildcard.example.com'
        >>> sanitize_domain_for_path("example.com")
        'example.com'
    """
    return domain.replace("*.", "wildcard.").replace("/", "").replace("\\", "")


def cert_dir(cert_store_path: str, domain: str) -> Path:
    """Return the Path for a domain's cert directory (creates it if needed)."""
    safe_domain = sanitize_domain_for_path(domain)
    p = Path(cert_store_path) / safe_domain
    p.mkdir(parents=True, exist_ok=True)
    return p


def read_cert_pem(cert_store_path: str, domain: str) -> Optional[str]:
    """Return the PEM text of the leaf cert, or None if not found."""
    path = cert_dir(cert_store_path, domain) / "cert.pem"
    if path.exists():
        return path.read_text()
    return None


def parse_expiry(pem_text: str) -> datetime:
    """Parse the notAfter field from a PEM certificate and return a UTC datetime."""
    cert = x509.load_pem_x509_certificate(pem_text.encode(), default_backend())
    # cryptography >= 42 exposes .not_valid_after_utc (timezone-aware)
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        # Older cryptography: naive datetime — attach UTC
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def parse_issuer(pem_text: str) -> str:
    """Parse the issuer CommonName from a PEM certificate for display
    purposes (e.g. "R11", "Pebble Intermediate CA"). Falls back to the full
    RFC 4514 issuer string when the issuer has no CN attribute."""
    cert = x509.load_pem_x509_certificate(pem_text.encode(), default_backend())
    cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        return str(cn_attrs[0].value)
    return cert.issuer.rfc4514_string()


def days_until_expiry(expiry: datetime) -> int:
    """Return integer days until expiry (negative if already expired)."""
    now = datetime.now(tz=timezone.utc)
    return (expiry - now).days


def write_cert_files(
    cert_store_path: str,
    domain: str,
    cert_pem: str,
    chain_pem: str,
    privkey_pem: str,
    acme_order_url: str = "",
    ca_provider: str = "",
) -> dict:
    """
    Write cert.pem, chain.pem, fullchain.pem, privkey.pem and metadata.json
    to ./certs/<domain>/.  Private key is set to mode 0o600.

    Returns a metadata dict with issued_at, expires_at, acme_order_url, ca_provider.
    """
    d = cert_dir(cert_store_path, domain)

    _write(d / "cert.pem", cert_pem)
    _write(d / "chain.pem", chain_pem)
    _write(d / "fullchain.pem", cert_pem + chain_pem)

    key_path = d / "privkey.pem"
    _write(key_path, privkey_pem)
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    # Parse expiry from the freshly written cert
    expiry = parse_expiry(cert_pem)
    metadata = {
        "issued_at": datetime.now(tz=timezone.utc).isoformat(),
        "expires_at": expiry.isoformat(),
        "acme_order_url": acme_order_url,
        "renewed_by": "acme-cert-agent",
        "ca_provider": ca_provider,
    }
    _write(d / "metadata.json", json.dumps(metadata, indent=2))

    return metadata


def detect_ca_for_domain(cert_store_path: str, domain: str, pem_text: str) -> Optional[str]:
    """
    Return the CA provider string for the given domain and PEM certificate text.

    Strategy (in order):
      1. Read `ca_provider` from metadata.json in cert_store_path/<domain>/ if present
         (written by storage_manager).
      2. If not set in metadata, fall back to X.509 issuer inspection of the provided
         `pem_text` via acme.ca_detection.detect_ca_from_cert().

    Returns:
        The CA provider string from metadata.json, or the provider (or default provider,
        e.g. "digicert") inferred by detect_ca_from_cert(pem_text). May be None if the
        CA cannot be determined at all.
    """
    meta = read_metadata(cert_store_path, domain)
    if meta and meta.get("ca_provider"):
        return meta["ca_provider"]

    from acme.ca_detection import detect_ca_from_cert  # avoid circular import at module level
    return detect_ca_from_cert(pem_text)


def read_metadata(cert_store_path: str, domain: str) -> Optional[dict]:
    """Return the stored metadata dict for a domain, or None."""
    path = cert_dir(cert_store_path, domain) / "metadata.json"
    if path.exists():
        return json.loads(path.read_text())
    return None


# ─── Internal ──────────────────────────────────────────────────────────────────


def _write(path: Path, content: str) -> None:
    """Atomically write text with fsync to prevent corruption."""
    atomic_write_text(path, content)
