"""
JWK / JWS / EAB utilities for the ACME protocol (RFC 8555, EAB per §7.3.4).

Uses *josepy* (the library powering Certbot) for battle-tested JWS support.

Responsibilities (boundary with acme/crypto.py):
  - Generate / load / save the **account** RSA key
  - Compute JWK thumbprint (for HTTP-01 key-authorizations)
  - Sign ACME POST bodies as JWS (with jwk or kid header)
  - Build the EAB outer-JWS for EAB-capable CAs (DigiCert, ZeroSSL, Sectigo)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

from josepy.jwk import JWKRSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from storage.atomic import atomic_write_bytes


# ─── Account key I/O ──────────────────────────────────────────────────────────


def generate_account_key(key_size: int = 2048) -> JWKRSA:
    """Generate a new RSA account key wrapped in a josepy JWKRSA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    return JWKRSA(key=private_key)


def save_account_key(jwk: JWKRSA, path: str) -> None:
    """Persist account key as PEM (PKCS8) with atomic writes (temp + fsync + rename)."""
    p = Path(path)
    pem = jwk.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Atomic write: temp file + fsync + rename
    atomic_write_bytes(p, pem)
    os.chmod(path, 0o600)


def load_account_key(path: str) -> JWKRSA:
    """Load an RSA account key from a PEM file."""
    pem = Path(path).read_bytes()
    private_key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    return JWKRSA(key=private_key)


def account_key_exists(path: str) -> bool:
    return Path(path).exists()


# ─── JWK thumbprint ───────────────────────────────────────────────────────────


def compute_jwk_thumbprint(jwk: JWKRSA) -> str:
    """
    Compute the base64url SHA-256 thumbprint of the public JWK.
    Used to construct the HTTP-01 key-authorization:
      key_authorization = token + "." + thumbprint

    RFC 7638 §3.2 canonical form for RSA: {"e":"...","kty":"RSA","n":"..."}
    josepy's fields_to_partial_json() returns only {e, n} — kty is missing.
    We add it explicitly so the digest matches what ACME servers expect.
    """
    pub = jwk.public_key()
    fields = pub.fields_to_partial_json()
    # RFC 7638 §3.2: required members for RSA are {e, kty, n} in alphabetical order.
    # fields_to_partial_json() omits "kty" — include it explicitly.
    canonical_dict = {"e": fields["e"], "kty": "RSA", "n": fields["n"]}
    canonical = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    return _b64url(digest)


def compute_key_authorization(token: str, jwk: JWKRSA) -> str:
    """Return the HTTP-01 key-authorization string for *token*."""
    return f"{token}.{compute_jwk_thumbprint(jwk)}"


# ─── JWS signing ─────────────────────────────────────────────────────────────


def sign_request(
    payload: dict | None,
    account_key: JWKRSA,
    nonce: str,
    url: str,
    account_url: str | None = None,
) -> dict:
    """
    Sign an ACME request payload and return the JWS dict to POST.

    If *account_url* is None the JWS header uses the full JWK (used for
    newAccount).  If *account_url* is set the header uses the shorter "kid"
    form (used for all subsequent requests).

    Raises ValueError if nonce or url is empty — an empty nonce produces a
    syntactically valid JWS that every ACME server will reject with badNonce.
    """
    if not nonce or not nonce.strip():
        raise ValueError("nonce must not be empty — call get_nonce() before signing")
    if not url or not url.strip():
        raise ValueError("url must not be empty")

    # Build header dict, omitting jwk if account_url is set
    header_dict = {
        "alg": "RS256",
        "nonce": nonce,
        "url": url,
    }
    if account_url:
        header_dict["kid"] = account_url
    else:
        jwk = account_key.public_key().fields_to_partial_json()
        jwk["kty"] = "RSA"
        header_dict["jwk"] = jwk

    protected = _b64url(json.dumps(header_dict).encode())
    payload_b64 = "" if payload is None else _b64url(json.dumps(payload).encode())

    signing_input = f"{protected}.{payload_b64}".encode()
    signature = _sign_rsa(account_key, signing_input)

    return {
        "protected": protected,
        "payload": payload_b64,
        "signature": _b64url(signature),
    }


# ─── EAB (External Account Binding) ──────────────────────────────────────────


def create_eab_jws(
    account_jwk: JWKRSA,
    eab_kid: str,
    eab_hmac_key_b64url: str,
    new_account_url: str,
) -> dict:
    """
    Build the EAB outer-JWS required by EAB-capable CAs (DigiCert, ZeroSSL, Sectigo).

    Per RFC 8555 §7.3.4 (External Account Binding):
      - Protected header: {"alg":"HS256","kid":<eab_kid>,"url":<newAccount url>}
        (§7.3.4 requires a MAC-based alg; HS256 is this project's choice)
      - Payload: the account public JWK
      - Signature: HMAC-SHA256 keyed with the decoded EAB HMAC key

    Raises ValueError if:
      - eab_kid is empty
      - eab_hmac_key_b64url is not valid base64url
      - Decoded HMAC key is < 16 bytes (implementation minimum; see
        validate_eab_hmac_key)
    """
    # Validate eab_kid
    if not eab_kid or not eab_kid.strip():
        raise ValueError("EAB key ID (eab_kid) cannot be empty")

    # Validate eab_hmac_key_b64url format and decode
    hmac_key = validate_eab_hmac_key(eab_hmac_key_b64url)

    pub_jwk = account_jwk.public_key().fields_to_partial_json()
    pub_jwk["kty"] = "RSA"

    eab_header = {
        "alg": "HS256",
        "kid": eab_kid,
        "url": new_account_url,
    }
    protected = _b64url(json.dumps(eab_header).encode())
    payload = _b64url(json.dumps(pub_jwk).encode())

    signing_input = f"{protected}.{payload}".encode()
    mac = hmac.new(hmac_key, signing_input, hashlib.sha256).digest()

    jws = {
        "protected": protected,
        "payload": payload,
        "signature": _b64url(mac),
    }

    # Validate JWS structure: all fields must be non-empty base64url strings
    for field in ("protected", "payload", "signature"):
        if not jws[field]:
            raise ValueError(f"Malformed JWS: {field} is empty")
        if not isinstance(jws[field], str):
            raise ValueError(f"Malformed JWS: {field} is not a string")

    return jws


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _b64url(data: bytes) -> str:
    """URL-safe base64 encoding with no padding (as required by JOSE)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode, adding padding as needed."""
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _sign_rsa(jwk: JWKRSA, data: bytes) -> bytes:
    """Sign *data* with the RSA private key using PKCS1v15 + SHA-256."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    return jwk.key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def validate_eab_hmac_key(eab_hmac_key_b64url: str) -> bytes:
    """Validate and decode the EAB HMAC key."""
    if not eab_hmac_key_b64url or not eab_hmac_key_b64url.strip():
        raise ValueError("EAB HMAC key (eab_hmac_key_b64url) cannot be empty")

    try:
        hmac_key = _b64url_decode(eab_hmac_key_b64url)
    except Exception as exc:
        raise ValueError(
            f"EAB HMAC key is not valid base64url: {exc!s}. "
            f"Must be base64url-encoded bytes."
        ) from exc

    # 16-byte (128-bit) floor is an implementation minimum: RFC 8555 §7.3.4
    # mandates no key length, and RFC 7518 §3.2 recommends >= 32 bytes for HS256.
    if len(hmac_key) < 16:
        raise ValueError(
            f"EAB HMAC key is too short: {len(hmac_key)} bytes. "
            f"Must be at least 16 bytes (128 bits)."
        )

    return hmac_key
