import base64
import hmac as hmac_lib
import json

import pytest

from acme.jws import (
    _b64url_decode,
    create_eab_jws,
    generate_account_key,
    sign_request,
    validate_eab_hmac_key,
)


# ─── validate_eab_hmac_key — unit tests ───────────────────────────────────────


# Positive test: valid base64url, >=16 bytes
def test_validate_eab_hmac_key_valid():
    # 16 bytes (128 bits) random key, base64url encoded
    key_bytes = b"A" * 16
    key_b64url = base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode()
    decoded = validate_eab_hmac_key(key_b64url)
    assert decoded == key_bytes


# Boundary: exactly 16 bytes is the implementation minimum (RFC 8555 §7.3.4
# sets none) — must be accepted
def test_validate_eab_hmac_key_exactly_16_bytes():
    key_bytes = b"B" * 16
    key_b64url = base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode()
    decoded = validate_eab_hmac_key(key_b64url)
    assert decoded == key_bytes
    assert len(decoded) == 16


# Negative test: empty string
def test_validate_eab_hmac_key_empty():
    with pytest.raises(ValueError) as exc:
        validate_eab_hmac_key("")
    assert "cannot be empty" in str(exc.value)


# Negative test: whitespace-only string is treated as empty
def test_validate_eab_hmac_key_whitespace_only():
    with pytest.raises(ValueError) as exc:
        validate_eab_hmac_key("   ")
    assert "cannot be empty" in str(exc.value)


# Negative test: invalid base64url
def test_validate_eab_hmac_key_invalid_base64():
    with pytest.raises(ValueError) as exc:
        validate_eab_hmac_key("!!!notbase64!!!")
    assert "not valid base64url" in str(exc.value)


# Negative test: too short (<16 bytes)
def test_validate_eab_hmac_key_too_short():
    key_bytes = b"A" * 8  # 8 bytes
    key_b64url = base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode()
    with pytest.raises(ValueError) as exc:
        validate_eab_hmac_key(key_b64url)
    assert "too short" in str(exc.value)


# ─── Bug 1 regression ─────────────────────────────────────────────────────────
# Regression: create_eab_jws must capture the return value of
# validate_eab_hmac_key().  If the return is discarded, hmac_key is undefined
# and the function raises NameError instead of producing a JWS.


def test_create_eab_jws_valid_hmac_key_produces_jws():
    """create_eab_jws must not raise NameError when given a valid HMAC key.

    Catches: validate_eab_hmac_key() called without capturing its return value,
    causing `NameError: name 'hmac_key' is not defined` at the hmac.new() call.
    """
    key_bytes = b"C" * 32
    key_b64url = base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode()
    account_jwk = generate_account_key()

    jws = create_eab_jws(
        account_jwk=account_jwk,
        eab_kid="test-kid-001",
        eab_hmac_key_b64url=key_b64url,
        new_account_url="https://acme.example.com/newAccount",
    )

    assert isinstance(jws, dict)
    assert set(jws.keys()) == {"protected", "payload", "signature"}
    assert all(isinstance(v, str) and v for v in jws.values())


def test_create_eab_jws_hmac_signature_is_correct():
    """The HMAC-SHA256 signature in the EAB JWS must be verifiable.

    Catches: if hmac_key is never set (discarded return value), the signature
    field would be absent or incorrect — an ACME server would reject the request.
    """
    key_bytes = b"D" * 32
    key_b64url = base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode()
    account_jwk = generate_account_key()
    new_account_url = "https://acme.example.com/newAccount"

    jws = create_eab_jws(
        account_jwk=account_jwk,
        eab_kid="test-kid-002",
        eab_hmac_key_b64url=key_b64url,
        new_account_url=new_account_url,
    )

    # Re-derive the expected HMAC using the same key and signing input
    signing_input = f"{jws['protected']}.{jws['payload']}".encode()
    expected_mac = hmac_lib.new(key_bytes, signing_input, "sha256").digest()
    expected_sig = base64.urlsafe_b64encode(expected_mac).rstrip(b"=").decode()

    assert jws["signature"] == expected_sig, (
        "EAB HMAC signature does not match — hmac_key may not have been set correctly"
    )


# ─── Bug 2 regression ─────────────────────────────────────────────────────────
# Regression: sign_request must not include null-valued fields in the encoded
# protected header.  Using JWSHeader.__dict__ naively serializes None fields
# as JSON null, violating RFC 8555 §6.2 (jwk and kid are mutually exclusive).


def test_sign_request_jwk_mode_no_null_in_protected_header():
    """JWK mode: protected header must not contain 'kid' or any null values.

    Catches: json.dumps(JWSHeader.__dict__) includes `"kid": null` when
    account_url=None, which is RFC 8555 §6.2 non-compliant.
    """
    key = generate_account_key()
    body = sign_request(
        payload={"test": True},
        account_key=key,
        nonce="nonce-abc",
        url="https://acme.test/newAccount",
        account_url=None,
    )

    raw_json = _b64url_decode(body["protected"]).decode()
    protected = json.loads(raw_json)

    assert "kid" not in protected, (
        f"'kid' must not appear in JWK-mode header; got fields: {list(protected)}"
    )
    assert "null" not in raw_json, (
        f"Null values must not appear in protected header JSON: {raw_json}"
    )


def test_sign_request_kid_mode_no_null_in_protected_header():
    """KID mode: protected header must not contain 'jwk' or any null values.

    Catches: json.dumps(JWSHeader.__dict__) includes `"jwk": null` when
    account_url is set, which is RFC 8555 §6.2 non-compliant.
    """
    key = generate_account_key()
    body = sign_request(
        payload={"test": True},
        account_key=key,
        nonce="nonce-xyz",
        url="https://acme.test/newOrder",
        account_url="https://acme.test/acct/1",
    )

    raw_json = _b64url_decode(body["protected"]).decode()
    protected = json.loads(raw_json)

    assert "jwk" not in protected, (
        f"'jwk' must not appear in KID-mode header; got fields: {list(protected)}"
    )
    assert "null" not in raw_json, (
        f"Null values must not appear in protected header JSON: {raw_json}"
    )
