"""
Low-level ACME RFC 8555 HTTP client.

This client is intentionally **stateless**: all account/nonce state is passed
in by the caller (the LangGraph nodes), making it easy to test with mock HTTP.

RFC 8555 compliance notes
--------------------------
* POST-as-GET: authorizations must be fetched with a signed empty payload, not
  plain GET.  Pass `account_key` and `account_url` to `get_authorization` /
  `poll_authorization` to enable this.
* badNonce retry: ACME servers (including Pebble, which rejects 5 % of nonces
  intentionally) return a fresh `Replay-Nonce` header even on error responses.
  `_post_signed` automatically retries up to `_NONCE_RETRIES` times.
"""
from __future__ import annotations

import time
from functools import partial
from typing import Any, Optional

from josepy.jwk import JWKRSA
import requests

from acme import jws as jwslib

_NONCE_RETRIES = 3


class AcmeError(Exception):
    """Raised when the ACME server returns an error response."""

    def __init__(self, status_code: int, body: dict, new_nonce: str = "") -> None:
        self.status_code = status_code
        self.body = body
        self.new_nonce = new_nonce
        problem_type = body.get("type", "unknown")
        detail = body.get("detail", str(body))
        super().__init__(f"ACME {status_code}: {problem_type} — {detail}")


class AcmeClient:
    """
    Base RFC 8555 client. Subclass to add CA-specific behaviour (EAB, preset URLs).

    Implements the full ACME protocol: directory discovery, nonce management,
    account registration, order creation, authorization handling, finalization,
    and certificate download.  All methods are intentionally stateless — callers
    pass nonce and account credentials on each call.
    """

    def __init__(
        self,
        directory_url: str,
        timeout: int = 30,
        ca_bundle: str = "",
        insecure: bool = False,
        optional_finalize_params: dict[str, str] | None = None,
    ) -> None:
        self.directory_url = directory_url
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "acme-cert-agent/1.0"})
        self._directory_cache: Optional[dict] = None  # Cache directory response
        self._optional_finalize_params = optional_finalize_params or {}

        if insecure:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self._session.verify = False
        elif ca_bundle:
            self._session.verify = ca_bundle

    # ── Directory & nonce ─────────────────────────────────────────────────

    def get_directory(self) -> dict:
        """GET /directory — discover ACME endpoint URLs.

        Caches the response per client instance to avoid redundant network
        calls during polling. Directory is static per ACME server session.
        """
        if self._directory_cache is None:
            resp = self._session.get(self.directory_url, timeout=self.timeout)
            resp.raise_for_status()
            self._directory_cache = resp.json()
        return self._directory_cache

    def get_nonce(self, directory: dict) -> str:
        """HEAD /newNonce — fetch a fresh anti-replay nonce."""
        resp = self._session.head(directory["newNonce"], timeout=self.timeout)
        nonce = resp.headers.get("Replay-Nonce")
        if not nonce:
            raise AcmeError(resp.status_code, {"detail": "No Replay-Nonce header"})
        return nonce

    # ── Account ───────────────────────────────────────────────────────────

    def create_account(
        self,
        account_key: JWKRSA,
        nonce: str,
        directory: dict,
    ) -> tuple[str, str]:
        """
        POST /newAccount with plain termsOfServiceAgreed payload.
        Returns (account_url, new_nonce).

        Override in subclasses to inject EAB or other CA-specific fields.
        """
        payload = {"termsOfServiceAgreed": True}
        resp = self._post_signed(payload, account_key, nonce, directory["newAccount"], directory=directory)
        return resp.headers.get("Location", ""), resp.headers.get("Replay-Nonce", "")

    def revoke_certificate(
        self,
        cert_pem: str,
        account_key: JWKRSA,
        account_url: str,
        nonce: str,
        directory: dict,
        reason: int = 0,
    ) -> str:
        """
        POST /revokeCert — revoke an issued certificate (RFC 8555 §7.6).

        cert_pem: PEM-encoded leaf certificate (not the full chain).
        reason:   RFC 5280 CRL reason code, must be 0-10:
                  0=unspecified, 1=keyCompromise, 2=cACompromise,
                  3=affiliationChanged, 4=superseded, 5=cessationOfOperation,
                  6=certificateHold, 7=removeFromCRL, 8=privilegeWithdrawn,
                  9=aACompromise, 10=weakSignatureAlgorithm (RFC 6962).
        Returns new_nonce.
        Raises ValueError if reason is outside 0-10 range.
        Raises AcmeError if the server rejects the revocation.
        """
        if not (0 <= reason <= 10):
            raise ValueError(
                f"Invalid revocation reason code: {reason}. "
                f"Must be 0-10 per RFC 5280 (0=unspecified, 1=keyCompromise, "
                f"4=superseded, 5=cessationOfOperation, etc.)"
            )

        import base64
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        cert_b64 = base64.urlsafe_b64encode(cert.public_bytes(Encoding.DER)).rstrip(b"=").decode()

        payload: dict = {"certificate": cert_b64}
        if reason != 0:
            payload["reason"] = reason

        resp = self._post_signed(
            payload, account_key, nonce, directory["revokeCert"], account_url, directory=directory
        )
        return resp.headers.get("Replay-Nonce", "")

    def lookup_account(
        self,
        account_key: JWKRSA,
        nonce: str,
        directory: dict,
    ) -> tuple[Optional[str], str]:
        """
        POST /newAccount with onlyReturnExisting=True (RFC 8555 §7.3.1).
        Returns (account_url, new_nonce) if account exists.
        Returns (None, new_nonce) if account does not exist (400 accountDoesNotExist).
        Raises AcmeError for all other errors, including other 400 errors.
        """
        new_account_url = directory["newAccount"]
        try:
            resp = self._post_signed(
                {"onlyReturnExisting": True}, account_key, nonce, new_account_url, directory=directory
            )
            return resp.headers.get("Location"), resp.headers.get("Replay-Nonce", "")
        except AcmeError as e:
            # RFC 8555: 400 with type "accountDoesNotExist" means account doesn't exist
            if e.status_code == 400 and e.body.get("type") == "urn:acme:error:accountDoesNotExist":
                return None, e.new_nonce
            # All other errors (including other 400s) should raise
            raise

    # ── Orders ────────────────────────────────────────────────────────────

    def create_order(
        self,
        domains: list[str],
        account_key: JWKRSA,
        account_url: str,
        nonce: str,
        directory: dict,
    ) -> tuple[dict, str, str]:
        """
        POST /newOrder — create a certificate order for one or more domains.
        Returns (order_body, order_url, new_nonce).
        """
        new_order_url = directory["newOrder"]
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        resp = self._post_signed(payload, account_key, nonce, new_order_url, account_url, directory=directory)
        return resp.json(), resp.headers.get("Location", ""), resp.headers.get("Replay-Nonce", "")

    def get_order(
        self,
        order_url: str,
        account_key: JWKRSA | None = None,
        account_url: str | None = None,
    ) -> dict:
        """
        Fetch an order object.
        Uses POST-as-GET when account credentials are provided (required by Pebble).
        """
        if account_key and account_url:
            directory = self.get_directory()
            nonce = self.get_nonce(directory)
            resp = self._post_signed(None, account_key, nonce, order_url, account_url, directory=directory)
        else:
            resp = self._session.get(order_url, timeout=self.timeout)
            resp.raise_for_status()
        return resp.json()

    # ── Authorizations & challenges ───────────────────────────────────────

    def get_authorization(
        self,
        auth_url: str,
        account_key: JWKRSA | None = None,
        account_url: str | None = None,
    ) -> dict:
        """
        Fetch an authorization object.

        Uses POST-as-GET (RFC 8555 §7.4.1) when `account_key` and `account_url`
        are provided — required by Pebble and modern ACME servers.
        Falls back to plain GET for backward compatibility when they are omitted.
        """
        if account_key and account_url:
            # Fetch a fresh nonce internally so the caller doesn't have to
            # thread it through every poll iteration.
            directory = self.get_directory()
            nonce = self.get_nonce(directory)
            resp = self._post_signed(None, account_key, nonce, auth_url, account_url, directory=directory)
        else:
            resp = self._session.get(auth_url, timeout=self.timeout)
            resp.raise_for_status()
        return resp.json()

    def respond_to_challenge(
        self,
        challenge_url: str,
        account_key: JWKRSA,
        account_url: str,
        nonce: str,
    ) -> tuple[dict, str]:
        """
        POST challenge URL with empty payload {} to tell the CA to verify.
        Returns (challenge_body, new_nonce).
        """
        resp = self._post_signed({}, account_key, nonce, challenge_url, account_url)
        return resp.json(), resp.headers.get("Replay-Nonce", "")

    def poll_authorization(
        self,
        auth_url: str,
        account_key: JWKRSA | None = None,
        account_url: str | None = None,
        max_attempts: int = 10,
        poll_interval: float = 2.0,
    ) -> str:
        """
        Poll an authorization URL until status is 'valid' or 'invalid'.

        Pass `account_key` and `account_url` to use POST-as-GET (required by
        Pebble and RFC 8555-compliant servers).
        Returns the final status string ('valid').
        Raises AcmeError on timeout or 'invalid'.
        """
        for _ in range(max_attempts):
            authz = self.get_authorization(auth_url, account_key, account_url)
            status = authz.get("status", "pending")
            if status == "valid":
                return status
            if status == "invalid":
                raise AcmeError(
                    200,
                    {
                        "type": "urn:ietf:params:acme:error:unauthorized",
                        "detail": f"Authorization invalid: {authz}",
                    },
                )
            time.sleep(poll_interval)

        raise AcmeError(
            0,
            {
                "type": "timeout",
                "detail": f"Authorization did not become valid after {max_attempts} polls",
            },
        )

    # ── Finalization & certificate download ───────────────────────────────

    def _extra_finalize_params(self) -> dict[str, str]:
        """CA-specific fields to merge into the finalize payload. Override in subclasses."""
        return {}

    def _cli_optional_keys(self) -> dict[str, str]:
        """Operator-supplied finalize params from --optional-keys, already
        validated against this CA's whitelist at settings-construction time."""
        return self._optional_finalize_params

    def finalize_order(
        self,
        finalize_url: str,
        csr_der: bytes,
        account_key: JWKRSA,
        account_url: str,
        nonce: str,
    ) -> tuple[dict, str]:
        """
        POST /finalize — submit DER-encoded CSR.
        Returns (finalize_response_body, new_nonce).
        """
        import base64
        csr_b64 = base64.urlsafe_b64encode(csr_der).rstrip(b"=").decode()
        payload = {"csr": csr_b64}
        payload.update(self._extra_finalize_params())
        payload.update(self._cli_optional_keys())
        resp = self._post_signed(payload, account_key, nonce, finalize_url, account_url)
        return resp.json(), resp.headers.get("Replay-Nonce", "")

    def poll_order_for_certificate(
        self,
        order_url: str,
        account_key: JWKRSA | None = None,
        account_url: str | None = None,
        max_attempts: int = 20,
        poll_interval: float = 3.0,
    ) -> str:
        """
        Poll order until status is 'valid' (certificate ready).
        Pass account credentials to use POST-as-GET (required by Pebble).
        Returns the certificate URL.
        """
        for _ in range(max_attempts):
            order = self.get_order(order_url, account_key, account_url)
            status = order.get("status")
            if status == "valid":
                cert_url = order.get("certificate")
                if not cert_url:
                    raise AcmeError(0, {"detail": "Order valid but no certificate URL"})
                return cert_url
            if status == "invalid":
                raise AcmeError(
                    0,
                    {"type": "invalid", "detail": f"Order became invalid: {order}"},
                )
            time.sleep(poll_interval)

        raise AcmeError(
            0,
            {"type": "timeout", "detail": "Order did not become valid (certificate not issued)"},
        )

    def download_certificate(
        self,
        cert_url: str,
        account_key: JWKRSA,
        account_url: str,
        nonce: str,
    ) -> tuple[str, str]:
        """
        POST-as-GET the certificate URL and return (full_chain_pem, new_nonce).
        """
        resp = self._post_signed(
            None, account_key, nonce, cert_url, account_url,
            accept="application/pem-certificate-chain",
        )
        return resp.text, resp.headers.get("Replay-Nonce", "")

    # ── Internal ──────────────────────────────────────────────────────────

    def _post_signed(
        self,
        payload: dict | None,
        account_key: JWKRSA,
        nonce: str,
        url: str,
        account_url: str | None = None,
        accept: str = "application/json",
        directory: dict | None = None,
    ) -> requests.Response:
        """
        Sign *payload* with *account_key* and POST to *url*, retrying up to
        `_NONCE_RETRIES` times on `badNonce` responses.

        ACME servers return a fresh `Replay-Nonce` even in error responses, so
        we extract it and re-sign rather than fetching a new nonce (saves one
        round-trip per retry).
        """
        current_nonce = nonce
        for attempt in range(_NONCE_RETRIES):
            body = jwslib.sign_request(payload, account_key, current_nonce, url, account_url)
            resp = self._session.post(
                url,
                json=body,
                headers={
                    "Content-Type": "application/jose+json",
                    "Accept": accept,
                },
                timeout=self.timeout,
            )
            if resp.ok:
                return resp

            try:
                error_body = resp.json()
            except Exception:
                error_body = {"detail": resp.text}

            # On badNonce, grab the new nonce from the response and retry
            if "badNonce" in error_body.get("type", "") and attempt < _NONCE_RETRIES - 1:
                fresh = resp.headers.get("Replay-Nonce")
                if fresh:
                    current_nonce = fresh
                    continue
                # Fall back to fetching a nonce if the header is missing
                if directory is None:
                    directory = self.get_directory()
                current_nonce = self.get_nonce(directory)
                continue

            raise AcmeError(resp.status_code, error_body, resp.headers.get("Replay-Nonce", ""))

        # Should never reach here, but satisfy the type checker
        raise AcmeError(0, {"detail": "Exceeded nonce retry limit"})

    def _post_jws(
        self,
        url: str,
        jws_body: dict[str, Any],
        accept: str = "application/json",
    ) -> requests.Response:
        """POST a pre-signed JWS body (used by unit tests that build their own body)."""
        resp = self._session.post(
            url,
            json=jws_body,
            headers={
                "Content-Type": "application/jose+json",
                "Accept": accept,
            },
            timeout=self.timeout,
        )
        if not resp.ok:
            try:
                error_body = resp.json()
            except Exception:
                error_body = {"detail": resp.text}
            raise AcmeError(resp.status_code, error_body)
        return resp


class EabAcmeClient(AcmeClient):
    """
    Intermediate base for CAs that require External Account Binding (RFC 8739).
    DigiCert, ZeroSSL, and Sectigo all use identical EAB logic.
    Subclasses only set DEFAULT_DIRECTORY_URL and call super().__init__().
    """

    def __init__(
        self,
        eab_key_id: str,
        eab_hmac_key: str,
        directory_url: str,
        timeout: int = 30,
        ca_bundle: str = "",
        insecure: bool = False,
        optional_finalize_params: dict[str, str] | None = None,
    ) -> None:
        super().__init__(directory_url, timeout, ca_bundle, insecure, optional_finalize_params)
        self.eab_key_id = eab_key_id
        self.eab_hmac_key = eab_hmac_key

    def create_account(
        self,
        account_key: JWKRSA,
        nonce: str,
        directory: dict,
    ) -> tuple[str, str]:
        """
        POST /newAccount with EAB binding per RFC 8739.
        Falls through to plain payload if either EAB credential is empty.
        Returns (account_url, new_nonce).
        """
        new_account_url = directory["newAccount"]
        payload: dict = {"termsOfServiceAgreed": True}
        if bool(self.eab_key_id) != bool(self.eab_hmac_key):
            missing = "eab_hmac_key" if self.eab_key_id else "eab_key_id"
            raise ValueError(
                f"EAB credentials are partially configured: {missing} is missing. "
                f"Both eab_key_id and eab_hmac_key must be set together."
            )
        if self.eab_key_id and self.eab_hmac_key:
            payload["externalAccountBinding"] = jwslib.create_eab_jws(
                account_key, self.eab_key_id, self.eab_hmac_key, new_account_url
            )
        resp = self._post_signed(payload, account_key, nonce, new_account_url, directory=directory)
        return resp.headers.get("Location", ""), resp.headers.get("Replay-Nonce", "")


class DigiCertAcmeClient(EabAcmeClient):
    """DigiCert ACME client — requires EAB credentials (RFC 8739)."""

    DEFAULT_DIRECTORY_URL = "https://acme.digicert.com/v2/DV/directory"

    def __init__(
        self,
        eab_key_id: str,
        eab_hmac_key: str,
        directory_url: str = DEFAULT_DIRECTORY_URL,
        timeout: int = 30,
        ca_bundle: str = "",
        insecure: bool = False,
        optional_finalize_params: dict[str, str] | None = None,
    ) -> None:
        super().__init__(eab_key_id, eab_hmac_key, directory_url, timeout, ca_bundle, insecure, optional_finalize_params)
    # create_account inherited from EabAcmeClient


class ZeroSSLAcmeClient(EabAcmeClient):
    """ZeroSSL ACME client — requires EAB credentials (RFC 8739)."""

    DEFAULT_DIRECTORY_URL = "https://acme.zerossl.com/v2/DV90"

    def __init__(
        self,
        eab_key_id: str,
        eab_hmac_key: str,
        directory_url: str = DEFAULT_DIRECTORY_URL,
        timeout: int = 30,
        ca_bundle: str = "",
        insecure: bool = False,
        optional_finalize_params: dict[str, str] | None = None,
    ) -> None:
        super().__init__(eab_key_id, eab_hmac_key, directory_url, timeout, ca_bundle, insecure, optional_finalize_params)
    # create_account inherited from EabAcmeClient


class SectigoAcmeClient(EabAcmeClient):
    """Sectigo ACME client — requires EAB credentials (RFC 8739)."""

    DEFAULT_DIRECTORY_URL = "https://acme.sectigo.com/v2/DV"

    def __init__(
        self,
        eab_key_id: str,
        eab_hmac_key: str,
        directory_url: str = DEFAULT_DIRECTORY_URL,
        timeout: int = 30,
        ca_bundle: str = "",
        insecure: bool = False,
        optional_finalize_params: dict[str, str] | None = None,
    ) -> None:
        super().__init__(eab_key_id, eab_hmac_key, directory_url, timeout, ca_bundle, insecure, optional_finalize_params)
    # create_account inherited from EabAcmeClient


class LetsEncryptAcmeClient(AcmeClient):
    """Let's Encrypt ACME client — no EAB required."""

    PRODUCTION_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
    STAGING_DIRECTORY_URL    = "https://acme-staging-v02.api.letsencrypt.org/directory"

    def __init__(
        self,
        staging: bool = False,
        timeout: int = 30,
        ca_bundle: str = "",
        insecure: bool = False,
        optional_finalize_params: dict[str, str] | None = None,
    ) -> None:
        url = self.STAGING_DIRECTORY_URL if staging else self.PRODUCTION_DIRECTORY_URL
        super().__init__(url, timeout, ca_bundle, insecure, optional_finalize_params)
    # create_account inherited from AcmeClient (plain, no EAB)


# Governs what an *operator* may set via --optional-keys for a given CA —
# independent of, and disjoint from, whatever keys a subclass's
# _extra_finalize_params() sets by default (see tests/test_finalize_params.py).
# A CA absent from this dict is treated as an empty whitelist (fail closed).
_FINALIZE_PARAM_WHITELIST: dict[str, frozenset[str]] = {
    "digicert": frozenset(),
    "letsencrypt": frozenset(),
    "letsencrypt_staging": frozenset(),
    "zerossl": frozenset(),
    "sectigo": frozenset(),
    "custom": frozenset(),
}


def _client_registry(ca_provider: str, settings: Any) -> AcmeClient:
    """Return the AcmeClient instance for the given CA provider and settings."""
    ca_bundle: str = settings.ACME_CA_BUNDLE
    insecure: bool = settings.ACME_INSECURE
    optional_finalize_params: dict[str, str] = getattr(settings, "OPTIONAL_FINALIZE_PARAMS", {})
    registry: dict[str, Any] = {
        "digicert": partial(
            DigiCertAcmeClient,
            eab_key_id=settings.ACME_EAB_KEY_ID,
            eab_hmac_key=settings.ACME_EAB_HMAC_KEY,
            ca_bundle=ca_bundle,
            insecure=insecure,
            optional_finalize_params=optional_finalize_params,
        ),
        "letsencrypt": partial(
            LetsEncryptAcmeClient,
            ca_bundle=ca_bundle,
            insecure=insecure,
            optional_finalize_params=optional_finalize_params,
        ),
        "letsencrypt_staging": partial(
            LetsEncryptAcmeClient,
            staging=True,
            ca_bundle=ca_bundle,
            insecure=insecure,
            optional_finalize_params=optional_finalize_params,
        ),
        "zerossl": partial(
            ZeroSSLAcmeClient,
            eab_key_id=settings.ACME_EAB_KEY_ID,
            eab_hmac_key=settings.ACME_EAB_HMAC_KEY,
            ca_bundle=ca_bundle,
            insecure=insecure,
            optional_finalize_params=optional_finalize_params,
        ),
        "sectigo": partial(
            SectigoAcmeClient,
            eab_key_id=settings.ACME_EAB_KEY_ID,
            eab_hmac_key=settings.ACME_EAB_HMAC_KEY,
            ca_bundle=ca_bundle,
            insecure=insecure,
            optional_finalize_params=optional_finalize_params,
        ),
        "custom": partial(
            AcmeClient,
            directory_url=settings.ACME_DIRECTORY_URL,
            ca_bundle=ca_bundle,
            insecure=insecure,
            optional_finalize_params=optional_finalize_params,
        ),
    }
    try:
        return registry[ca_provider]()
    except KeyError:
        raise ValueError(
            f"Unknown CA_PROVIDER: {ca_provider!r}. "
            f"Must be one of: {', '.join(registry.keys())}"
        )


def make_client() -> AcmeClient:
    """
    Instantiate the right AcmeClient subclass based on CA_PROVIDER setting.
    Late-imports config to avoid circular imports at module load time.
    """
    from config import settings  # noqa: PLC0415

    return _client_registry(settings.CA_PROVIDER, settings)
