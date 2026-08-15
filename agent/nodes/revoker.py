"""
cert_revoker node — revoke a certificate via ACME POST /revokeCert.

RFC 8555 §7.6: the client POSTs a JWS-signed payload containing the
base64url-encoded DER certificate and an optional RFC 5280 reason code
(0=unspecified, 1=keyCompromise, 4=superseded, 5=cessationOfOperation).
Reason code 0 omits the field from the payload per §7.6.

Security note: the account key is loaded from disk, never stored in AgentState
or returned in the result dict.

Retry policy: only errors known to be transient (rate limiting, server-side
5xx, connection failures) are retried, with the same bounded exponential
backoff formula as agent/nodes/error_handler.py. Everything else — policy or
protocol rejections (unauthorized, alreadyRevoked, malformed, missing local
cert file) — is treated as fatal for that domain: log and move on. See
doc/REVOCATION_IMPLEMENTATION.md "Best-Effort, No Retries" for the (now
narrower) rationale.
"""
from __future__ import annotations

import time

from acme import jws as jwslib
from acme.client import AcmeError, make_client
from agent.state import AgentState
from storage import filesystem as fs

from logger import logger

# ACME problem-document "type" fragments (both the RFC 8555
# urn:ietf:params:acme:error:* form and the older urn:acme:error:* form seen
# in this codebase) that indicate a transient failure worth retrying.
_RETRYABLE_ERROR_PATTERNS = (
    "ratelimited",
    "serverinternal",
    "connection",
)


def _is_retryable_error(exc: AcmeError) -> bool:
    lower = str(exc).lower()
    return any(pat in lower for pat in _RETRYABLE_ERROR_PATTERNS)


def _revocation_backoff(retry_count: int, retry_delay_seconds: int) -> int:
    """Same exponential-backoff formula as error_handler.py's renewal path,
    capped at 300s — kept as a private duplicate rather than a shared import
    so the two graphs' retry policies can diverge independently later."""
    exponent = retry_count + 1
    return int(min(retry_delay_seconds * (2 ** exponent), 300))


class CertRevokerNode:
    """Callable certificate revoker implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        domain = state["current_revocation_domain"]
        if not domain:
            logger.warning("cert_revoker called with no current_revocation_domain")
            return {}

        cert_pem = fs.read_cert_pem(state["cert_store_path"], domain)
        if cert_pem is None:
            logger.error("Certificate file not found for domain %s", domain)
            error_msg = f"Revocation failed for {domain}: certificate file not found"
            return {
                "failed_revocations": state.get("failed_revocations", []) + [domain],
                "error_log": state.get("error_log", []) + [error_msg],
                "current_revocation_domain": None,
            }

        account_key_path = state["account_key_path"]
        account_key = jwslib.load_account_key(account_key_path)

        client = make_client()
        directory = client.get_directory()

        nonce = state.get("current_nonce") or client.get_nonce(directory)

        try:
            new_nonce = client.revoke_certificate(
                cert_pem=cert_pem,
                account_key=account_key,
                account_url=state["acme_account_url"],
                nonce=nonce,
                directory=directory,
                reason=state.get("revocation_reason", 0),
            )
            logger.info("Revoked certificate for domain: %s", domain)
            return {
                "revoked_domains": state.get("revoked_domains", []) + [domain],
                "current_nonce": new_nonce,
                "current_revocation_domain": None,
                "retry_count": 0,
                "retry_not_before": None,
            }

        except AcmeError as exc:
            logger.error("Revocation failed for %s: %s", domain, exc)
            error_msg = f"Revocation failed for {domain}: {exc}"
            updates: dict = {
                "current_nonce": exc.new_nonce or nonce,
                "error_log": state.get("error_log", []) + [error_msg],
            }

            retry_count = state.get("retry_count", 0)
            max_retries = state.get("max_retries", 0)
            if _is_retryable_error(exc) and retry_count < max_retries:
                new_retry_count = retry_count + 1
                delay = _revocation_backoff(retry_count, state.get("retry_delay_seconds", 5))
                retry_not_before = time.time() + delay
                logger.info(
                    "Revocation retry #%d for %s (backoff %ds, retry at %d)",
                    new_retry_count, domain, delay, int(retry_not_before),
                )
                # current_revocation_domain stays set — the retry loops back to
                # cert_revoker for this SAME domain, not the next one.
                updates.update(
                    retry_count=new_retry_count,
                    retry_delay_seconds=delay,
                    retry_not_before=retry_not_before,
                )
                return updates

            updates.update(
                failed_revocations=state.get("failed_revocations", []) + [domain],
                current_revocation_domain=None,
                retry_count=0,
                retry_not_before=None,
            )
            return updates


def cert_revoker(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `CertRevokerNode`."""
    return CertRevokerNode().run(state)
