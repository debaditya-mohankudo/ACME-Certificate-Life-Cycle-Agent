"""
certificate_scanner node — reads all managed domain cert files and populates
cert_records + identifies which domains need renewal.

CA detection is only performed when CA_PROVIDER is "custom" (i.e. the operator
has not selected a named CA).  For all named providers (letsencrypt, digicert,
zerossl, sectigo, letsencrypt_staging) the config is authoritative and
detection is skipped — detected_ca_provider is left as None.
"""
from __future__ import annotations

import config
 
from typing import Optional

from agent.state import AgentState, CertRecord
from storage import filesystem as fs

from logger import logger


class CertificateScannerNode:
    """Callable scanner node implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        """
        For each domain in managed_domains:
          - Check if cert.pem exists in cert_store_path
          - Parse expiry date
          - Compute days_until_expiry
          - Set needs_renewal flag
          - Detect CA provider from existing cert (advisory, custom CA only)
        Populates state["cert_records"].
        """
        cert_store_path = state["cert_store_path"]
        managed_domains = state["managed_domains"]
        threshold = state["renewal_threshold_days"]

        records: list[CertRecord] = []

        for domain in managed_domains:
            pem = fs.read_cert_pem(cert_store_path, domain)
            domain_dir = fs.cert_dir(cert_store_path, domain)

            if pem is None:
                logger.info("  %s → no certificate found — will renew", domain)
                record: CertRecord = {
                    "domain": domain,
                    "cert_path": None,
                    "key_path": None,
                    "expiry_date": None,
                    "days_until_expiry": None,
                    "needs_renewal": True,
                    "detected_ca_provider": None,
                }
            else:
                # CA_PROVIDER only exists on AcmeConfig — this node is shared with the
                # spiffe graph (agent/graph.py), where config.settings is a SpiffeConfig
                # and has no such attribute.
                ca_provider = getattr(config.settings, "CA_PROVIDER", None)
                if ca_provider == "custom":
                    detected_ca = fs.detect_ca_for_domain(cert_store_path, domain, pem)
                    _warn_if_ca_mismatch(domain, detected_ca, ca_provider)
                else:
                    detected_ca = None

                try:
                    expiry = fs.parse_expiry(pem)
                    days = fs.days_until_expiry(expiry)
                    needs_renewal = days < threshold
                    status = "URGENT" if days < 7 else ("ROUTINE" if needs_renewal else "OK")
                    logger.info(
                        "  %s → expires %s (%d days) — %s",
                        domain,
                        expiry.strftime("%Y-%m-%d"),
                        days,
                        status,
                    )
                    record = {
                        "domain": domain,
                        "cert_path": str(domain_dir / "cert.pem"),
                        "key_path": str(domain_dir / "privkey.pem"),
                        "expiry_date": expiry.isoformat(),
                        "days_until_expiry": days,
                        "needs_renewal": needs_renewal,
                        "detected_ca_provider": detected_ca,
                    }
                except Exception as exc:
                    logger.warning("  %s → failed to parse cert: %s", domain, exc)
                    record = {
                        "domain": domain,
                        "cert_path": str(domain_dir / "cert.pem"),
                        "key_path": None,
                        "expiry_date": None,
                        "days_until_expiry": None,
                        "needs_renewal": True,
                        "detected_ca_provider": detected_ca,
                    }

            records.append(record)

        return {"cert_records": records}


def certificate_scanner(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `CertificateScannerNode`."""
    return CertificateScannerNode().run(state)


# ─── Internal helpers ──────────────────────────────────────────────────────────


def _warn_if_ca_mismatch(domain: str, detected: Optional[str], configured: str) -> None:
    """
    Log a WARNING when the detected CA differs from the configured CA_PROVIDER.

    Let's Encrypt production and staging are treated as equivalent because
    both are served by "Let's Encrypt" as the issuer O field.
    """
    if detected is None:
        return

    def _normalise(ca: str) -> str:
        return "letsencrypt" if ca == "letsencrypt_staging" else ca

    if _normalise(detected) != _normalise(configured):
        logger.warning(
            "CA mismatch for %s: cert was issued by '%s' but CA_PROVIDER is '%s'. "
            "Renewal will use the configured CA. Update CA_PROVIDER if this is unintended.",
            domain,
            detected,
            configured,
        )
