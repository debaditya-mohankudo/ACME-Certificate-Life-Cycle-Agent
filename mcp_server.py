"""
MCP server exposing ACME lifecycle services as tools.

Tools:
  - health: configuration/provider sanity check (no side effects)
  - renew_once: run one renewal cycle
  - revoke_cert: revoke one or more certificates
  - expiring_in_30_days: list domains with certs expiring in <= 30 days
  - expiring_within: list domains with certs expiring within N days (configurable)
  - domain_status: get cert status for one or more domains
  - list_managed_domains: return the configured managed domain list
  - read_cert_details: rich cert inspection — SANs, issuer, serial, CA, validity dates
  - generate_test_cert: generate self-signed test certificate with configurable validity
"""
from __future__ import annotations

import asyncio
from logger import logger
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from config import Settings

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "MCP dependency is missing. Install project dependencies with 'uv sync'."
    ) from exc


mcp = FastMCP("acme-certificate-lifecycle-agent")
CA_PROVIDER_CHOICES = {
    "digicert",
    "letsencrypt",
    "letsencrypt_staging",
    "zerossl",
    "sectigo",
    "custom",
}
CA_INPUT_MODE_CHOICES = {"config", "custom"}
# Rationale: see doc/MCP_TOOL_SERIALIZATION.md#why-asyncio-lock-instead-of-threading-lock
_MCP_OPERATION_LOCK = asyncio.Lock()


def _resolve_ca_inputs(
    ca_input_mode: str,
    ca_provider: str | None,
    acme_directory_url: str | None,
) -> tuple[str | None, str | None]:
    """Resolve CA inputs from explicit mode selection.

    - config: use config.py/.env values, ignore custom inputs
    - custom: require both ca_provider and acme_directory_url (validates ca_provider against known choices)
    """
    if ca_input_mode not in CA_INPUT_MODE_CHOICES:
        raise ValueError(f"ca_input_mode must be one of: {', '.join(sorted(CA_INPUT_MODE_CHOICES))}")

    if ca_input_mode == "config":
        return None, None

    # Validate custom mode inputs
    if not ca_provider or not acme_directory_url:
        raise ValueError(
            "When ca_input_mode='custom', both ca_provider and acme_directory_url are required"
        )
    
    # Validate ca_provider is a known choice
    if ca_provider not in CA_PROVIDER_CHOICES:
        raise ValueError(
            f"ca_provider must be one of: {', '.join(sorted(CA_PROVIDER_CHOICES))}"
        )
    
    # Basic URL validation
    if not acme_directory_url.startswith(("http://", "https://")):
        raise ValueError("acme_directory_url must start with http:// or https://")
    
    return ca_provider, acme_directory_url


@contextmanager
def _temporary_settings_override(
    settings_override: Settings | None = None,
):
    """Temporarily replace config settings for a single tool execution."""
    import config

    original_settings = config.settings
    if settings_override is not None:
        config.settings = settings_override

    try:
        yield
    finally:
        config.settings = original_settings


def _build_effective_settings(
    ca_provider: str | None,
    acme_directory_url: str | None,
) -> Settings:
    from main import build_settings_from_override
    import config

    return build_settings_from_override(
        ca_provider=ca_provider,
        acme_directory_url=acme_directory_url,
        base_settings=config.settings,
    )


def _validate_reason(reason: int) -> int:
    if reason not in {0, 1, 4, 5}:
        raise ValueError("reason must be one of: 0, 1, 4, 5")
    return reason


def _validate_domain_for_cert_generation(domain: str) -> None:
    """Validate domain to prevent path traversal and directory escape attacks.
    
    Ensures domain is:
    - Non-empty
    - Does not contain path separators or traversal sequences
    - Safe to use as a subdirectory within CERT_STORE_PATH
    """
    if not domain:
        raise ValueError("domain cannot be empty")
    if "/" in domain or "\\" in domain:
        raise ValueError("domain cannot contain path separators")
    if ".." in domain or domain.startswith("."):
        raise ValueError("domain cannot contain path traversal sequences")
    if domain in {".", ".."}:
        raise ValueError("invalid domain name")


@asynccontextmanager
async def _operation_lock(*, required: bool):
    """Acquire process-wide operation lock when required by policy."""
    if not required:
        yield
        return

    async with _MCP_OPERATION_LOCK:
        yield


def _run_renew_once(domains: list[str] | None, checkpoint: bool, settings: Settings | None = None) -> dict[str, Any]:
    from main import run_once

    try:
        return run_once(domains=domains, use_checkpoint=checkpoint, settings=settings)
    except SystemExit as exc:
        raise RuntimeError(f"renew_once failed with exit code {exc.code}") from exc


def _run_revoke(
    domains: list[str],
    reason: int,
    checkpoint: bool,
    settings: Settings | None = None,
) -> dict[str, Any]:
    from main import run_revocation

    try:
        return run_revocation(
            domains=domains,
            reason=reason,
            use_checkpoint=checkpoint,
            settings=settings,
        )
    except SystemExit as exc:
        raise RuntimeError(f"revoke_cert failed with exit code {exc.code}") from exc


def _run_expiring_in_30_days(domains: list[str] | None, settings: Settings | None = None) -> list[str]:
    from main import list_domains_expiring_within

    try:
        return list_domains_expiring_within(days=30, domains=domains, settings=settings)
    except SystemExit as exc:
        raise RuntimeError(
            f"expiring_in_30_days failed with exit code {exc.code}"
        ) from exc


def _run_expiring_within(days: int, domains: list[str] | None, settings: Settings | None = None) -> list[str]:
    from main import list_domains_expiring_within

    try:
        return list_domains_expiring_within(days=days, domains=domains, settings=settings)
    except SystemExit as exc:
        raise RuntimeError(
            f"expiring_within failed with exit code {exc.code}"
        ) from exc


def _run_domain_status(domains: list[str], settings: Settings | None = None) -> list[dict[str, Any]]:
    from main import get_domain_statuses

    try:
        return get_domain_statuses(domains, settings=settings)
    except SystemExit as exc:
        raise RuntimeError(f"domain_status failed with exit code {exc.code}") from exc


@mcp.tool()
async def health(
    ca_input_mode: Literal["config", "custom"],
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Return non-secret configuration/readiness checks with explicit CA input mode."""
    try:
        import config

        resolved_provider, resolved_directory = _resolve_ca_inputs(
            ca_input_mode=ca_input_mode,
            ca_provider=ca_provider,
            acme_directory_url=acme_directory_url,
        )
        effective_settings = _build_effective_settings(
            ca_provider=resolved_provider,
            acme_directory_url=resolved_directory,
        )

        async with _operation_lock(required=True):
            with _temporary_settings_override(
                settings_override=effective_settings,
            ):
                current_settings = config.settings
                missing_llm_key = not current_settings.LLM_DISABLED and (
                    (current_settings.LLM_PROVIDER == "anthropic" and not current_settings.ANTHROPIC_API_KEY)
                    or (current_settings.LLM_PROVIDER == "openai" and not current_settings.OPENAI_API_KEY)
                )

                warnings: list[str] = []
                if not current_settings.MANAGED_DOMAINS:
                    warnings.append("MANAGED_DOMAINS is empty")
                if missing_llm_key:
                    warnings.append(f"{current_settings.LLM_PROVIDER.upper()} API key is not set")
                if (
                    current_settings.HTTP_CHALLENGE_MODE == "standalone"
                    and current_settings.HTTP_CHALLENGE_PORT != 80
                ):
                    warnings.append("HTTP_CHALLENGE_PORT is not 80; ensure public HTTP-01 reachability")
                if current_settings.ACME_INSECURE:
                    warnings.append("ACME_INSECURE=true (testing only)")

                return {
                    "ok": len(warnings) == 0,
                    "provider": current_settings.CA_PROVIDER,
                    "acme_directory": current_settings.ACME_DIRECTORY_URL,
                    "llm_provider": current_settings.LLM_PROVIDER,
                    "challenge_mode": current_settings.HTTP_CHALLENGE_MODE,
                    "managed_domain_count": len(current_settings.MANAGED_DOMAINS),
                    "warnings": warnings,
                }
    except Exception as e:
        logger.exception("health check failed")
        return {
            "ok": False,
            "status": "failed",
            "error": str(e),
        }


@mcp.tool()
async def renew_once(
    ca_input_mode: Literal["config", "custom"],
    domains: list[str] | None = None,
    checkpoint: bool = False,
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Run one renewal cycle with explicit CA input mode."""
    try:
        resolved_provider, resolved_directory = _resolve_ca_inputs(
            ca_input_mode=ca_input_mode,
            ca_provider=ca_provider,
            acme_directory_url=acme_directory_url,
        )
        effective_settings = _build_effective_settings(
            ca_provider=resolved_provider,
            acme_directory_url=resolved_directory,
        )

        async with _operation_lock(required=True):
            with _temporary_settings_override(
                settings_override=effective_settings,
            ):
                final_state = _run_renew_once(
                    domains=domains,
                    checkpoint=checkpoint,
                    settings=effective_settings,
                )
                return {
                    "status": "success",
                    "completed_renewals": final_state.get("completed_renewals", []),
                    "failed_renewals": final_state.get("failed_renewals", []),
                    "error_log": final_state.get("error_log", []),
                }
    except Exception as e:
        logger.exception("renew_once failed")
        return {
            "status": "failed",
            "error": str(e),
        }


@mcp.tool()
async def revoke_cert(
    ca_input_mode: Literal["config", "custom"],
    domains: list[str],
    reason: int = 0,
    checkpoint: bool = False,
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Revoke certs with explicit CA input mode (RFC 5280 reasons: 0,1,4,5)."""
    try:
        if not domains:
            raise ValueError("domains must contain at least one domain")

        resolved_provider, resolved_directory = _resolve_ca_inputs(
            ca_input_mode=ca_input_mode,
            ca_provider=ca_provider,
            acme_directory_url=acme_directory_url,
        )
        effective_settings = _build_effective_settings(
            ca_provider=resolved_provider,
            acme_directory_url=resolved_directory,
        )

        async with _operation_lock(required=True):
            with _temporary_settings_override(
                settings_override=effective_settings,
            ):
                final_state = _run_revoke(
                    domains=domains,
                    reason=_validate_reason(reason),
                    checkpoint=checkpoint,
                    settings=effective_settings,
                )
                return {
                    "status": "success",
                    "revoked_domains": final_state.get("revoked_domains", []),
                    "failed_revocations": final_state.get("failed_revocations", []),
                    "error_log": final_state.get("error_log", []),
                }
    except Exception as e:
        logger.exception("revoke_cert failed")
        return {
            "status": "failed",
            "error": str(e),
        }


@mcp.tool()
async def expiring_in_30_days(domains: list[str] | None = None) -> dict[str, Any]:
    """List domains whose current cert expires in 30 days or less (read-only, not serialized)."""
    try:
        import config

        async with _operation_lock(required=False):
            expiring_domains = _run_expiring_in_30_days(domains=domains, settings=config.settings)
        return {
            "status": "success",
            "window_days": 30,
            "expiring_domains": expiring_domains,
        }
    except Exception as e:
        logger.exception("expiring_in_30_days failed")
        return {
            "status": "failed",
            "error": str(e),
        }


@mcp.tool()
async def expiring_within(days: int, domains: list[str] | None = None) -> dict[str, Any]:
    """List domains whose current cert expires within N days (read-only, not serialized).

    Args:
        days: Look-ahead window in days (1–3650).
        domains: Domains to check. Defaults to all managed domains.
    """
    try:
        if days < 1 or days > 3650:
            raise ValueError("days must be between 1 and 3650")

        import config

        async with _operation_lock(required=False):
            expiring_domains = _run_expiring_within(days=days, domains=domains, settings=config.settings)
        return {
            "status": "success",
            "window_days": days,
            "expiring_domains": expiring_domains,
        }
    except Exception as e:
        logger.exception("expiring_within failed")
        return {
            "status": "failed",
            "error": str(e),
        }


@mcp.tool()
async def list_managed_domains() -> dict[str, Any]:
    """Return the list of domains currently configured in MANAGED_DOMAINS (read-only, not serialized)."""
    try:
        import config

        async with _operation_lock(required=False):
            domains = list(config.settings.MANAGED_DOMAINS)
        return {
            "status": "success",
            "managed_domains": domains,
            "count": len(domains),
        }
    except Exception as e:
        logger.exception("list_managed_domains failed")
        return {
            "status": "failed",
            "error": str(e),
        }


def _extract_cert_details(pem_text: str, domain: str, cert_store_path: str) -> dict[str, Any]:
    """Parse a PEM certificate and return rich detail fields."""
    from cryptography import x509 as _x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import ExtensionOID, NameOID
    from storage.filesystem import parse_expiry, days_until_expiry, detect_ca_for_domain

    cert = _x509.load_pem_x509_certificate(pem_text.encode(), default_backend())

    # Subject CN
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject_cn = cn_attrs[0].value if cn_attrs else None
    except Exception:
        subject_cn = None

    # Issuer O
    try:
        o_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        issuer_org = o_attrs[0].value if o_attrs else None
    except Exception:
        issuer_org = None

    # SANs
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(name.value) for name in san_ext.value]
    except _x509.ExtensionNotFound:
        sans = []

    # Serial number (colon-separated hex, standard display format)
    serial_hex = format(cert.serial_number, "x")
    serial_display = ":".join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))

    # Validity window
    try:
        not_before = cert.not_valid_before_utc.isoformat()
    except AttributeError:
        from datetime import timezone as _tz
        not_before = cert.not_valid_before.replace(tzinfo=_tz.utc).isoformat()

    expiry = parse_expiry(pem_text)
    days_left = days_until_expiry(expiry)

    if days_left < 0:
        status = "expired"
    elif days_left <= 30:
        status = "expiring_soon"
    else:
        status = "valid"

    # CA detection (metadata.json first, then issuer inspection)
    detected_ca = detect_ca_for_domain(cert_store_path, domain, pem_text)

    return {
        "domain": domain,
        "cert_found": True,
        "status": status,
        "subject_cn": subject_cn,
        "sans": sans,
        "issuer_org": issuer_org,
        "detected_ca": detected_ca,
        "serial": serial_display,
        "not_before": not_before,
        "not_after": expiry.isoformat(),
        "days_until_expiry": days_left,
        "expired": days_left < 0,
    }


@mcp.tool()
async def read_cert_details(domains: list[str]) -> dict[str, Any]:
    """Return rich certificate details for one or more domains (read-only, not serialized).

    Includes subject CN, SANs, issuer org, detected CA, serial number, and validity dates.
    """
    try:
        import config
        from storage.filesystem import read_cert_pem

        if not domains:
            raise ValueError("domains must contain at least one domain")

        results: list[dict[str, Any]] = []
        async with _operation_lock(required=False):
            cert_store_path = config.settings.CERT_STORE_PATH
            for domain in domains:
                pem = read_cert_pem(cert_store_path, domain)
                if pem is None:
                    results.append({"domain": domain, "cert_found": False})
                    continue
                try:
                    results.append(_extract_cert_details(pem, domain, cert_store_path))
                except Exception as exc:
                    results.append({"domain": domain, "cert_found": True, "status": "parse_error", "error": str(exc)})

        return {"status": "success", "cert_details": results}
    except Exception as e:
        logger.exception("read_cert_details failed")
        return {"status": "failed", "error": str(e)}


@mcp.tool()
async def domain_status(domains: list[str]) -> dict[str, Any]:
    """Get certificate status details for one or more domains (read-only, not serialized)."""
    try:
        import config

        if not domains:
            raise ValueError("domains must contain at least one domain")

        async with _operation_lock(required=False):
            return {
                "status": "success",
                "domain_statuses": _run_domain_status(domains=domains, settings=config.settings),
            }
    except Exception as e:
        logger.exception("domain_status failed")
        return {
            "status": "failed",
            "error": str(e),
        }


@mcp.tool()
async def generate_test_cert(
    domain: str,
    days: int,
) -> dict[str, Any]:
    """Generate a self-signed test certificate with configurable validity period.
    
    Certificates are stored in the configured CERT_STORE_PATH, with one directory per domain.
    
    Args:
        domain: Domain name to use as Common Name (CN) in the certificate
                (must not contain path separators or traversal sequences)
        days: Validity period in days from now (use negative for expired certs)
    
    Returns:
        Dictionary with status, certificate details, and file paths
    """
    try:
        from scripts.generate_test_cert import generate_self_signed_cert
        import datetime
        import config
        
        # Validate domain to prevent path traversal attacks
        _validate_domain_for_cert_generation(domain)
        
        # Always use the configured CERT_STORE_PATH (never accept arbitrary paths)
        store_path = Path(config.settings.CERT_STORE_PATH)
        output_dir = store_path / domain
        
        # Generate the certificate
        async with _operation_lock(required=True):
            generate_self_signed_cert(
                domain=domain,
                validity_days=days,
                output_dir=output_dir,
            )
        
        # Calculate expiry status
        now = datetime.datetime.now(datetime.timezone.utc)
        not_valid_after = now + datetime.timedelta(days=days)
        days_remaining = (not_valid_after - now).days
        status_text = "EXPIRED" if days_remaining < 0 else ("EXPIRING SOON" if days_remaining <= 30 else "VALID")
        
        return {
            "status": "success",
            "message": f"Generated self-signed certificate for {domain}",
            "domain": domain,
            "validity_days": days,
            "cert_status": status_text,
            "days_remaining": days_remaining,
            "output_directory": str(output_dir),
            "files": [
                str(output_dir / "cert.pem"),
                str(output_dir / "privkey.pem"),
                str(output_dir / "metadata.json"),
            ],
        }
    except Exception as e:
        logger.exception("generate_test_cert failed")
        return {
            "status": "failed",
            "error": str(e),
        }


if __name__ == "__main__":
    mcp.run()
