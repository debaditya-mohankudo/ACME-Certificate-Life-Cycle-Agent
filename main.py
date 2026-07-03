"""
ACME Certificate Lifecycle Agent — CLI entry point.

Usage:
  python main.py --once                 # Run one renewal cycle immediately
  python main.py --schedule             # Run on the configured schedule (default 06:00 UTC)
  python main.py --once --checkpoint    # Run with MemorySaver checkpointing
  python main.py --domains a.com b.com  # Override managed domains for this run
  python main.py --expiring-in-30-days  # Query-only: list domains with certs expiring in <= 30 days (no renewals)
  python main.py --domain-status my.local  # Query-only: print status for one or more domains (no renewals)
  python main.py --generate-test-cert example.com --days 90  # Generate self-signed test cert for 90 days

These CLI commands are read-only unless explicitly documented otherwise; in particular,
the --expiring-in-30-days and --domain-status options never perform certificate issuance,
renewal, revocation, or other state-changing operations.

The --generate-test-cert option generates a self-signed certificate (does not contact ACME servers).
"""
from __future__ import annotations

import argparse
import sys
from typing import Any, Callable

from logger import logger as log

CA_PROVIDER_CHOICES = [
    "digicert",
    "letsencrypt",
    "letsencrypt_staging",
    "zerossl",
    "sectigo",
    "custom",
]


# ── Agent runner ──────────────────────────────────────────────────────────────


def run_once(
    domains: list[str] | None = None,
    use_checkpoint: bool = False,
    settings: Any | None = None,
) -> dict:
    """Execute one full certificate lifecycle cycle and return final state."""
    from agent.graph import build_graph, initial_state
    import config

    effective_settings = settings or config.settings

    effective_domains = domains or effective_settings.MANAGED_DOMAINS
    if not effective_domains:
        log.error("No managed domains configured. Set MANAGED_DOMAINS in .env or pass --domains.")
        sys.exit(1)

    if not effective_settings.LLM_DISABLED:
        _required_keys = {"anthropic": effective_settings.ANTHROPIC_API_KEY, "openai": effective_settings.OPENAI_API_KEY}
        if effective_settings.LLM_PROVIDER in _required_keys and not _required_keys[effective_settings.LLM_PROVIDER]:
            log.error(
                "%s_API_KEY is not set for LLM_PROVIDER=%r. Add it to .env.",
                effective_settings.LLM_PROVIDER.upper(),
                effective_settings.LLM_PROVIDER,
            )
            sys.exit(1)

    log.info("Starting certificate lifecycle agent for %d domain(s): %s",
             len(effective_domains), ", ".join(effective_domains))

    graph = build_graph(use_checkpointing=use_checkpoint)
    state = initial_state(
        managed_domains=effective_domains,
        cert_store_path=effective_settings.CERT_STORE_PATH,
        account_key_path=effective_settings.ACCOUNT_KEY_PATH,
        renewal_threshold_days=effective_settings.RENEWAL_THRESHOLD_DAYS,
        max_retries=effective_settings.MAX_RETRIES,
        webroot_path=effective_settings.WEBROOT_PATH,
    )

    config = {"configurable": {"thread_id": "main"}} if use_checkpoint else None

    final_state = graph.invoke(state, config=config)

    completed = final_state.get("completed_renewals", [])
    failed = final_state.get("failed_renewals", [])
    log.info("Run complete — renewed: %s | failed: %s", completed or "none", failed or "none")

    return final_state


def run_revocation(
    domains: list[str],
    reason: int = 0,
    use_checkpoint: bool = False,
    settings: Any | None = None,
) -> dict:
    """Execute a certificate revocation run and return final state."""
    from agent.revocation_graph import build_revocation_graph, revocation_initial_state
    import config

    effective_settings = settings or config.settings

    # Validate reason code
    if reason not in {0, 1, 4, 5}:
        log.error("Invalid revocation reason %d. Must be one of: 0, 1, 4, 5", reason)
        sys.exit(1)

    if not domains:
        log.error("No domains specified for revocation.")
        sys.exit(1)

    # Warn about unmanaged domains (informational only)
    managed = set(effective_settings.MANAGED_DOMAINS)
    unmanaged = [d for d in domains if d not in managed]
    if unmanaged:
        log.warning("Revoking unmanaged domains: %s", ", ".join(unmanaged))

    log.info("Starting revocation run for %d domain(s): %s (reason=%d)",
             len(domains), ", ".join(domains), reason)

    graph = build_revocation_graph(use_checkpointing=use_checkpoint)
    state = revocation_initial_state(
        domains=domains,
        reason=reason,
        cert_store_path=effective_settings.CERT_STORE_PATH,
        account_key_path=effective_settings.ACCOUNT_KEY_PATH,
    )

    config = {"configurable": {"thread_id": "revocation"}} if use_checkpoint else None

    final_state = graph.invoke(state, config=config)

    revoked = final_state.get("revoked_domains", [])
    failed = final_state.get("failed_revocations", [])
    log.info("Revocation run complete — revoked: %s | failed: %s", revoked or "none", failed or "none")

    return final_state


def run_scheduled(domains: list[str] | None = None, use_checkpoint: bool = False) -> None:
    """Run the agent on a recurring schedule."""
    import schedule
    import time
    from config import settings

    schedule_time = settings.SCHEDULE_TIME
    log.info("Scheduling daily certificate check at %s UTC", schedule_time)

    def job() -> None:
        log.info("Scheduled run triggered")
        try:
            run_once(domains=domains, use_checkpoint=use_checkpoint)
        except Exception as exc:
            log.exception("Scheduled run failed: %s", exc)

    schedule.every().day.at(schedule_time).do(job)

    log.info("Running initial check immediately...")
    job()

    log.info("Entering schedule loop — press Ctrl+C to stop")
    while True:
        schedule.run_pending()
        time.sleep(60)


def list_domains_expiring_within(
    days: int,
    domains: list[str] | None = None,
    settings: Any | None = None,
) -> list[str]:
    """Return domains whose current cert expires within `days` days."""
    import config
    from storage import filesystem as fs

    effective_settings = settings or config.settings

    effective_domains = domains or effective_settings.MANAGED_DOMAINS
    if not effective_domains:
        log.error("No managed domains configured. Set MANAGED_DOMAINS in .env or pass --domains.")
        sys.exit(1)

    expiring: list[tuple[str, int]] = []
    for domain in effective_domains:
        pem = fs.read_cert_pem(effective_settings.CERT_STORE_PATH, domain)
        if pem is None:
            continue
        try:
            expiry = fs.parse_expiry(pem)
            days_until_expiry = fs.days_until_expiry(expiry)
            if days_until_expiry <= days:
                expiring.append((domain, days_until_expiry))
        except Exception as exc:
            log.warning("Skipping %s: failed to parse cert expiry: %s", domain, exc)

    expiring.sort(key=lambda item: item[1])
    return [domain for domain, _ in expiring]


def generate_test_cert(
    domain: str,
    days: int = 30,
) -> None:
    """Generate a self-signed test certificate for a domain."""
    import config
    from pathlib import Path
    from scripts.generate_test_cert import generate_self_signed_cert
    from storage.filesystem import sanitize_domain_for_path
    
    if not domain:
        log.error("Domain is required for test certificate generation.")
        sys.exit(1)
    
    if days < 1 or days > 3650:
        log.error("Days must be between 1 and 3650.")
        sys.exit(1)
    
    try:
        safe_domain = sanitize_domain_for_path(domain)
        cert_path = Path(config.settings.CERT_STORE_PATH) / safe_domain / "cert.pem"
        key_path = Path(config.settings.CERT_STORE_PATH) / safe_domain / "privkey.pem"
        generate_self_signed_cert(
            domain=domain,
            validity_days=days,
        )
        log.info(
            "Test certificate generated successfully.\n"
            "  Domain: %s\n"
            "  Validity: %d days\n"
            "  Cert: %s\n"
            "  Key: %s",
            domain,
            days,
            cert_path,
            key_path,
        )
    except Exception as exc:
        log.error("Failed to generate test certificate: %s", exc)
        sys.exit(1)


def get_domain_statuses(
    domains: list[str],
    settings: Any | None = None,
) -> list[dict[str, str | int | bool | None]]:
    """Return certificate status details for one or more domains."""
    import config
    from storage import filesystem as fs

    effective_settings = settings or config.settings

    if not domains:
        log.error("No domains provided for status lookup.")
        sys.exit(1)

    statuses: list[dict[str, str | int | bool | None]] = []
    for domain in domains:
        pem = fs.read_cert_pem(effective_settings.CERT_STORE_PATH, domain)
        if pem is None:
            statuses.append(
                {
                    "domain": domain,
                    "cert_found": False,
                    "status": "missing",
                    "expires_at": None,
                    "days_until_expiry": None,
                    "expired": None,
                }
            )
            continue

        try:
            expiry = fs.parse_expiry(pem)
            days_until_expiry = fs.days_until_expiry(expiry)
            if days_until_expiry < 0:
                status = "expired"
            elif days_until_expiry <= 30:
                status = "expiring_soon"
            else:
                status = "valid"

            statuses.append(
                {
                    "domain": domain,
                    "cert_found": True,
                    "status": status,
                    "expires_at": expiry.isoformat(),
                    "days_until_expiry": days_until_expiry,
                    "expired": days_until_expiry < 0,
                }
            )
        except Exception as exc:
            statuses.append(
                {
                    "domain": domain,
                    "cert_found": True,
                    "status": "parse_error",
                    "expires_at": None,
                    "days_until_expiry": None,
                    "expired": None,
                }
            )
            log.warning("Failed to parse cert expiry for %s: %s", domain, exc)

    return statuses


def build_settings_from_override(
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
    base_settings: Any | None = None,
) -> Any:
    """Build an explicit Settings object from base settings plus optional overrides."""
    import config

    effective_base = base_settings or config.settings
    if not ca_provider and not acme_directory_url:
        return effective_base

    data = effective_base.model_dump()
    if ca_provider is not None:
        data["CA_PROVIDER"] = ca_provider
    if acme_directory_url is not None:
        data["ACME_DIRECTORY_URL"] = acme_directory_url

    return config.Settings(**data)


def apply_runtime_settings_overrides(
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> None:
    """Apply one-shot CLI settings overrides by replacing the settings singleton."""
    if not ca_provider and not acme_directory_url:
        return

    import config

    config.settings = build_settings_from_override(
        ca_provider=ca_provider,
        acme_directory_url=acme_directory_url,
        base_settings=config.settings,
    )

    log.info(
        "Applied runtime config override: CA_PROVIDER=%s ACME_DIRECTORY_URL=%s",
        config.settings.CA_PROVIDER,
        config.settings.ACME_DIRECTORY_URL,
    )


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ACME Certificate Lifecycle Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --once
  python main.py --schedule
  python main.py --once --domains api.example.com shop.example.com
  python main.py --once --ca-provider custom --acme-directory-url https://localhost:14000/dir
  python main.py --once --checkpoint
  python main.py --expiring-in-30-days
  python main.py --domain-status my.local api.example.com
  python main.py --revoke-cert example.com api.example.com
  python main.py --revoke-cert example.com --reason 4
        """,
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one renewal cycle immediately and exit",
    )
    parser.add_argument(
        "--schedule",
        action="store_true",
        help="Run on the configured daily schedule (SCHEDULE_TIME in .env)",
    )
    parser.add_argument(
        "--revoke-cert",
        nargs="+",
        metavar="DOMAIN",
        help="Revoke certificates for one or more domains",
    )
    parser.add_argument(
        "--reason",
        type=int,
        default=0,
        metavar="CODE",
        help="RFC 5280 revocation reason code (default: 0=unspecified; also: 1=keyCompromise, 4=superseded, 5=cessationOfOperation)",
    )
    parser.add_argument(
        "--domains",
        nargs="+",
        metavar="DOMAIN",
        help="Override managed domains for renewal run",
    )
    parser.add_argument(
        "--checkpoint",
        action="store_true",
        help="Enable MemorySaver checkpointing for resumable runs",
    )
    parser.add_argument(
        "--expiring-in-30-days",
        action="store_true",
        help="Print domains whose existing certificates expire in 30 days or less",
    )
    parser.add_argument(
        "--domain-status",
        nargs="+",
        metavar="DOMAIN",
        help="Print certificate status details for one or more domains",
    )
    parser.add_argument(
        "--ca-provider",
        choices=CA_PROVIDER_CHOICES,
        help="Override CA provider for this process only",
    )
    parser.add_argument(
        "--acme-directory-url",
        metavar="URL",
        help="Override ACME directory URL for this process only (typically with --ca-provider custom)",
    )
    parser.add_argument(
        "--generate-test-cert",
        metavar="DOMAIN",
        help="Generate a self-signed test certificate for the specified domain",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        metavar="N",
        help="Validity period in days for generated test certificate (default: 30; range: 1-3650)",
    )

    args = parser.parse_args()

    def _has_selected_action(parsed_args: argparse.Namespace) -> bool:
        """Return True if at least one primary CLI action flag was provided."""
        return (
            parsed_args.once
            or parsed_args.schedule
            or parsed_args.revoke_cert
            or parsed_args.expiring_in_30_days
            or bool(parsed_args.domain_status)
            or bool(parsed_args.generate_test_cert)
        )

    if not _has_selected_action(args):
        parser.print_help()
        sys.exit(1)

    apply_runtime_settings_overrides(
        ca_provider=args.ca_provider,
        acme_directory_url=args.acme_directory_url,
    )

    # ── Command registry for CLI dispatch ────────────────────────────────────
    
    def cmd_domain_status() -> None:
        """Handler: print certificate status for specified domains."""
        statuses = get_domain_statuses(args.domain_status)
        for item in statuses:
            print(item)

    def cmd_expiring_in_30_days() -> None:
        """Handler: list domains expiring within 30 days."""
        expiring_domains = list_domains_expiring_within(days=30, domains=args.domains)
        if expiring_domains:
            print("\n".join(expiring_domains))
        else:
            print("No domains expiring within 30 days.")
    
    def cmd_generate_test_cert() -> None:
        """Handler: generate a self-signed test certificate."""
        generate_test_cert(domain=args.generate_test_cert, days=args.days)
    
    def cmd_revoke_cert() -> None:
        """Handler: revoke one or more certificates."""
        run_revocation(domains=args.revoke_cert, reason=args.reason, use_checkpoint=args.checkpoint)
    
    def cmd_once() -> None:
        """Handler: run one renewal cycle immediately."""
        run_once(domains=args.domains, use_checkpoint=args.checkpoint)
    
    def cmd_schedule() -> None:
        """Handler: run on a recurring daily schedule."""
        run_scheduled(domains=args.domains, use_checkpoint=args.checkpoint)
    
    # ── Registry: maps CLI action to handler function ────────────────────────
    command_registry: dict[str, tuple[bool, Callable[[], None]]] = {
        "domain_status": (bool(args.domain_status), cmd_domain_status),
        "expiring_in_30_days": (args.expiring_in_30_days, cmd_expiring_in_30_days),
        "generate_test_cert": (bool(args.generate_test_cert), cmd_generate_test_cert),
        "revoke_cert": (bool(args.revoke_cert), cmd_revoke_cert),
        "once": (args.once, cmd_once),
        "schedule": (args.schedule, cmd_schedule),
    }
    
    # ── Execute first matching command ────────────────────────────────────────
    for _, (is_selected, handler) in command_registry.items():
        if is_selected:
            handler()
            break


if __name__ == "__main__":
    main()
