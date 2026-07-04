"""
Unit tests for CERT_ISSUANCE_MODE — the strict either/or switch between the
ACME and SPIFFE issuance flows.

Verifies:
- Default is "acme" (backwards compatible with existing deployments)
- Valid acme-mode and spiffe-mode configs both construct cleanly
- ACME-only fields left set while mode="spiffe" are coerced to empty, loudly (WARNING)
- SPIFFE-only fields left set while mode="acme" are coerced to empty/default, loudly (WARNING)
- spiffe mode still hard-requires SPIFFE_TRUST_DOMAIN (no sensible value to coerce a missing one to)
- Existing ACME-only validators (EAB, webroot, DNS) are skipped entirely in spiffe mode
"""
from __future__ import annotations

import pytest


def test_cert_issuance_mode_defaults_to_acme():
    from config import Settings

    settings = Settings()
    assert settings.CERT_ISSUANCE_MODE == "acme"


def test_valid_acme_mode_config_constructs(monkeypatch):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "acme")
    from config import Settings

    settings = Settings()
    assert settings.CERT_ISSUANCE_MODE == "acme"
    assert settings.CA_PROVIDER == "digicert"


def test_valid_spiffe_mode_config_constructs(monkeypatch):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    from config import Settings

    settings = Settings()
    assert settings.CERT_ISSUANCE_MODE == "spiffe"
    assert settings.SPIFFE_TRUST_DOMAIN == "example.org"


def test_spiffe_mode_requires_trust_domain(monkeypatch):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    from config import Settings

    with pytest.raises(ValueError, match="SPIFFE_TRUST_DOMAIN must be set"):
        Settings()


def test_spiffe_mode_coerces_managed_domains_to_empty(monkeypatch, caplog):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    monkeypatch.setenv("MANAGED_DOMAINS", "foo.com")
    from config import Settings

    with caplog.at_level("WARNING"):
        settings = Settings()
    assert settings.MANAGED_DOMAINS == []
    assert "ignoring MANAGED_DOMAINS" in caplog.text


def test_acme_mode_coerces_spire_agent_socket_path_to_default(monkeypatch, caplog):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "acme")
    monkeypatch.setenv("SPIRE_AGENT_SOCKET_PATH", "/custom/socket.sock")
    from config import Settings

    with caplog.at_level("WARNING"):
        settings = Settings()
    assert settings.SPIRE_AGENT_SOCKET_PATH == "/tmp/spire-agent/public/api.sock"
    assert "ignoring SPIRE_AGENT_SOCKET_PATH" in caplog.text


def test_acme_mode_coerces_spiffe_trust_domain_to_empty(monkeypatch, caplog):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "acme")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    from config import Settings

    with caplog.at_level("WARNING"):
        settings = Settings()
    assert settings.SPIFFE_TRUST_DOMAIN == ""
    assert "ignoring SPIFFE_TRUST_DOMAIN" in caplog.text


def test_acme_mode_coerces_managed_spiffe_ids_to_empty(monkeypatch, caplog):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "acme")
    monkeypatch.setenv("MANAGED_SPIFFE_IDS", "spiffe://example.org/workload")
    from config import Settings

    with caplog.at_level("WARNING"):
        settings = Settings()
    assert settings.MANAGED_SPIFFE_IDS == []
    assert "ignoring MANAGED_SPIFFE_IDS" in caplog.text


def test_managed_spiffe_ids_accepts_csv_string(monkeypatch):
    """MANAGED_SPIFFE_IDS parses comma-separated strings, same as MANAGED_DOMAINS."""
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    monkeypatch.setenv(
        "MANAGED_SPIFFE_IDS", "spiffe://example.org/a,spiffe://example.org/b"
    )
    from config import Settings

    settings = Settings()
    assert settings.MANAGED_SPIFFE_IDS == [
        "spiffe://example.org/a",
        "spiffe://example.org/b",
    ]


def test_spiffe_mode_skips_eab_validation(monkeypatch):
    """A CA_PROVIDER requiring EAB creds must not be enforced in spiffe mode."""
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    # CA_PROVIDER left at its "digicert" default, which normally requires EAB —
    # must not raise, since ACME validators are skipped entirely in spiffe mode.
    from config import Settings

    settings = Settings()
    assert settings.CERT_ISSUANCE_MODE == "spiffe"


def test_spiffe_mode_skips_acme_directory_resolution(monkeypatch):
    """resolve_acme_directory must not run (and not raise) in spiffe mode."""
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    from config import Settings

    settings = Settings()
    assert settings.ACME_DIRECTORY_URL == ""


def test_spire_agent_socket_path_default(monkeypatch):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    from config import Settings

    settings = Settings()
    assert settings.SPIRE_AGENT_SOCKET_PATH == "/tmp/spire-agent/public/api.sock"
