"""
Unit tests for CERT_ISSUANCE_MODE — the strict either/or switch between the
ACME and SPIFFE issuance flows.

Verifies:
- make_settings() defaults to AcmeConfig (backwards compatible with existing deployments)
- make_settings() constructs the right class for each mode, and only that class
- ACME-only fields simply don't exist on SpiffeConfig, and vice versa (not "coerced" —
  they're never present in the first place, since each is a separate pydantic class)
- Stray other-mode env vars are logged as a WARNING by make_settings() itself
  (relocated from the old validate_cert_issuance_mode_fields coercion, task:63eee5d7)
- spiffe mode still hard-requires SPIFFE_TRUST_DOMAIN (no sensible value to invent for a
  missing required value)
- Existing ACME-only validators (EAB, webroot, DNS) don't exist at all on SpiffeConfig
"""
from __future__ import annotations

import pytest


def test_make_settings_defaults_to_acme_config():
    from config import AcmeConfig, make_settings

    settings = make_settings()
    assert isinstance(settings, AcmeConfig)
    assert settings.CERT_ISSUANCE_MODE == "acme"


def test_make_settings_constructs_acme_config(monkeypatch):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "acme")
    from config import AcmeConfig, make_settings

    settings = make_settings()
    assert isinstance(settings, AcmeConfig)
    assert settings.CA_PROVIDER == "digicert"


def test_make_settings_constructs_spiffe_config(monkeypatch):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    from config import SpiffeConfig, make_settings

    settings = make_settings()
    assert isinstance(settings, SpiffeConfig)
    assert settings.SPIFFE_TRUST_DOMAIN == "example.org"


def test_spiffe_mode_requires_trust_domain(monkeypatch):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    from config import make_settings

    with pytest.raises(ValueError, match="SPIFFE_TRUST_DOMAIN must be set"):
        make_settings()


def test_spiffe_config_has_no_acme_only_fields():
    """AcmeConfig-only fields simply don't exist on SpiffeConfig — not cleared, absent."""
    from config import SpiffeConfig

    settings = SpiffeConfig(SPIFFE_TRUST_DOMAIN="example.org")
    for field in ("CA_PROVIDER", "MANAGED_DOMAINS", "ACME_DIRECTORY_URL",
                  "ACME_EAB_KEY_ID", "ACME_EAB_HMAC_KEY"):
        assert not hasattr(settings, field), f"SpiffeConfig should not have {field}"


def test_acme_config_has_no_spiffe_only_fields():
    """SpiffeConfig-only fields simply don't exist on AcmeConfig — not cleared, absent."""
    from config import AcmeConfig

    settings = AcmeConfig()
    for field in ("SPIRE_AGENT_SOCKET_PATH", "SPIFFE_TRUST_DOMAIN", "MANAGED_SPIFFE_IDS"):
        assert not hasattr(settings, field), f"AcmeConfig should not have {field}"


def test_make_settings_warns_on_stray_spiffe_env_vars_in_acme_mode(monkeypatch, caplog):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "acme")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    monkeypatch.setenv("MANAGED_SPIFFE_IDS", "spiffe://example.org/workload")
    monkeypatch.setenv("SPIRE_AGENT_SOCKET_PATH", "/custom/socket.sock")
    from config import make_settings

    with caplog.at_level("WARNING"):
        settings = make_settings()

    assert not hasattr(settings, "SPIFFE_TRUST_DOMAIN")
    assert "ignoring SPIFFE_TRUST_DOMAIN" in caplog.text
    assert "ignoring MANAGED_SPIFFE_IDS" in caplog.text
    assert "ignoring SPIRE_AGENT_SOCKET_PATH" in caplog.text


def test_make_settings_warns_on_stray_managed_domains_in_spiffe_mode(monkeypatch, caplog):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    monkeypatch.setenv("MANAGED_DOMAINS", "foo.com")
    from config import make_settings

    with caplog.at_level("WARNING"):
        settings = make_settings()

    assert not hasattr(settings, "MANAGED_DOMAINS")
    assert "ignoring MANAGED_DOMAINS" in caplog.text


def test_managed_spiffe_ids_accepts_csv_string(monkeypatch):
    """MANAGED_SPIFFE_IDS parses comma-separated strings, same as MANAGED_DOMAINS."""
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    monkeypatch.setenv(
        "MANAGED_SPIFFE_IDS", "spiffe://example.org/a,spiffe://example.org/b"
    )
    from config import make_settings

    settings = make_settings()
    assert settings.MANAGED_SPIFFE_IDS == [
        "spiffe://example.org/a",
        "spiffe://example.org/b",
    ]


def test_spiffe_mode_skips_eab_validation(monkeypatch):
    """A CA_PROVIDER requiring EAB creds doesn't exist to enforce in spiffe mode."""
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    from config import SpiffeConfig, make_settings

    settings = make_settings()
    assert isinstance(settings, SpiffeConfig)


def test_spiffe_mode_has_no_acme_directory_resolution(monkeypatch):
    """resolve_acme_directory doesn't exist on SpiffeConfig — nothing to resolve or raise."""
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    from config import make_settings

    settings = make_settings()
    assert not hasattr(settings, "ACME_DIRECTORY_URL")


def test_spire_agent_socket_path_default(monkeypatch):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    from config import make_settings

    settings = make_settings()
    assert settings.SPIRE_AGENT_SOCKET_PATH == "/tmp/spire-agent/public/api.sock"
