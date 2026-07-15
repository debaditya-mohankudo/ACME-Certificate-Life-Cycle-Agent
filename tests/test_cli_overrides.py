from __future__ import annotations

from types import SimpleNamespace
import sys

import pytest

import config
import main


def test_apply_runtime_settings_overrides_custom(monkeypatch):
    original_settings = config.settings
    monkeypatch.setenv("CA_PROVIDER", "digicert")
    monkeypatch.setenv("ACME_DIRECTORY_URL", "")

    try:
        main.apply_runtime_settings_overrides(
            ca_provider="custom",
            acme_directory_url="https://localhost:14000/dir",
        )
        assert config.settings.CA_PROVIDER == "custom"
        assert config.settings.ACME_DIRECTORY_URL == "https://localhost:14000/dir"
    finally:
        config.settings = original_settings


def test_apply_runtime_settings_overrides_named_provider_uses_preset(monkeypatch):
    original_settings = config.settings
    monkeypatch.setenv("CA_PROVIDER", "custom")
    monkeypatch.setenv("ACME_DIRECTORY_URL", "https://example.invalid/dir")

    try:
        main.apply_runtime_settings_overrides(
            ca_provider="letsencrypt",
            acme_directory_url="https://override.invalid/dir",
        )
        assert config.settings.CA_PROVIDER == "letsencrypt"
        assert config.settings.ACME_DIRECTORY_URL == "https://acme-v02.api.letsencrypt.org/directory"
    finally:
        config.settings = original_settings


def test_list_domains_expiring_within_filters_and_sorts(monkeypatch):
    original_settings = config.settings

    try:
        config.settings = SimpleNamespace(
            MANAGED_DOMAINS=["a.example.com", "b.example.com", "c.example.com", "d.example.com"],
            CERT_STORE_PATH="/tmp/certs",
        )

        pem_by_domain = {
            "a.example.com": "pem_a",
            "b.example.com": "pem_b",
            "c.example.com": "pem_c",
            "d.example.com": None,
        }
        days_by_pem = {
            "pem_a": 40,
            "pem_b": 30,
            "pem_c": -2,
        }

        monkeypatch.setattr(
            "storage.filesystem.read_cert_pem",
            lambda cert_store_path, domain: pem_by_domain[domain],
        )
        monkeypatch.setattr("storage.filesystem.parse_expiry", lambda pem: pem)
        monkeypatch.setattr(
            "storage.filesystem.days_until_expiry",
            lambda expiry: days_by_pem[expiry],
        )

        result = main.list_domains_expiring_within(days=30)

        assert result == ["c.example.com", "b.example.com"]
    finally:
        config.settings = original_settings


def test_list_domains_expiring_within_exits_when_no_domains_configured():
    original_settings = config.settings

    try:
        config.settings = SimpleNamespace(MANAGED_DOMAINS=[], CERT_STORE_PATH="/tmp/certs")
        with pytest.raises(SystemExit) as exc:
            main.list_domains_expiring_within(days=30)
        assert exc.value.code == 1
    finally:
        config.settings = original_settings


def test_get_domain_statuses_classifies_domains(monkeypatch):
    original_settings = config.settings

    try:
        config.settings = SimpleNamespace(CERT_STORE_PATH="/tmp/certs")

        class FakeExpiry:
            def __init__(self, value: str):
                self.value = value

            def isoformat(self) -> str:
                return self.value

        pem_by_domain = {
            "missing.example.com": None,
            "expired.example.com": "pem_expired",
            "soon.example.com": "pem_soon",
            "ok.example.com": "pem_ok",
        }
        expiry_by_pem = {
            "pem_expired": FakeExpiry("2025-01-01T00:00:00+00:00"),
            "pem_soon": FakeExpiry("2026-03-01T00:00:00+00:00"),
            "pem_ok": FakeExpiry("2026-07-01T00:00:00+00:00"),
        }
        days_by_expiry = {
            expiry_by_pem["pem_expired"]: -1,
            expiry_by_pem["pem_soon"]: 7,
            expiry_by_pem["pem_ok"]: 120,
        }

        monkeypatch.setattr(
            "storage.filesystem.read_cert_pem",
            lambda cert_store_path, domain: pem_by_domain[domain],
        )
        monkeypatch.setattr("storage.filesystem.parse_expiry", lambda pem: expiry_by_pem[pem])
        monkeypatch.setattr(
            "storage.filesystem.days_until_expiry",
            lambda expiry: days_by_expiry[expiry],
        )
        monkeypatch.setattr("storage.filesystem.parse_issuer", lambda pem: f"issuer-for-{pem}")

        statuses = main.get_domain_statuses(
            ["missing.example.com", "expired.example.com", "soon.example.com", "ok.example.com"]
        )

        assert statuses[0]["status"] == "missing"
        assert statuses[0]["cert_found"] is False
        assert statuses[0]["issuer"] is None

        assert statuses[1]["issuer"] == "issuer-for-pem_expired"

        assert statuses[1]["status"] == "expired"
        assert statuses[1]["expired"] is True
        assert statuses[1]["days_until_expiry"] == -1

        assert statuses[2]["status"] == "expiring_soon"
        assert statuses[2]["expired"] is False
        assert statuses[2]["days_until_expiry"] == 7

        assert statuses[3]["status"] == "valid"
        assert statuses[3]["expired"] is False
        assert statuses[3]["days_until_expiry"] == 120
    finally:
        config.settings = original_settings


def test_get_domain_statuses_exits_when_empty_domains():
    with pytest.raises(SystemExit) as exc:
        main.get_domain_statuses([])
    assert exc.value.code == 1


def test_cli_domain_status_prints_results(monkeypatch, capsys):
    received_domains = []

    def _fake_statuses(domains):
        received_domains.extend(domains)
        return [
            {"domain": "a.example.com", "status": "valid"},
            {"domain": "b.example.com", "status": "expired"},
        ]

    monkeypatch.setattr(main, "get_domain_statuses", _fake_statuses)
    monkeypatch.setattr(main, "apply_runtime_settings_overrides", lambda **_: None)
    monkeypatch.setattr(sys, "argv", ["main.py", "--domain-status", "a.example.com", "b.example.com"])

    main.main()

    assert received_domains == ["a.example.com", "b.example.com"]
    stdout = capsys.readouterr().out.strip().splitlines()
    assert stdout == [
        "{'domain': 'a.example.com', 'status': 'valid'}",
        "{'domain': 'b.example.com', 'status': 'expired'}",
    ]


def test_cli_expiring_in_30_days_uses_domains_override(monkeypatch, capsys):
    calls = []

    def _fake_list(days, domains=None):
        calls.append((days, domains))
        return ["b.example.com", "a.example.com"]

    monkeypatch.setattr(main, "list_domains_expiring_within", _fake_list)
    monkeypatch.setattr(main, "apply_runtime_settings_overrides", lambda **_: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--expiring-in-30-days",
            "--domains",
            "a.example.com",
            "b.example.com",
        ],
    )

    main.main()

    assert calls == [(30, ["a.example.com", "b.example.com"])]
    assert capsys.readouterr().out.strip().splitlines() == [
        "b.example.com",
        "a.example.com",
    ]


def test_cli_applies_runtime_overrides_before_action(monkeypatch):
    order = []

    def _fake_apply_runtime_settings_overrides(**kwargs):
        order.append(("override", kwargs))

    def _fake_run_once(domains=None, use_checkpoint=False):
        order.append(("run_once", domains, use_checkpoint))
        return {}

    monkeypatch.setattr(main, "apply_runtime_settings_overrides", _fake_apply_runtime_settings_overrides)
    monkeypatch.setattr(main, "run_once", _fake_run_once)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--once",
            "--domains",
            "a.example.com",
            "b.example.com",
            "--ca-provider",
            "custom",
            "--acme-directory-url",
            "https://localhost:14000/dir",
        ],
    )

    main.main()

    assert order[0][0] == "override"
    assert order[0][1] == {
        "ca_provider": "custom",
        "acme_directory_url": "https://localhost:14000/dir",
    }
    assert order[1] == ("run_once", ["a.example.com", "b.example.com"], False)


def test_cli_rejects_unknown_ca_provider(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--once", "--ca-provider", "nope"])

    with pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 2
    stderr = capsys.readouterr().err
    assert "invalid choice" in stderr


def test_cli_domain_status_requires_domains(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--domain-status"])

    with pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 2
    stderr = capsys.readouterr().err
    assert "expected at least one argument" in stderr


def test_cli_help_contains_all_supported_flags(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--help"])

    with pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 0
    help_text = capsys.readouterr().out

    expected_flags = [
        "--once",
        "--schedule",
        "--revoke-cert",
        "--reason",
        "--domains",
        "--checkpoint",
        "--expiring-in-30-days",
        "--domain-status",
        "--ca-provider",
        "--acme-directory-url",
        "--generate-test-cert",
        "--days",
    ]

    for flag in expected_flags:
        assert flag in help_text


def test_generate_test_cert_with_custom_days(monkeypatch, tmp_path):
    """Test generate_test_cert with explicit validity period."""
    original_settings = config.settings
    
    try:
        config.settings = SimpleNamespace(
            CERT_STORE_PATH=str(tmp_path),
        )
        main.generate_test_cert(domain="test.example.com", days=90)
        
        # Verify files were created
        cert_file = tmp_path / "test.example.com" / "cert.pem"
        key_file = tmp_path / "test.example.com" / "privkey.pem"
        metadata_file = tmp_path / "test.example.com" / "metadata.json"
        
        assert cert_file.exists()
        assert key_file.exists()
        assert metadata_file.exists()
    finally:
        config.settings = original_settings


def test_generate_test_cert_with_default_days(monkeypatch, tmp_path):
    """Test generate_test_cert with default 30 days."""
    original_settings = config.settings
    
    try:
        config.settings = SimpleNamespace(
            CERT_STORE_PATH=str(tmp_path),
        )
        main.generate_test_cert(domain="another.example.com")
        
        # Verify files were created
        cert_file = tmp_path / "another.example.com" / "cert.pem"
        key_file = tmp_path / "another.example.com" / "privkey.pem"
        
        assert cert_file.exists()
        assert key_file.exists()
    finally:
        config.settings = original_settings


def test_generate_test_cert_rejects_empty_domain(monkeypatch, tmp_path):
    """Test generate_test_cert rejects empty domain."""
    original_settings = config.settings
    
    try:
        config.settings = SimpleNamespace(
            CERT_STORE_PATH=str(tmp_path),
        )
        with pytest.raises(SystemExit) as exc:
            main.generate_test_cert(domain="", days=30)
        assert exc.value.code == 1
    finally:
        config.settings = original_settings


def test_generate_test_cert_rejects_invalid_days(monkeypatch, tmp_path):
    """Test generate_test_cert rejects invalid days range."""
    original_settings = config.settings
    
    try:
        config.settings = SimpleNamespace(
            CERT_STORE_PATH=str(tmp_path),
        )
        # Too few days
        with pytest.raises(SystemExit) as exc:
            main.generate_test_cert(domain="test.com", days=0)
        assert exc.value.code == 1
        
        # Too many days
        with pytest.raises(SystemExit) as exc:
            main.generate_test_cert(domain="test.com", days=3651)
        assert exc.value.code == 1
    finally:
        config.settings = original_settings


def test_cli_tui_dispatches_to_tui_command(monkeypatch):
    called = []
    monkeypatch.setattr(main, "apply_runtime_settings_overrides", lambda **_: None)
    monkeypatch.setattr(sys, "argv", ["main.py", "--tui"])

    class _FakeApp:
        def run(self):
            called.append(True)

    # Patch the import site inside cmd_tui, not a module-level main.AcmeTuiApp
    # (there is none — the import is intentionally lazy so main.py doesn't
    # require the optional `tui` extra to be installed for non-TUI usage).
    import types

    fake_tui_app_module = types.ModuleType("tui.app")
    fake_tui_app_module.AcmeTuiApp = _FakeApp
    monkeypatch.setitem(sys.modules, "tui.app", fake_tui_app_module)

    main.main()

    assert called == [True]


def test_cli_tui_missing_extra_exits_cleanly(monkeypatch):
    monkeypatch.setattr(main, "apply_runtime_settings_overrides", lambda **_: None)
    monkeypatch.setattr(sys, "argv", ["main.py", "--tui"])
    monkeypatch.delitem(sys.modules, "tui.app", raising=False)
    monkeypatch.setitem(sys.modules, "tui.app", None)  # forces ImportError on `from tui.app import ...`

    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 1


