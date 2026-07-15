"""DomainStatusScreen tests — table population from get_domain_statuses(),
refresh action, no cert-store writes."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

textual = pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.widgets import DataTable  # noqa: E402

import tui.screens.domain_status as ds_module  # noqa: E402
from tui.screens.domain_status import DomainStatusScreen  # noqa: E402


class _DomainStatusApp(App):
    def on_mount(self) -> None:
        self.push_screen(DomainStatusScreen())


@pytest.mark.asyncio
async def test_domain_status_screen_populates_table_for_missing_certs(monkeypatch, tmp_path):
    fake_settings = SimpleNamespace(
        MANAGED_DOMAINS=["a.example.com", "b.example.com"],
        CERT_STORE_PATH=str(tmp_path),  # empty dir -> both domains "missing"
    )
    monkeypatch.setattr(ds_module.config, "settings", fake_settings)

    app = _DomainStatusApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one("#domain-table", DataTable)
        assert table.row_count == 2


@pytest.mark.asyncio
async def test_domain_status_screen_empty_managed_domains_no_crash(monkeypatch, tmp_path):
    fake_settings = SimpleNamespace(MANAGED_DOMAINS=[], CERT_STORE_PATH=str(tmp_path))
    monkeypatch.setattr(ds_module.config, "settings", fake_settings)

    app = _DomainStatusApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one("#domain-table", DataTable)
        assert table.row_count == 0


@pytest.mark.asyncio
async def test_domain_status_screen_shows_issuer_column(monkeypatch, tmp_path):
    """Regression: user asked to see the issuing CA alongside status/expiry
    — a bare expiry table doesn't tell a maintainer which CA (e.g. Pebble
    vs. real Let's Encrypt) actually issued a given cert."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer.example.com")])
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pebble"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Pebble Intermediate CA"),
        ]
    )
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    cert_dir = tmp_path / "issuer.example.com"
    cert_dir.mkdir()
    (cert_dir / "cert.pem").write_text(pem)

    fake_settings = SimpleNamespace(
        MANAGED_DOMAINS=["issuer.example.com"],
        CERT_STORE_PATH=str(tmp_path),
    )
    monkeypatch.setattr(ds_module.config, "settings", fake_settings)

    app = _DomainStatusApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one("#domain-table", DataTable)
        assert "Issuer" in [str(col.label) for col in table.columns.values()]
        row = table.get_row_at(0)
        assert row[-1] == "Pebble Intermediate CA"


@pytest.mark.asyncio
async def test_domain_status_screen_refresh_action_no_crash(monkeypatch, tmp_path):
    fake_settings = SimpleNamespace(MANAGED_DOMAINS=["a.example.com"], CERT_STORE_PATH=str(tmp_path))
    monkeypatch.setattr(ds_module.config, "settings", fake_settings)

    app = _DomainStatusApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.action_refresh()
        await pilot.pause()
        table = app.screen.query_one("#domain-table", DataTable)
        assert table.row_count == 1
