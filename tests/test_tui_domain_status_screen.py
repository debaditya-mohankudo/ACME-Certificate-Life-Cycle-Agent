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
    monkeypatch.setattr(ds_module, "settings", fake_settings)

    app = _DomainStatusApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one("#domain-table", DataTable)
        assert table.row_count == 2


@pytest.mark.asyncio
async def test_domain_status_screen_empty_managed_domains_no_crash(monkeypatch, tmp_path):
    fake_settings = SimpleNamespace(MANAGED_DOMAINS=[], CERT_STORE_PATH=str(tmp_path))
    monkeypatch.setattr(ds_module, "settings", fake_settings)

    app = _DomainStatusApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one("#domain-table", DataTable)
        assert table.row_count == 0


@pytest.mark.asyncio
async def test_domain_status_screen_refresh_action_no_crash(monkeypatch, tmp_path):
    fake_settings = SimpleNamespace(MANAGED_DOMAINS=["a.example.com"], CERT_STORE_PATH=str(tmp_path))
    monkeypatch.setattr(ds_module, "settings", fake_settings)

    app = _DomainStatusApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.action_refresh()
        await pilot.pause()
        table = app.screen.query_one("#domain-table", DataTable)
        assert table.row_count == 1
