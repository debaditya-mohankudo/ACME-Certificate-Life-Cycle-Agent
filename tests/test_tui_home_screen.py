"""HomeScreen tests — read-only config summary rendering, mode-safe field access."""
from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from textual.app import App  # noqa: E402

import tui.screens.home as home_module  # noqa: E402
from tui.screens.home import HomeScreen, _format_config_summary  # noqa: E402


class _HomeScreenApp(App):
    def on_mount(self) -> None:
        self.push_screen(HomeScreen())


@pytest.mark.asyncio
async def test_home_screen_composes():
    app = _HomeScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.screen.__class__.__name__ == "HomeScreen"
        assert app.screen.query_one("#config-details") is not None


class _FakeAcmeSettings:
    """Hardcoded acme-mode stand-in for config.settings — deterministic
    regardless of whatever mode the ambient .env actually resolves to, and
    intentionally has no SPIFFE_TRUST_DOMAIN/MANAGED_SPIFFE_IDS attributes at
    all, matching AcmeConfig's real shape (see config.py: the inactive
    mode's fields don't exist on the object)."""

    CERT_ISSUANCE_MODE = "acme"
    CA_PROVIDER = "letsencrypt"
    ACME_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
    MANAGED_DOMAINS = ["example.com", "shop.example.com"]
    HTTP_CHALLENGE_MODE = "standalone"
    LLM_DISABLED = True


def test_format_config_summary_acme_mode(monkeypatch):
    monkeypatch.setattr(home_module.config, "settings", _FakeAcmeSettings())
    summary = home_module._format_config_summary()
    assert "Issuance mode: [b]acme[/b]" in summary
    assert "CA provider: letsencrypt" in summary
    assert "Managed domains (2):" in summary
    assert "example.com" in summary
    assert "Deterministic mode (no LLM calls)" in summary
    # SPIFFE-only fields must never be accessed in acme mode
    assert "SPIFFE" not in summary
