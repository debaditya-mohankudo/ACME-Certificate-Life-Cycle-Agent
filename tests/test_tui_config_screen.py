"""ConfigScreen tests — validate-then-persist ordering, .env write, hot-reload,
and that other TUI modules observe the reload (the from-config-import-settings
staleness bug found while building this screen)."""
from __future__ import annotations

import os

import pytest

textual = pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.widgets import Input, Select  # noqa: E402

from tui.screens.config_edit import ConfigScreen  # noqa: E402


class _ConfigScreenApp(App):
    def on_mount(self) -> None:
        self.push_screen(ConfigScreen())


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    """Run against a throwaway .env in an isolated cwd — must never touch
    the real repo .env. (See task history: an earlier manual verification
    script accidentally wrote to the real repo .env; every ConfigScreen test
    from here on must be structurally incapable of repeating that.)"""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "CA_PROVIDER=digicert\nMANAGED_DOMAINS=old.example.com\nHTTP_CHALLENGE_MODE=standalone\n"
    )
    import config

    original_settings = config.settings
    original_environ = dict(os.environ)
    yield tmp_path
    config.settings = original_settings
    os.environ.clear()
    os.environ.update(original_environ)


@pytest.mark.asyncio
async def test_config_screen_composes_with_current_values(isolated_env):
    import config

    config.settings = config.make_settings()

    app = _ConfigScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.screen.__class__.__name__ == "ConfigScreen"
        assert app.screen.query_one("#domains-input", Input).value == "old.example.com"
        assert app.screen.query_one("#ca-provider-select", Select).value == "digicert"


@pytest.mark.asyncio
async def test_config_screen_rejects_invalid_combo_without_writing(isolated_env):
    import config

    config.settings = config.make_settings()
    env_before = (isolated_env / ".env").read_text()

    app = _ConfigScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        screen.query_one("#domains-input", Input).value = "new.example.com"
        screen.query_one("#challenge-mode-select", Select).value = "dns"  # no CLOUDFLARE_API_TOKEN set
        screen.action_save()
        await pilot.pause()

        assert app.screen.__class__.__name__ == "ConfigScreen"  # rejected, did not pop
        assert (isolated_env / ".env").read_text() == env_before  # .env untouched
        assert config.settings.HTTP_CHALLENGE_MODE == "standalone"  # settings untouched


@pytest.mark.asyncio
async def test_config_screen_saves_valid_combo_and_home_screen_reflects_it(isolated_env):
    import config

    config.settings = config.make_settings()

    from tui.app import AcmeTuiApp

    app = AcmeTuiApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.action_config_screen()
        await pilot.pause()

        screen = app.screen
        screen.query_one("#ca-provider-select", Select).value = "letsencrypt"
        screen.query_one("#domains-input", Input).value = "new.example.com"
        screen.action_save()
        await pilot.pause()

        # regression: this only works if home.py/run.py/domain_status.py/
        # config_edit.py all do `import config; config.settings.X` rather
        # than `from config import settings` (a stale name-binding bug found
        # while building this screen — the latter freezes a reference to the
        # pre-reload object forever, even across brand-new Screen instances).
        assert app.screen.__class__.__name__ == "HomeScreen"
        summary = str(app.screen.query_one("#config-details").render())
        assert "new.example.com" in summary
        assert "letsencrypt" in summary
        assert config.settings.CA_PROVIDER == "letsencrypt"
        assert (isolated_env / ".env").read_text().count("new.example.com") == 1
