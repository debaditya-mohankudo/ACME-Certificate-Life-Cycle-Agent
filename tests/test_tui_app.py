"""AcmeTuiApp tests — initial screen, breadcrumb on push/pop navigation."""
from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from tui.app import AcmeTuiApp  # noqa: E402


@pytest.mark.asyncio
async def test_app_starts_on_home_screen_with_home_breadcrumb():
    app = AcmeTuiApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.screen.__class__.__name__ == "HomeScreen"
        assert app.sub_title == "Home"


@pytest.mark.asyncio
async def test_breadcrumb_updates_on_push_and_pop():
    app = AcmeTuiApp()
    async with app.run_test() as pilot:
        await pilot.pause()

        app.screen.action_run_screen()
        await pilot.pause()
        assert app.screen.__class__.__name__ == "RunScreen"
        assert app.sub_title == "Home › Run"

        app.pop_screen()
        await pilot.pause()
        assert app.screen.__class__.__name__ == "HomeScreen"
        assert app.sub_title == "Home"  # regression: this stayed stale before pop_screen was overridden

        app.screen.action_domain_status_screen()
        await pilot.pause()
        assert app.screen.__class__.__name__ == "DomainStatusScreen"
        assert app.sub_title == "Home › Domain Status"
