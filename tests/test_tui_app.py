"""AcmeTuiApp tests — initial screen, breadcrumb on push/pop navigation,
exception logging safety net."""
from __future__ import annotations

import logging

import pytest

textual = pytest.importorskip("textual")

from tui.app import AcmeTuiApp  # noqa: E402


class _CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


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


@pytest.mark.asyncio
async def test_worker_exception_is_logged_via_agent_logger():
    from logger import logger as agent_logger

    capture = _CaptureHandler()
    agent_logger.logger.addHandler(capture)
    try:
        app = AcmeTuiApp()
        async with app.run_test() as pilot:
            await pilot.pause()

            def _boom():
                raise RuntimeError("worker boom")

            app.run_worker(_boom, thread=True)
            import asyncio

            await asyncio.sleep(0.3)
            await pilot.pause()
    except Exception:
        pass  # run_test() re-raises worker failures for test visibility; logging already happened
    finally:
        agent_logger.logger.removeHandler(capture)

    assert any("TUI worker failed: worker boom" in m for m in capture.messages)
    assert any(m == "worker_error" for m in capture.messages)


@pytest.mark.asyncio
async def test_handle_exception_is_logged_via_agent_logger():
    from logger import logger as agent_logger

    capture = _CaptureHandler()
    agent_logger.logger.addHandler(capture)
    try:
        app = AcmeTuiApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_exception(ValueError("sync boom"))
            await pilot.pause()
    except Exception:
        pass
    finally:
        agent_logger.logger.removeHandler(capture)

    assert any("TUI unhandled exception: sync boom" in m for m in capture.messages)
    assert any(m == "unhandled_exception" for m in capture.messages)
