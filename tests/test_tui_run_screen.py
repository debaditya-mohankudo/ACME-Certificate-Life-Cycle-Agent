"""RunScreen tests — composition, run_active reactive drives button/input
disabling, and the subprocess-launch/JSONL-parse/diagnosis-panel path.

Requires the `tui` extra (uv sync --extra tui); skipped entirely if textual
isn't installed, matching how tests for other optional-extra features in
this repo behave.
"""
from __future__ import annotations

import sys

import pytest

textual = pytest.importorskip("textual")

from textual.app import App  # noqa: E402

from tui.screens.run import RunScreen  # noqa: E402
import tui.screens.run as run_module  # noqa: E402

pytestmark = pytest.mark.asyncio


class _RunScreenApp(App):
    def on_mount(self) -> None:
        self.push_screen(RunScreen())


async def test_run_screen_composes_and_run_button_starts_enabled():
    app = _RunScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.screen.__class__.__name__ == "RunScreen"
        assert app.screen.query_one("#run-button").disabled is False


async def test_run_active_reactive_disables_inputs():
    """Regression test: a reactive named `is_running` collides with
    Screen's own built-in is_running property and silently breaks mounting
    (SignalError at test-harness teardown) — this must stay named
    `run_active`. See tui/screens/run.py's comment on the reactive
    declaration for the full explanation."""
    app = _RunScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        button = screen.query_one("#run-button")

        screen.run_active = True
        await pilot.pause()
        assert button.disabled is True

        screen.run_active = False
        await pilot.pause()
        assert button.disabled is False


async def test_finish_run_failure_populates_diagnosis_panel():
    app = _RunScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen

        screen._finish_run(
            1,
            "urn:ietf:params:acme:error:unauthorized",
            ["example.com"],
            "standalone",
        )
        panel = screen.query_one("#diagnosis-panel")
        assert panel.display is True


async def test_run_button_launches_subprocess_and_streams_jsonl(monkeypatch, tmp_path):
    fake_script = tmp_path / "fake_main.py"
    fake_script.write_text(
        "import json, sys\n"
        "print(json.dumps({'level': 'INFO', 'message': 'starting'}))\n"
        "print(json.dumps({'level': 'ERROR', 'message': "
        "'urn:ietf:params:acme:error:unauthorized: boom'}))\n"
        "sys.exit(1)\n"
    )

    import subprocess

    orig_popen = subprocess.Popen

    def fake_popen(argv, **kwargs):
        return orig_popen([sys.executable, str(fake_script)], **kwargs)

    monkeypatch.setattr(run_module.subprocess, "Popen", fake_popen)

    app = _RunScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        screen.query_one("#domain-input").value = "example.com"
        screen.query_one("#run-button").press()

        # worker runs in a real thread; give it a moment to finish against
        # the fast fake script, then let Textual process the queued
        # call_from_thread callbacks.
        import asyncio

        await asyncio.sleep(0.5)
        await pilot.pause()

        assert screen._run_in_progress is False
        assert screen.run_active is False
        assert screen.query_one("#diagnosis-panel").display is True
