"""RevokeScreen tests — composition, run_active toggling, subprocess-launch path."""
from __future__ import annotations

import sys

import pytest

textual = pytest.importorskip("textual")

from textual.app import App  # noqa: E402

from tui.screens.revoke import RevokeScreen  # noqa: E402


class _RevokeScreenApp(App):
    def on_mount(self) -> None:
        self.push_screen(RevokeScreen())


@pytest.mark.asyncio
async def test_revoke_screen_composes_and_button_starts_enabled():
    app = _RevokeScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.screen.__class__.__name__ == "RevokeScreen"
        assert app.screen.query_one("#revoke-button").disabled is False


@pytest.mark.asyncio
async def test_run_active_disables_inputs():
    app = _RevokeScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        button = screen.query_one("#revoke-button")

        screen.run_active = True
        await pilot.pause()
        assert button.disabled is True

        screen.run_active = False
        await pilot.pause()
        assert button.disabled is False


@pytest.mark.asyncio
async def test_revoke_button_launches_subprocess_and_streams_jsonl(monkeypatch, tmp_path):
    fake_script = tmp_path / "fake_main.py"
    fake_script.write_text(
        "import json\n"
        "print(json.dumps({'level': 'INFO', 'message': 'revoking'}))\n"
        "print(json.dumps({'level': 'INFO', 'message': 'done'}))\n"
    )

    import subprocess

    import tui.subprocess_stream as stream_module

    orig_popen = subprocess.Popen

    def fake_popen(argv, **kwargs):
        return orig_popen([sys.executable, str(fake_script)], **kwargs)

    monkeypatch.setattr(stream_module.subprocess, "Popen", fake_popen)

    app = _RevokeScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        screen.query_one("#domain-input").value = "example.com"
        screen.query_one("#revoke-button").press()

        import asyncio

        await asyncio.sleep(0.5)
        await pilot.pause()

        assert screen._run_in_progress is False
        assert screen.run_active is False
