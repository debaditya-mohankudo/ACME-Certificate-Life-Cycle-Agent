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

pytestmark = pytest.mark.asyncio


class _RunScreenApp(App):
    def on_mount(self) -> None:
        self.push_screen(RunScreen())


async def test_run_screen_composes_with_inputs_enabled():
    app = _RunScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.screen.__class__.__name__ == "RunScreen"
        assert app.screen.query_one("#domain-input").disabled is False
        assert app.screen.query_one("#ca-provider-select").disabled is False


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
        domain_input = screen.query_one("#domain-input")

        screen.run_active = True
        await pilot.pause()
        assert domain_input.disabled is True

        screen.run_active = False
        await pilot.pause()
        assert domain_input.disabled is False


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

    import tui.subprocess_stream as stream_module

    orig_popen = subprocess.Popen

    def fake_popen(argv, **kwargs):
        return orig_popen([sys.executable, str(fake_script)], **kwargs)

    monkeypatch.setattr(stream_module.subprocess, "Popen", fake_popen)

    app = _RunScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        screen.query_one("#domain-input").value = "example.com"
        screen.action_run()

        # worker runs in a real thread; give it a moment to finish against
        # the fast fake script, then let Textual process the queued
        # call_from_thread callbacks.
        import asyncio

        await asyncio.sleep(0.5)
        await pilot.pause()

        assert screen._run_in_progress is False
        assert screen.run_active is False
        assert screen.query_one("#diagnosis-panel").display is True


async def test_diagnosis_falls_back_to_raw_traceback_tail_when_no_error_line(monkeypatch, tmp_path):
    """Regression: an *uncaught* exception (e.g. AcmeError propagating out of
    graph.invoke() unhandled) prints a raw Python traceback, not a
    level=="ERROR" JSONL line — found live running against letsencrypt_staging
    with a policy-rejected domain (main.py has no top-level try/except around
    graph.invoke()). Previously the diagnosis panel showed a dead-end
    "nothing captured" message; it must now show the traceback's own summary
    line instead."""
    fake_script = tmp_path / "fake_main.py"
    fake_script.write_text(
        "import json\n"
        "print(json.dumps({'level': 'INFO', 'message': 'starting'}))\n"
        "raise RuntimeError('boom traceback')\n"
    )

    import subprocess

    import tui.subprocess_stream as stream_module

    orig_popen = subprocess.Popen

    def fake_popen(argv, **kwargs):
        return orig_popen([sys.executable, str(fake_script)], **kwargs)

    monkeypatch.setattr(stream_module.subprocess, "Popen", fake_popen)

    app = _RunScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        screen.query_one("#domain-input").value = "example.com"
        screen.action_run()

        import asyncio

        await asyncio.sleep(0.5)
        await pilot.pause()

        panel_text = str(screen.query_one("#diagnosis-panel").render())
        assert "unhandled error" in panel_text
        assert "RuntimeError: boom traceback" in panel_text


async def test_diagnosis_recognizes_known_acme_error_urn_in_raw_traceback(monkeypatch, tmp_path):
    """Regression: user reported the raw-traceback fallback panel was
    unreadable for a server maintainer — a rejectedIdentifier urn buried in an
    uncaught AcmeError's traceback was shown as a bare stack-trace line
    instead of an explanation. The panel must now recognize known RFC 8555
    error urns in the captured output and explain cause + next step."""
    fake_script = tmp_path / "fake_main.py"
    fake_script.write_text(
        "import json\n"
        "print(json.dumps({'level': 'INFO', 'message': 'starting'}))\n"
        "raise RuntimeError("
        "'acme.client.AcmeError: ACME 400: "
        "urn:ietf:params:acme:error:rejectedIdentifier -- Cannot issue for "
        "\"example.com\": forbidden by policy')\n"
    )

    import subprocess

    import tui.subprocess_stream as stream_module

    orig_popen = subprocess.Popen

    def fake_popen(argv, **kwargs):
        return orig_popen([sys.executable, str(fake_script)], **kwargs)

    monkeypatch.setattr(stream_module.subprocess, "Popen", fake_popen)

    app = _RunScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        screen.query_one("#domain-input").value = "example.com"
        screen.action_run()

        import asyncio

        await asyncio.sleep(0.5)
        await pilot.pause()

        panel_text = str(screen.query_one("#diagnosis-panel").render())
        assert "refuses to issue for this domain, by policy" in panel_text
        assert "set MANAGED_DOMAINS to a real domain" in panel_text


async def test_save_log_action_writes_feed_to_file(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    fake_script = tmp_path / "fake_main.py"
    fake_script.write_text(
        "import json\nprint(json.dumps({'level': 'INFO', 'message': 'starting'}))\n"
    )

    import subprocess

    import tui.subprocess_stream as stream_module

    orig_popen = subprocess.Popen

    def fake_popen(argv, **kwargs):
        return orig_popen([sys.executable, str(fake_script)], **kwargs)

    monkeypatch.setattr(stream_module.subprocess, "Popen", fake_popen)

    app = _RunScreenApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen

        # nothing run yet -> warns, writes nothing
        screen.action_save_log()
        await pilot.pause()
        assert not list(tmp_path.glob("run-log-*.txt"))

        screen.query_one("#domain-input").value = "example.com"
        screen.action_run()
        import asyncio

        await asyncio.sleep(0.3)
        await pilot.pause()

        screen.action_save_log()
        await pilot.pause()

        saved = list(tmp_path.glob("run-log-*.txt"))
        assert len(saved) == 1
        assert "starting" in saved[0].read_text()
