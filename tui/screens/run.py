"""RunScreen — pick domain(s) + CA provider, run `python main.py --once ...`
as a subprocess, and stream its JSONL stdout into a live EventFeed.

Execution is a subprocess over the existing CLI, not an in-process
build_graph() call — this keeps the TUI outside the LangGraph state machine
entirely (per this repo's CLAUDE.md: "never bypass the graph"), and means
there's no shared Python object (graph, event loop) between the TUI process
and the run for a lock to protect. The only thing this screen needs to
guard against is launching a second subprocess while one is alive, which is
a plain instance flag, not a threading/asyncio design question.

See docstring in agent-facing design notes (task d362e679) for why this
supersedes an earlier in-process design.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Select, Static
from textual.worker import get_current_worker

from config import settings
from diagnostics import diagnose
from tui.tui_widgets import EventFeed, bordered, log_ui

CA_PROVIDER_CHOICES = [
    ("Let's Encrypt (recommended)", "letsencrypt"),
    ("Let's Encrypt — staging / test run", "letsencrypt_staging"),
    ("DigiCert", "digicert"),
    ("ZeroSSL", "zerossl"),
    ("Sectigo", "sectigo"),
    ("Custom ACME server", "custom"),
]


class RunScreen(Screen):
    """Domain/CA picker -> subprocess run -> live EventFeed -> failure diagnosis."""

    BINDINGS = [("escape", "pop_screen", "Back")]

    # Named run_active, not is_running: Screen/Widget already define a
    # built-in `is_running` property the framework uses internally to track
    # mount state (see app.py's _get_screen / signal.py's subscribe). A
    # reactive attribute of that name silently shadows it and breaks screen
    # mounting in confusing, delayed ways (SignalError at test-harness exit,
    # not at the point of collision) — verified by reproducing the failure
    # in a minimal reactive-Screen repro and bisecting to the name collision.
    run_active: reactive[bool] = reactive(False)

    def __init__(self) -> None:
        super().__init__()
        self._run_in_progress = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            bordered(
                Input(
                    value=",".join(getattr(settings, "MANAGED_DOMAINS", []) or []),
                    placeholder="domain.com,other.com",
                    id="domain-input",
                ),
                "Domain(s) — comma separated",
            ).add_class("panel"),
            bordered(
                Select(CA_PROVIDER_CHOICES, id="ca-provider-select", value="letsencrypt_staging"),
                "Certificate Authority",
            ).add_class("panel"),
            Button("Run", id="run-button", variant="primary"),
            bordered(EventFeed(id="event-feed"), "Live Run").add_class("panel"),
            bordered(Static("", id="diagnosis-panel"), "Diagnosis").add_class("panel"),
            id="run-body",
        )
        yield Footer()

    def on_mount(self) -> None:
        log_ui("screen_shown", screen="RunScreen")
        self.query_one("#diagnosis-panel", Static).display = False

    def on_screen_resume(self) -> None:
        log_ui("screen_resumed", screen="RunScreen")

    def watch_run_active(self, run_active: bool) -> None:
        self.query_one("#run-button", Button).disabled = run_active
        self.query_one("#domain-input", Input).disabled = run_active
        self.query_one("#ca-provider-select", Select).disabled = run_active
        feed = self.query_one("#event-feed", EventFeed)
        feed.border_title = "Live Run — running…" if run_active else "Live Run"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "run-button":
            return
        log_ui("button_pressed", screen="RunScreen", button=event.button.id)

        if self._run_in_progress:
            self.notify("A run is already in progress.", severity="warning")
            return

        domains_raw = self.query_one("#domain-input", Input).value.strip()
        domains = [d.strip() for d in domains_raw.split(",") if d.strip()]
        if not domains:
            self.notify("Enter at least one domain.", severity="warning")
            return
        ca_provider = self.query_one("#ca-provider-select", Select).value

        self.query_one("#diagnosis-panel", Static).display = False
        self.query_one("#event-feed", EventFeed).clear()
        self._run_in_progress = True
        self.run_active = True
        self.run_worker(lambda: self._do_run(domains, ca_provider), thread=True)

    def _do_run(self, domains: list[str], ca_provider: str) -> None:
        """Runs in a worker thread (see module docstring — this is a real OS
        thread via Textual's `thread=True`, not a coroutine). Every widget
        touch below goes through `call_from_thread`, matching the pattern
        already used in bee-bug-hunter's own TUI (tui.py:547-575) for the
        same reason: Textual widgets aren't safe to touch off the main
        thread directly.
        """
        worker = get_current_worker()
        argv = [sys.executable, "main.py", "--once", "--domains", *domains, "--ca-provider", ca_provider]
        last_error: str | None = None
        challenge_mode = getattr(settings, "HTTP_CHALLENGE_MODE", "standalone")
        exit_code = 1
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            assert proc.stdout is not None
            for line in proc.stdout:
                if worker.is_cancelled:
                    proc.terminate()
                    break
                record = self._parse_jsonl_line(line)
                self.app.call_from_thread(self._append_feed_line, line.rstrip("\n"), record)
                if record and record.get("level") == "ERROR":
                    last_error = record.get("message", line)
            exit_code = proc.wait()
        finally:
            self._run_in_progress = False
            self.app.call_from_thread(self._finish_run, exit_code, last_error, domains, challenge_mode)

    @staticmethod
    def _parse_jsonl_line(line: str) -> dict[str, Any] | None:
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def _append_feed_line(self, raw_line: str, record: dict[str, Any] | None) -> None:
        feed = self.query_one("#event-feed", EventFeed)
        if record is None:
            feed.write_event("context_log", EventFeed.escape(raw_line))
            return
        level = record.get("level", "INFO")
        message = record.get("message", raw_line)
        kind = {"ERROR": "tool_crashed", "CRITICAL": "tool_crashed", "WARNING": "tool_call"}.get(level, "context_log")
        feed.write_event(kind, EventFeed.escape(f"[{level}] {message}"))

    def _finish_run(self, exit_code: int, last_error: str | None, domains: list[str], challenge_mode: str) -> None:
        self.run_active = False
        feed = self.query_one("#event-feed", EventFeed)
        if exit_code == 0:
            feed.write_event("tool_done", "Run finished successfully.")
            log_ui("run_finished", screen="RunScreen", exit_code=exit_code, domains=domains)
            return

        feed.write_event("tool_crashed", f"Run exited with code {exit_code}.")
        log_ui("run_finished", screen="RunScreen", exit_code=exit_code, domains=domains, error=last_error)

        panel = self.query_one("#diagnosis-panel", Static)
        if last_error:
            result = diagnose(
                error_text=last_error,
                domain=domains[0],
                challenge_mode=challenge_mode,
            )
            panel.update(result.summary)
        else:
            panel.update("Run failed but no ERROR-level log line was captured — check the feed above.")
        panel.display = True

    def action_pop_screen(self) -> None:
        log_ui("key_pressed", screen="RunScreen", key="escape")
        self.app.pop_screen()
