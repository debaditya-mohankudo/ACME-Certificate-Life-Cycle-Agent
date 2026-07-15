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

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Footer, Header, Input, Select, Static
from textual.worker import get_current_worker

import config
from diagnostics import diagnose
from tui.subprocess_stream import stream_subprocess
from tui.tui_widgets import EventFeed, bordered, breadcrumb_bar, log_ui

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

    # f2, not a plain letter: this screen has focusable Input/Select widgets
    # that consume printable key presses while typing, so a mnemonic like
    # "r" would type into whichever field has focus instead of triggering
    # Run — F-keys don't collide with text entry. Matches DomainStatusScreen's
    # existing f5-for-refresh convention. No Button widget for this action —
    # docker_log_analyzer/tui.py's TUI is keyboard-only by design; adopted
    # here per explicit user feedback replacing a full-width clickable button.
    BINDINGS = [
        ("escape", "pop_screen", "Back"),
        ("f2", "run", "Run"),
        ("f3", "save_log", "Save Log"),
    ]

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
        self._feed_lines: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield breadcrumb_bar(["Home", "Run"], 1)
        yield Vertical(
            bordered(
                Input(
                    value=",".join(getattr(config.settings, "MANAGED_DOMAINS", []) or []),
                    placeholder="domain.com,other.com",
                    id="domain-input",
                ),
                "Domain(s) — comma separated",
            ).add_class("panel"),
            bordered(
                Select(CA_PROVIDER_CHOICES, id="ca-provider-select", value="letsencrypt_staging"),
                "Certificate Authority",
            ).add_class("panel"),
            bordered(EventFeed(id="event-feed"), "Live Run — press F2 to run").add_class("panel"),
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
        self.query_one("#domain-input", Input).disabled = run_active
        self.query_one("#ca-provider-select", Select).disabled = run_active
        feed = self.query_one("#event-feed", EventFeed)
        feed.border_title = "Live Run — running…" if run_active else "Live Run — press F2 to run"

    def action_run(self) -> None:
        log_ui("key_pressed", screen="RunScreen", key="f2")

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
        self._feed_lines = []
        self._run_in_progress = True
        self.run_active = True
        self.run_worker(lambda: self._do_run(domains, ca_provider), thread=True)

    def action_save_log(self) -> None:
        log_ui("key_pressed", screen="RunScreen", key="f3")
        if not self._feed_lines:
            self.notify("Nothing to save yet — run first.", severity="warning")
            return
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = Path(f"run-log-{timestamp}.txt")
        path.write_text("\n".join(self._feed_lines) + "\n")
        log_ui("run_log_saved", screen="RunScreen", path=str(path))
        self.notify(f"Saved to {path}", severity="information")

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
        challenge_mode = getattr(config.settings, "HTTP_CHALLENGE_MODE", "standalone")
        exit_code = 1
        last_error: str | None = None
        try:
            exit_code, last_error = stream_subprocess(
                argv,
                on_line=lambda raw, rec: self.app.call_from_thread(self._append_feed_line, raw, rec),
                is_cancelled=lambda: worker.is_cancelled,
            )
        finally:
            self._run_in_progress = False
            self.app.call_from_thread(self._finish_run, exit_code, last_error, domains, challenge_mode)

    def _append_feed_line(self, raw_line: str, record: dict[str, Any] | None) -> None:
        self._feed_lines.append(raw_line)
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
            # No ERROR-level JSONL line — most commonly an *uncaught* Python
            # exception (e.g. an AcmeError propagating out of graph.invoke()
            # unhandled) printed as a raw traceback rather than through the
            # structured logger, so stream_subprocess never saw a
            # level=="ERROR" record to capture. The traceback's own summary
            # line (the last non-empty line) is still useful — show it
            # directly rather than a dead-end "nothing captured" message.
            tail = next((line for line in reversed(self._feed_lines) if line.strip()), None)
            if tail:
                panel.update(f"Run failed with an unhandled error (not a structured ACME error):\n\n{tail}")
            else:
                panel.update("Run failed but no output was captured — check the feed above.")
        panel.display = True

    def action_pop_screen(self) -> None:
        log_ui("key_pressed", screen="RunScreen", key="escape")
        self.app.pop_screen()
