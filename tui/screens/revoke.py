"""RevokeScreen — domain picker + RFC 5280 reason code, runs
`python main.py --revoke-cert ...` as a subprocess.

Mirrors RunScreen's picker/worker/EventFeed pattern (both now share
tui/subprocess_stream.py's launch/parse loop rather than duplicating it —
see that module's docstring). Reason-code choices are main.py's own
{0,1,4,5} set (main.py:393-398's --reason help text), not re-derived.

revocation-graph-best-effort-looping semantics (no retry/error_handler in
that subgraph; per-domain failures land in failed_revocations, loop
continues unconditionally) are unchanged — this screen just launches the
existing CLI command and renders its outcome, it doesn't reimplement any of
that behavior.
"""
from __future__ import annotations

import sys

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Select
from textual.worker import get_current_worker

from tui.subprocess_stream import stream_subprocess
from tui.tui_widgets import EventFeed, bordered, log_ui

REASON_CODE_CHOICES = [
    ("Unspecified", "0"),
    ("Key compromise", "1"),
    ("Superseded", "4"),
    ("Cessation of operation", "5"),
]


class RevokeScreen(Screen):
    """Domain/reason-code picker -> subprocess revoke -> live EventFeed."""

    BINDINGS = [("escape", "pop_screen", "Back")]

    run_active: reactive[bool] = reactive(False)  # see run.py's comment: never name this is_running

    def __init__(self) -> None:
        super().__init__()
        self._run_in_progress = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            bordered(
                Input(placeholder="domain.com,other.com", id="domain-input"),
                "Domain(s) to revoke — comma separated",
            ).add_class("panel"),
            bordered(
                Select(REASON_CODE_CHOICES, id="reason-select", value="0"),
                "RFC 5280 Reason Code",
            ).add_class("panel"),
            Button("Revoke", id="revoke-button", variant="error"),
            bordered(EventFeed(id="event-feed"), "Live Revocation").add_class("panel"),
            id="revoke-body",
        )
        yield Footer()

    def on_mount(self) -> None:
        log_ui("screen_shown", screen="RevokeScreen")

    def on_screen_resume(self) -> None:
        log_ui("screen_resumed", screen="RevokeScreen")

    def watch_run_active(self, run_active: bool) -> None:
        self.query_one("#revoke-button", Button).disabled = run_active
        self.query_one("#domain-input", Input).disabled = run_active
        self.query_one("#reason-select", Select).disabled = run_active
        feed = self.query_one("#event-feed", EventFeed)
        feed.border_title = "Live Revocation — running…" if run_active else "Live Revocation"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "revoke-button":
            return
        log_ui("button_pressed", screen="RevokeScreen", button=event.button.id)

        if self._run_in_progress:
            self.notify("A revocation is already in progress.", severity="warning")
            return

        domains_raw = self.query_one("#domain-input", Input).value.strip()
        domains = [d.strip() for d in domains_raw.split(",") if d.strip()]
        if not domains:
            self.notify("Enter at least one domain.", severity="warning")
            return
        reason = self.query_one("#reason-select", Select).value

        self.query_one("#event-feed", EventFeed).clear()
        self._run_in_progress = True
        self.run_active = True
        self.run_worker(lambda: self._do_revoke(domains, reason), thread=True)

    def _do_revoke(self, domains: list[str], reason: str) -> None:
        worker = get_current_worker()
        argv = [sys.executable, "main.py", "--revoke-cert", *domains, "--reason", str(reason)]
        exit_code = 1
        try:
            exit_code, _last_error = stream_subprocess(
                argv,
                on_line=lambda raw, rec: self.app.call_from_thread(self._append_feed_line, raw, rec),
                is_cancelled=lambda: worker.is_cancelled,
            )
        finally:
            self._run_in_progress = False
            self.app.call_from_thread(self._finish_run, exit_code, domains)

    def _append_feed_line(self, raw_line: str, record: dict | None) -> None:
        feed = self.query_one("#event-feed", EventFeed)
        if record is None:
            feed.write_event("context_log", EventFeed.escape(raw_line))
            return
        level = record.get("level", "INFO")
        message = record.get("message", raw_line)
        kind = {"ERROR": "tool_crashed", "CRITICAL": "tool_crashed", "WARNING": "tool_call"}.get(level, "context_log")
        feed.write_event(kind, EventFeed.escape(f"[{level}] {message}"))

    def _finish_run(self, exit_code: int, domains: list[str]) -> None:
        self.run_active = False
        feed = self.query_one("#event-feed", EventFeed)
        if exit_code == 0:
            feed.write_event("tool_done", "Revocation finished.")
        else:
            feed.write_event("tool_crashed", f"Revocation exited with code {exit_code}.")
        log_ui("run_finished", screen="RevokeScreen", exit_code=exit_code, domains=domains)

    def action_pop_screen(self) -> None:
        log_ui("key_pressed", screen="RevokeScreen", key="escape")
        self.app.pop_screen()
