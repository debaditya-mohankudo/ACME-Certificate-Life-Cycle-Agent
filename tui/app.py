"""AcmeTuiApp — entry point wiring HomeScreen/DomainStatusScreen/RunScreen/
RevokeScreen into one Textual App, with a screen-stack-driven breadcrumb
(mirroring crew-bug-hunter's update_breadcrumb) and the shared house palette.

Launch via `python main.py --tui` (requires: uv sync --extra tui).
"""
from __future__ import annotations

from textual.app import App
from textual.worker import Worker, WorkerState

from logger import logger as agent_logger
from tui.screens.home import HomeScreen
from tui.tui_widgets import log_ui

# Shared palette — keep in sync with the CSS rules below.
ACCENT = "#22d3ee"
GREEN = "#4ade80"
RED = "#f87171"
AMBER = "#fbbf24"
MUTED = "#5a6472"

BREADCRUMB_LABELS = {
    "HomeScreen": "Home",
    "DomainStatusScreen": "Domain Status",
    "RunScreen": "Run",
    "RevokeScreen": "Revoke",
    "ConfigScreen": "Edit Config",
}


class AcmeTuiApp(App):
    """ACME Certificate Lifecycle Agent — interactive TUI."""

    TITLE = "ACME Certificate Lifecycle Agent"

    # App-level (not per-screen) binding, so Quit shows in the Footer and
    # works from every screen — this is navigation chrome, not an action
    # specific to whatever screen happens to be on top. Matches
    # crew-bug-hunter's identical convention (tui.py:399-403).
    BINDINGS = [("q", "quit", "Quit")]

    CSS = f"""
    Screen {{
        background: #0d1119;
    }}
    .panel {{
        border: round {MUTED};
        border-title-color: {ACCENT};
    }}
    Button {{
        margin: 1 0;
    }}
    Button.-primary {{
        background: {ACCENT};
    }}
    #intro {{ padding: 1; }}
    #config-details {{ padding: 1; }}
    #home-body {{ padding: 1 2; }}
    #run-body {{ padding: 1 2; }}
    #revoke-body {{ padding: 1 2; }}
    #domain-status-body {{ padding: 1 2; }}
    #config-body {{ padding: 1 2; }}
    """

    def on_mount(self) -> None:
        log_ui("app_mounted")
        self.push_screen(HomeScreen())

    def action_quit(self) -> None:
        log_ui("key_pressed", screen=self.screen.__class__.__name__, key="q")
        self.exit()

    # Two exception paths exist in a Textual app and neither is logged by
    # default: (1) an exception raised inside a worker (run_worker(...,
    # thread=True) — RunScreen/RevokeScreen's subprocess launches, e.g. if
    # `python` itself can't be found) surfaces only as a Worker.StateChanged
    # message, not a normal Python exception the caller can catch; (2) an
    # exception raised synchronously in an event handler (on_button_pressed,
    # an action_*, compose, ...) goes through App._handle_exception, which by
    # default just renders Textual's own crash screen — never reaching this
    # repo's structured JSONL logger. Both are hooked here so every
    # exception, not just the ones individual screens explicitly catch,
    # lands in the same run_id-correlated log stream as node-level errors.
    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.state != WorkerState.ERROR or event.worker.error is None:
            return
        exc = event.worker.error
        agent_logger.error(
            "TUI worker failed: %s",
            exc,
            exc_info=(type(exc), exc, exc.__traceback__),
        )
        log_ui(
            "worker_error",
            screen=self.screen.__class__.__name__,
            worker=event.worker.name,
            error=str(exc),
        )
        self.notify(f"Background task failed: {exc}", severity="error")

    def _handle_exception(self, error: Exception) -> None:
        agent_logger.error(
            "TUI unhandled exception: %s",
            error,
            exc_info=(type(error), error, error.__traceback__),
        )
        log_ui(
            "unhandled_exception",
            screen=self.screen.__class__.__name__ if self.screen_stack else "none",
            error=str(error),
        )
        super()._handle_exception(error)

    def _update_breadcrumb(self) -> None:
        # screen_stack's bottom entry is Textual's own implicit default
        # screen, not one of ours — skip anything not in BREADCRUMB_LABELS
        # rather than showing it, matching crew-bug-hunter's convention.
        self.sub_title = " › ".join(
            BREADCRUMB_LABELS[s.__class__.__name__]
            for s in self.screen_stack
            if s.__class__.__name__ in BREADCRUMB_LABELS
        )

    # Both overridden (rather than relying on App.on_screen_resume, which in
    # practice doesn't reliably fire on every push/pop in this Textual
    # version — verified empirically: breadcrumb stayed stale after
    # pop_screen until this was added) so the breadcrumb updates on both
    # directions of navigation.
    def push_screen(self, screen, *args, **kwargs):
        result = super().push_screen(screen, *args, **kwargs)
        self.call_after_refresh(self._update_breadcrumb)
        return result

    def pop_screen(self, *args, **kwargs):
        result = super().pop_screen(*args, **kwargs)
        self.call_after_refresh(self._update_breadcrumb)
        # If we've landed back on HomeScreen (e.g. after ConfigScreen saved
        # changes), refresh its config summary too — same on_screen_resume
        # unreliability applies here, not just to the breadcrumb.
        if isinstance(self.screen, HomeScreen):
            self.call_after_refresh(self.screen.refresh_summary)
        return result
