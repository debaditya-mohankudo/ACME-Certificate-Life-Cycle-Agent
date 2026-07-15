"""AcmeTuiApp — entry point wiring HomeScreen/DomainStatusScreen/RunScreen/
RevokeScreen into one Textual App, with a screen-stack-driven breadcrumb
(mirroring crew-bug-hunter's update_breadcrumb) and the shared house palette.

Launch via `python main.py --tui` (requires: uv sync --extra tui).
"""
from __future__ import annotations

from textual.app import App

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
}


class AcmeTuiApp(App):
    """ACME Certificate Lifecycle Agent — interactive TUI."""

    TITLE = "ACME Certificate Lifecycle Agent"

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
    """

    def on_mount(self) -> None:
        log_ui("app_mounted")
        self.push_screen(HomeScreen())

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
        return result
