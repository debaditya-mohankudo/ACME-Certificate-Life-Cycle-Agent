"""DomainStatusScreen — read-only DataTable of managed domains with
expiry/status, refreshable on demand.

Reuses main.py's get_domain_statuses(domains, settings) directly rather than
re-deriving cert-parsing logic or constructing a full AgentState to drive
CertificateScannerNode — get_domain_statuses is already a pure function over
(domains, settings) with no graph/state dependency, which is a simpler reuse
path than the scanner node for a purely read-only screen. No network calls,
no CERT_STORE_PATH writes.
"""
from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header

import config
from tui.tui_widgets import bordered, breadcrumb_bar, log_ui

_STATUS_COLOR = {
    "valid": "green",
    "expiring_soon": "yellow",
    "expired": "red",
    "missing": "dim",
    "parse_error": "red",
}


class DomainStatusScreen(Screen):
    """Live table of MANAGED_DOMAINS' certificate status."""

    BINDINGS = [("escape", "pop_screen", "Back"), ("f5", "refresh", "Refresh")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield breadcrumb_bar(["Home", "Domain Status"], 1)
        yield Vertical(
            bordered(DataTable(id="domain-table"), "Managed Domains — press F5 to refresh").add_class("panel"),
            id="domain-status-body",
        )
        yield Footer()

    def on_mount(self) -> None:
        log_ui("screen_shown", screen="DomainStatusScreen")
        table = self.query_one("#domain-table", DataTable)
        table.add_columns("Domain", "Status", "Expires", "Days Left", "Issuer")
        self._refresh()

    def on_screen_resume(self) -> None:
        log_ui("screen_resumed", screen="DomainStatusScreen")

    def action_refresh(self) -> None:
        log_ui("key_pressed", screen="DomainStatusScreen", key="f5")
        self._refresh()

    def action_pop_screen(self) -> None:
        log_ui("key_pressed", screen="DomainStatusScreen", key="escape")
        self.app.pop_screen()

    def _refresh(self) -> None:
        from main import get_domain_statuses

        table = self.query_one("#domain-table", DataTable)
        table.clear()

        domains = getattr(config.settings, "MANAGED_DOMAINS", []) or []
        if not domains:
            return

        for row in get_domain_statuses(domains, config.settings):
            status = row.get("status", "unknown")
            color = _STATUS_COLOR.get(status, "")
            status_text = Text(status, style=color) if color else Text(status)
            days_left = row.get("days_until_expiry")
            table.add_row(
                row.get("domain", ""),
                status_text,
                row.get("expires_at") or "-",
                str(days_left) if days_left is not None else "-",
                row.get("issuer") or "-",
            )
