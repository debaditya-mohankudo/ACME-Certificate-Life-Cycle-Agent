"""HomeScreen — read-only config summary (CA_PROVIDER or SPIFFE trust domain,
managed domains/SVIDs, LLM mode). No network calls, no cert-store access —
matches the safety of main.py's existing read-only query commands.

Every mode-specific field is read via getattr(config.settings, field, default),
not direct attribute access: CERT_ISSUANCE_MODE dispatches config.settings to
exactly one of AcmeConfig/SpiffeConfig at construction time, and the inactive
mode's fields simply don't exist on the object (accessing them raises
AttributeError — see config.py's module docstring and the repo's own
getattr-with-default convention already used in agent/nodes/scanner.py and
agent/nodes/storage.py for the same reason).

Imports the `config` module and reads `config.settings.*` live, rather than
`from config import settings` — the latter binds a name at import time, and
since ConfigScreen *reassigns* config.settings (config.settings = ...) rather
than mutating it in place, any module that did `from config import settings`
would keep pointing at the stale pre-reload object forever, not just until
next re-import. Found as a real bug: after saving ConfigScreen, HomeScreen's
summary didn't update even after screen-resume refresh, because it was
importing settings, not config.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Footer, Header, Static

import config
from tui.tui_widgets import bordered, breadcrumb_bar, log_ui, stat_tile, status_chip


def _format_config_summary() -> str:
    mode = getattr(config.settings, "CERT_ISSUANCE_MODE", "acme")
    lines = [f"Issuance mode: [b]{mode}[/b]"]

    if mode == "spiffe":
        trust_domain = getattr(config.settings, "SPIFFE_TRUST_DOMAIN", "") or "(not set)"
        svids = getattr(config.settings, "MANAGED_SPIFFE_IDS", []) or []
        lines.append(f"SPIFFE trust domain: {trust_domain}")
        lines.append(f"Managed SPIFFE IDs ({len(svids)}):")
        lines.extend(f"  - {svid}" for svid in svids) if svids else lines.append("  (none configured)")
    else:
        ca_provider = getattr(config.settings, "CA_PROVIDER", "?")
        directory_url = getattr(config.settings, "ACME_DIRECTORY_URL", "") or "(resolved from CA_PROVIDER preset)"
        domains = getattr(config.settings, "MANAGED_DOMAINS", []) or []
        challenge_mode = getattr(config.settings, "HTTP_CHALLENGE_MODE", "standalone")
        lines.append(f"CA provider: {ca_provider}")
        lines.append(f"ACME directory URL: {directory_url}")
        lines.append(f"Challenge mode: {challenge_mode}")
        lines.append(f"Managed domains ({len(domains)}):")
        lines.extend(f"  - {d}" for d in domains) if domains else lines.append("  (none configured)")

    llm_disabled = getattr(config.settings, "LLM_DISABLED", True)
    llm_line = "Deterministic mode (no LLM calls)" if llm_disabled else (
        f"LLM planner enabled — provider: {getattr(config.settings, 'LLM_PROVIDER', '?')}"
    )
    lines.append("")
    lines.append(llm_line)

    return "\n".join(lines)


def _status_chips() -> list[Static]:
    mode = getattr(config.settings, "CERT_ISSUANCE_MODE", "acme")
    llm_disabled = getattr(config.settings, "LLM_DISABLED", True)
    return [
        status_chip(f"{mode} mode", kind="success"),
        status_chip("deterministic" if llm_disabled else "LLM planner enabled", kind="success" if llm_disabled else "warning"),
    ]


def _list_value(items: list[str], max_shown: int = 3) -> str:
    """Comma-separated names for a stat tile's value, truncated with a
    "+N more" suffix so a long MANAGED_DOMAINS list doesn't blow out the
    tile's width — the tile is meant to show the actual names at a glance,
    not just a count, per explicit user feedback ("its not showing the
    domain names")."""
    if not items:
        return "(none)"
    shown = ", ".join(items[:max_shown])
    remaining = len(items) - max_shown
    return f"{shown} +{remaining} more" if remaining > 0 else shown


def _stat_tiles() -> list[Widget]:
    mode = getattr(config.settings, "CERT_ISSUANCE_MODE", "acme")
    if mode == "spiffe":
        svids = getattr(config.settings, "MANAGED_SPIFFE_IDS", []) or []
        return [stat_tile(f"Managed SVIDs ({len(svids)})", _list_value(svids))]
    domains = getattr(config.settings, "MANAGED_DOMAINS", []) or []
    ca_provider = getattr(config.settings, "CA_PROVIDER", "?")
    return [
        stat_tile(f"Managed Domains ({len(domains)})", _list_value(domains)),
        stat_tile("CA Provider", ca_provider),
    ]


class HomeScreen(Screen):
    """What this app does, plus a read-only render of the active config."""

    BINDINGS = [
        ("r", "run_screen", "Run"),
        ("d", "domain_status_screen", "Domain Status"),
        ("c", "config_screen", "Edit Config"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield breadcrumb_bar(["Home"], 0)
        yield Vertical(
            Static(
                "ACME Certificate Lifecycle Agent — TUI\n\n"
                "A deterministic LangGraph state machine that automates TLS "
                "certificate renewal via ACME (or SPIFFE SVID issuance). This "
                "TUI drives the same CLI (main.py) a terminal user would — it "
                "never bypasses the graph or the CLI's own safety checks.",
                id="intro",
            ),
            Horizontal(*_status_chips(), classes="status-chips", id="status-chips-row"),
            Horizontal(*_stat_tiles(), classes="stat-tiles", id="stat-tiles-row"),
            bordered(Static(_format_config_summary(), id="config-details"), "Active Configuration").add_class(
                "panel"
            ),
            id="home-body",
        )
        yield Footer()

    def on_mount(self) -> None:
        log_ui("screen_shown", screen="HomeScreen")

    def on_screen_resume(self) -> None:
        log_ui("screen_resumed", screen="HomeScreen")
        self.refresh_summary()

    def refresh_summary(self) -> None:
        """Re-render the config summary, status chips, and stat tiles against
        the current config.settings. Called explicitly from
        AcmeTuiApp.pop_screen (not just relying on on_screen_resume above) —
        see app.py's comment: on_screen_resume doesn't reliably fire on
        pop_screen in this Textual version, which would otherwise leave this
        panel showing stale values after ConfigScreen edits and pops back.

        Chips/tiles are Horizontal rows of child widgets, not a single
        Static's text — .update() doesn't apply; remove and re-mount the
        row's children instead."""
        self.query_one("#config-details", Static).update(_format_config_summary())

        chips_row = self.query_one("#status-chips-row", Horizontal)
        chips_row.remove_children()
        chips_row.mount_all(_status_chips())

        tiles_row = self.query_one("#stat-tiles-row", Horizontal)
        tiles_row.remove_children()
        tiles_row.mount_all(_stat_tiles())

    def action_run_screen(self) -> None:
        log_ui("key_pressed", screen="HomeScreen", key="r")
        from tui.screens.run import RunScreen

        self.app.push_screen(RunScreen())

    def action_domain_status_screen(self) -> None:
        log_ui("key_pressed", screen="HomeScreen", key="d")
        from tui.screens.domain_status import DomainStatusScreen

        self.app.push_screen(DomainStatusScreen())

    def action_config_screen(self) -> None:
        log_ui("key_pressed", screen="HomeScreen", key="c")
        from tui.screens.config_edit import ConfigScreen

        self.app.push_screen(ConfigScreen())
