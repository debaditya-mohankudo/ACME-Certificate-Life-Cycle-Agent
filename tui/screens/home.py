"""HomeScreen — read-only config summary (CA_PROVIDER or SPIFFE trust domain,
managed domains/SVIDs, LLM mode). No network calls, no cert-store access —
matches the safety of main.py's existing read-only query commands.

Every mode-specific field is read via getattr(settings, field, default), not
direct attribute access: CERT_ISSUANCE_MODE dispatches config.settings to
exactly one of AcmeConfig/SpiffeConfig at construction time, and the inactive
mode's fields simply don't exist on the object (accessing them raises
AttributeError — see config.py's module docstring and the repo's own
getattr-with-default convention already used in agent/nodes/scanner.py and
agent/nodes/storage.py for the same reason).
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from config import settings
from tui.tui_widgets import bordered, log_ui


def _format_config_summary() -> str:
    mode = getattr(settings, "CERT_ISSUANCE_MODE", "acme")
    lines = [f"Issuance mode: [b]{mode}[/b]"]

    if mode == "spiffe":
        trust_domain = getattr(settings, "SPIFFE_TRUST_DOMAIN", "") or "(not set)"
        svids = getattr(settings, "MANAGED_SPIFFE_IDS", []) or []
        lines.append(f"SPIFFE trust domain: {trust_domain}")
        lines.append(f"Managed SPIFFE IDs ({len(svids)}):")
        lines.extend(f"  - {svid}" for svid in svids) if svids else lines.append("  (none configured)")
    else:
        ca_provider = getattr(settings, "CA_PROVIDER", "?")
        directory_url = getattr(settings, "ACME_DIRECTORY_URL", "") or "(resolved from CA_PROVIDER preset)"
        domains = getattr(settings, "MANAGED_DOMAINS", []) or []
        challenge_mode = getattr(settings, "HTTP_CHALLENGE_MODE", "standalone")
        lines.append(f"CA provider: {ca_provider}")
        lines.append(f"ACME directory URL: {directory_url}")
        lines.append(f"Challenge mode: {challenge_mode}")
        lines.append(f"Managed domains ({len(domains)}):")
        lines.extend(f"  - {d}" for d in domains) if domains else lines.append("  (none configured)")

    llm_disabled = getattr(settings, "LLM_DISABLED", True)
    llm_line = "Deterministic mode (no LLM calls)" if llm_disabled else (
        f"LLM planner enabled — provider: {getattr(settings, 'LLM_PROVIDER', '?')}"
    )
    lines.append("")
    lines.append(llm_line)

    return "\n".join(lines)


class HomeScreen(Screen):
    """What this app does, plus a read-only render of the active config."""

    BINDINGS = [("r", "run_screen", "Run"), ("d", "domain_status_screen", "Domain Status")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            Static(
                "ACME Certificate Lifecycle Agent — TUI\n\n"
                "A deterministic LangGraph state machine that automates TLS "
                "certificate renewal via ACME (or SPIFFE SVID issuance). This "
                "TUI drives the same CLI (main.py) a terminal user would — it "
                "never bypasses the graph or the CLI's own safety checks.\n\n"
                "[b]r[/b] Run a renewal   [b]d[/b] Domain status",
                id="intro",
            ),
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

    def action_run_screen(self) -> None:
        log_ui("key_pressed", screen="HomeScreen", key="r")
        from tui.screens.run import RunScreen

        self.app.push_screen(RunScreen())

    def action_domain_status_screen(self) -> None:
        log_ui("key_pressed", screen="HomeScreen", key="d")
        from tui.screens.domain_status import DomainStatusScreen

        self.app.push_screen(DomainStatusScreen())
