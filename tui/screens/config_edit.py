"""ConfigScreen — edit CA_PROVIDER / MANAGED_DOMAINS / HTTP_CHALLENGE_MODE and
persist to .env, then hot-reload config.settings in-process.

ACME mode only, per explicit product scoping — this screen never reads or
writes CERT_ISSUANCE_MODE/SPIFFE_* fields. If CERT_ISSUANCE_MODE=spiffe is
ever active, opening this screen still shows/edits the ACME fields (they
exist on-disk in .env regardless of which mode is currently active — see
config.py's per-mode class split), it just doesn't affect which mode is
selected.

Uses python-dotenv's set_key (already a transitive dependency via
pydantic-settings, no new dependency added) for safe, quoting-correct
read-modify-write of individual .env keys, rather than hand-parsing the
file. set_key deliberately fails if the target path doesn't exist rather
than creating one in an unexpected location — this screen creates an empty
.env first if missing, since .env at the project root is this repo's own
well-known, intended config file (see .env.example), not an arbitrary path.
"""
from __future__ import annotations

from pathlib import Path

from dotenv import set_key
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Select

import config
from tui.tui_widgets import bordered, log_ui

CA_PROVIDER_CHOICES = [
    ("Let's Encrypt (recommended)", "letsencrypt"),
    ("Let's Encrypt — staging / test run", "letsencrypt_staging"),
    ("DigiCert", "digicert"),
    ("ZeroSSL", "zerossl"),
    ("Sectigo", "sectigo"),
    ("Custom ACME server", "custom"),
]

CHALLENGE_MODE_CHOICES = [
    ("Standalone — this server has a live website on port 80", "standalone"),
    ("Webroot — drop the challenge file into an existing web root", "webroot"),
    ("DNS — I manage this domain's DNS", "dns"),
]

_ENV_PATH = Path(".env")


class ConfigScreen(Screen):
    """Edit CA provider / managed domains / challenge mode, save to .env."""

    BINDINGS = [("escape", "pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            bordered(
                Select(CA_PROVIDER_CHOICES, id="ca-provider-select", value=self._current_ca_provider()),
                "Certificate Authority",
            ).add_class("panel"),
            bordered(
                Input(
                    value=",".join(getattr(config.settings, "MANAGED_DOMAINS", []) or []),
                    placeholder="domain.com,other.com",
                    id="domains-input",
                ),
                "Managed Domain(s) — comma separated",
            ).add_class("panel"),
            bordered(
                Select(CHALLENGE_MODE_CHOICES, id="challenge-mode-select", value=self._current_challenge_mode()),
                "Validation Type",
            ).add_class("panel"),
            Button("Save", id="save-button", variant="primary"),
            id="config-body",
        )
        yield Footer()

    @staticmethod
    def _current_ca_provider() -> str:
        value = getattr(config.settings, "CA_PROVIDER", "letsencrypt")
        return value if value in {c[1] for c in CA_PROVIDER_CHOICES} else "letsencrypt"

    @staticmethod
    def _current_challenge_mode() -> str:
        value = getattr(config.settings, "HTTP_CHALLENGE_MODE", "standalone")
        return value if value in {c[1] for c in CHALLENGE_MODE_CHOICES} else "standalone"

    def on_mount(self) -> None:
        log_ui("screen_shown", screen="ConfigScreen")

    def on_screen_resume(self) -> None:
        log_ui("screen_resumed", screen="ConfigScreen")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "save-button":
            return
        log_ui("button_pressed", screen="ConfigScreen", button=event.button.id)

        domains_raw = self.query_one("#domains-input", Input).value.strip()
        domains = [d.strip() for d in domains_raw.split(",") if d.strip()]
        if not domains:
            self.notify("Enter at least one domain.", severity="warning")
            return

        ca_provider = self.query_one("#ca-provider-select", Select).value
        challenge_mode = self.query_one("#challenge-mode-select", Select).value

        try:
            self._validate_and_apply(ca_provider, domains, challenge_mode)
        except Exception as exc:
            # e.g. AcmeConfig's own cross-field validators — "DNS mode
            # requires CLOUDFLARE_API_TOKEN", EAB-required-for-this-CA, etc.
            # Must not write .env or reload config.settings on failure —
            # validate-then-persist, not persist-then-validate, so a bad
            # combination never lands in .env or the running process.
            self.notify(f"Invalid configuration: {exc}", severity="error")
            log_ui("config_save_rejected", screen="ConfigScreen", error=str(exc))
            return

        self._save_to_env(ca_provider, domains, challenge_mode)
        log_ui(
            "config_saved",
            screen="ConfigScreen",
            ca_provider=ca_provider,
            domains=domains,
            challenge_mode=challenge_mode,
        )
        self.notify("Configuration saved.", severity="information")
        self.app.pop_screen()

    @staticmethod
    def _validate_and_apply(ca_provider: str, domains: list[str], challenge_mode: str) -> None:
        """Construct a candidate settings object from the current process
        env + these three overrides (without touching .env yet). Raises if
        the combination is invalid (e.g. config.py's own DNS_PROVIDER/EAB
        cross-field validators). Only on success does it become
        config.settings — the caller persists to .env afterward."""
        import os

        original = {
            key: os.environ.get(key)
            for key in ("CA_PROVIDER", "MANAGED_DOMAINS", "HTTP_CHALLENGE_MODE")
        }
        os.environ["CA_PROVIDER"] = ca_provider
        os.environ["MANAGED_DOMAINS"] = ",".join(domains)
        os.environ["HTTP_CHALLENGE_MODE"] = challenge_mode
        try:
            config.settings = config.make_settings()
        except Exception:
            for key, value in original.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            raise

    @staticmethod
    def _save_to_env(ca_provider: str, domains: list[str], challenge_mode: str) -> None:
        if not _ENV_PATH.exists():
            _ENV_PATH.touch()
        set_key(str(_ENV_PATH), "CA_PROVIDER", ca_provider)
        set_key(str(_ENV_PATH), "MANAGED_DOMAINS", ",".join(domains))
        set_key(str(_ENV_PATH), "HTTP_CHALLENGE_MODE", challenge_mode)

    def action_pop_screen(self) -> None:
        log_ui("key_pressed", screen="ConfigScreen", key="escape")
        self.app.pop_screen()
