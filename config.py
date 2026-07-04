"""
Application configuration via Pydantic Settings.
All values can be overridden by environment variables or a .env file.

CERT_ISSUANCE_MODE selects between two mutually exclusive config classes,
AcmeConfig and SpiffeConfig — only one is ever instantiated (via the
make_settings() factory below), not one flat class holding both modes'
fields. Run two separate instances/configs if you need both modes at once.
"""
from __future__ import annotations

import os
import warnings
from typing import List, Literal, Optional

from pydantic import field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from logger import logger


class _CommaFallbackMixin:
    """Return the raw string when JSON parsing fails.

    pydantic-settings ≥2.7 calls json.loads() on complex-typed fields
    (e.g. List[str]) before field_validators run.  A plain comma-separated
    value like ``api.example.com,shop.example.com`` is not valid JSON and
    raises SettingsError before the parse_domains validator can handle it.
    This mixin catches that ValueError and returns the raw string so the
    field_validator receives it and can split on commas as intended.
    """

    def prepare_field_value(self, field_name, field, value, value_is_complex):  # type: ignore[override]
        try:
            return super().prepare_field_value(field_name, field, value, value_is_complex)  # type: ignore[misc]
        except ValueError:
            return value


class _CSVEnvSource(_CommaFallbackMixin, EnvSettingsSource):
    pass


class _CSVDotEnvSource(_CommaFallbackMixin, DotEnvSettingsSource):
    pass


class _BaseAppSettings(BaseSettings):
    """Fields and validators consulted regardless of CERT_ISSUANCE_MODE.

    AcmeConfig and SpiffeConfig share only what's declared here — each mode's
    own fields don't exist on the other's instance at all. Code paths shared
    between the two graphs (e.g. agent/nodes/scanner.py, storage.py) must read
    mode-specific fields via getattr(config.settings, "FIELD", default), never
    assume presence.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    CERT_ISSUANCE_MODE: Literal["acme", "spiffe"] = "acme"

    # ── Storage ────────────────────────────────────────────────────────────
    CERT_STORE_PATH: str = "./certs"
    ACCOUNT_KEY_PATH: str = "./account.key"
    KEY_TYPE: Literal["rsa", "ecc"] = "rsa"
    DOMAIN_KEY_SIZE: int = 2048
    ECC_CURVE: Literal["secp256r1", "secp384r1", "secp521r1"] = "secp256r1"

    # ── LLM (renewal planner only — error_handler/reporter remain deterministic) ──
    LLM_DISABLED: bool = True   # Default: deterministic planner; set False to enable LLM
    # claude_cli shells to `claude -p --safe-mode --tools none` (reuses the caller's
    # existing Claude Code login) — no API key or `uv sync --extra llm-*` needed,
    # which is why it's the default once LLM_DISABLED=False.
    LLM_PROVIDER: Literal["anthropic", "openai", "ollama", "claude_cli"] = "claude_cli"
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    LLM_MODEL_PLANNER: str = "haiku"

    # ── Scheduling ─────────────────────────────────────────────────────────
    SCHEDULE_TIME: str = "06:00"

    # ── Retry / resilience ─────────────────────────────────────────────────
    MAX_RETRIES: int = 3

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            _CSVEnvSource(settings_cls),
            _CSVDotEnvSource(settings_cls),
            file_secret_settings,
        )

    @field_validator("KEY_TYPE", mode="before")
    @classmethod
    def validate_key_type(cls, v: str) -> str:
        """Normalize and validate supported certificate key types."""
        normalized = v.strip().lower()
        allowed = {"rsa", "ecc"}
        if normalized not in allowed:
            raise ValueError(f"KEY_TYPE must be one of {allowed}")
        return normalized

    @field_validator("LLM_DISABLED", mode="before")
    @classmethod
    def validate_llm_disabled(cls, v: object) -> bool:
        """Validate LLM_DISABLED is a boolean flag.

        Accepts truthy/falsy values and converts to bool: bool passthrough,
        common string forms (true/false/1/0/yes/no), and int-like values.
        """
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            lowered = v.strip().lower()
            if lowered in {"true", "1", "yes", "on"}:
                return True
            elif lowered in {"false", "0", "no", "off"}:
                return False
            else:
                raise ValueError(
                    f"LLM_DISABLED must be a boolean (true/false), got: {v!r}"
                )
        try:
            return bool(v)
        except Exception:
            raise ValueError(
                f"LLM_DISABLED must be a boolean, got: {type(v).__name__}"
            )

    @model_validator(mode="after")
    def validate_llm_available(self) -> "_BaseAppSettings":
        """If LLM is enabled, verify langchain packages are installed."""
        if not self.LLM_DISABLED:
            try:
                import langchain.chat_models  # noqa: F401
            except ImportError:
                raise ValueError(
                    "LLM_DISABLED=false but langchain is not installed. "
                    "Run: uv sync --extra llm-anthropic  (or llm-openai / llm-ollama)\n"
                    "Or set LLM_DISABLED=true in .env to run without LLM."
                )
        return self

    @model_validator(mode="after")
    def validate_key_type_settings(self) -> "_BaseAppSettings":
        """Validate key-type dependent settings for RSA and ECC."""
        if self.KEY_TYPE == "rsa" and self.DOMAIN_KEY_SIZE < 2048:
            raise ValueError("DOMAIN_KEY_SIZE must be >= 2048 when KEY_TYPE='rsa'")
        if self.KEY_TYPE == "ecc" and not self.ECC_CURVE:
            raise ValueError("ECC_CURVE must be set when KEY_TYPE='ecc'")
        return self


class AcmeConfig(_BaseAppSettings):
    """CERT_ISSUANCE_MODE='acme' — public-CA certificate issuance via ACME."""

    CERT_ISSUANCE_MODE: Literal["acme"] = "acme"

    # ── CA Provider ─────────────────────────────────────────────────────────
    CA_PROVIDER: Literal[
        "digicert", "letsencrypt", "letsencrypt_staging", "zerossl", "sectigo", "custom"
    ] = "digicert"

    # ── ACME credentials (EAB — required for DigiCert, ZeroSSL, and Sectigo) ──────
    ACME_EAB_KEY_ID: str = ""
    ACME_EAB_HMAC_KEY: str = ""
    # Only consulted when CA_PROVIDER="custom"
    ACME_DIRECTORY_URL: str = ""

    # ── Domain management ───────────────────────────────────────────────────
    MANAGED_DOMAINS: List[str] = []
    RENEWAL_THRESHOLD_DAYS: int = 30

    # ── HTTP-01 / DNS-01 Challenge ─────────────────────────────────────────
    HTTP_CHALLENGE_MODE: str = "standalone"   # "standalone" | "webroot" | "dns"
    HTTP_CHALLENGE_PORT: int = 80
    WEBROOT_PATH: Optional[str] = None

    # ── DNS-01 Challenge ───────────────────────────────────────────────────
    DNS_PROVIDER: Literal["cloudflare", "route53", "google"] = "cloudflare"
    DNS_PROPAGATION_WAIT_SECONDS: int = 60

    # Cloudflare
    CLOUDFLARE_API_TOKEN: str = ""
    CLOUDFLARE_ZONE_ID: str = ""         # optional; auto-discovered from domain if empty

    # Route53
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_REGION: str = "us-east-1"
    AWS_ROUTE53_HOSTED_ZONE_ID: str = "" # optional; auto-discovered if empty

    # Google Cloud DNS
    GOOGLE_PROJECT_ID: str = ""
    GOOGLE_APPLICATION_CREDENTIALS: str = "" # path to service account JSON
    GOOGLE_CLOUD_DNS_ZONE_NAME: str = ""     # GCP managed zone name

    # ── ACME TLS (for testing against Pebble / self-signed CAs) ───────────
    ACME_CA_BUNDLE: str = ""       # Path to CA cert bundle; empty = system default
    ACME_INSECURE: bool = False    # Skip TLS verification (never use in production)

    @field_validator("MANAGED_DOMAINS", mode="before")
    @classmethod
    def parse_domains(cls, v: object) -> List[str]:
        """Accept comma-separated string or list."""
        if isinstance(v, str):
            return [d.strip() for d in v.split(",") if d.strip()]
        return v  # type: ignore[return-value]

    @field_validator("HTTP_CHALLENGE_MODE")
    @classmethod
    def validate_challenge_mode(cls, v: str) -> str:
        """Validate supported HTTP challenge mode values."""
        allowed = {"standalone", "webroot", "dns"}
        if v not in allowed:
            raise ValueError(f"HTTP_CHALLENGE_MODE must be one of {allowed}")
        return v

    @model_validator(mode="after")
    def validate_eab_credentials(self) -> "AcmeConfig":
        """Reject partial EAB configuration before any network call is made."""
        if self.CA_PROVIDER in {"digicert", "zerossl", "sectigo"}:
            key_set = bool(self.ACME_EAB_KEY_ID)
            hmac_set = bool(self.ACME_EAB_HMAC_KEY)
            if key_set != hmac_set:
                missing = "ACME_EAB_HMAC_KEY" if key_set else "ACME_EAB_KEY_ID"
                raise ValueError(
                    f"{missing} must be set when CA_PROVIDER='{self.CA_PROVIDER}'. "
                    f"Both ACME_EAB_KEY_ID and ACME_EAB_HMAC_KEY are required together."
                )
        return self

    @model_validator(mode="after")
    def validate_webroot(self) -> "AcmeConfig":
        """Require WEBROOT_PATH when webroot challenge mode is selected."""
        if self.HTTP_CHALLENGE_MODE == "webroot" and not self.WEBROOT_PATH:
            raise ValueError(
                "WEBROOT_PATH must be set when HTTP_CHALLENGE_MODE='webroot'"
            )
        return self

    @model_validator(mode="after")
    def validate_dns_config(self) -> "AcmeConfig":
        """Validate required DNS provider settings for DNS-01 mode."""
        if self.HTTP_CHALLENGE_MODE != "dns":
            return self
        if self.DNS_PROVIDER == "cloudflare" and not self.CLOUDFLARE_API_TOKEN:
            raise ValueError(
                "CLOUDFLARE_API_TOKEN must be set when DNS_PROVIDER='cloudflare'"
            )
        if self.DNS_PROVIDER == "google" and not self.GOOGLE_PROJECT_ID:
            raise ValueError(
                "GOOGLE_PROJECT_ID must be set when DNS_PROVIDER='google'"
            )
        return self

    @model_validator(mode="after")
    def resolve_acme_directory(self) -> "AcmeConfig":
        """Resolve ACME directory URL from provider presets or custom value."""
        if any(os.environ.get(k) for k in (
            "DIGICERT_ACME_DIRECTORY", "DIGICERT_EAB_KEY_ID", "DIGICERT_EAB_HMAC_KEY"
        )):
            warnings.warn(
                "DIGICERT_ACME_DIRECTORY/DIGICERT_EAB_KEY_ID/DIGICERT_EAB_HMAC_KEY are deprecated. "
                "Use CA_PROVIDER + ACME_EAB_KEY_ID + ACME_EAB_HMAC_KEY instead.",
                DeprecationWarning,
                stacklevel=2,
            )

        _PRESETS = {
            "digicert":            "https://acme.digicert.com/v2/DV/directory",
            "letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
            "letsencrypt_staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "zerossl":             "https://acme.zerossl.com/v2/DV90",
            "sectigo":             "https://acme.sectigo.com/v2/DV",
        }
        if self.CA_PROVIDER in _PRESETS:
            self.ACME_DIRECTORY_URL = _PRESETS[self.CA_PROVIDER]
        elif not self.ACME_DIRECTORY_URL:
            raise ValueError("ACME_DIRECTORY_URL must be set when CA_PROVIDER='custom'")
        return self

    @model_validator(mode="after")
    def log_resolved_settings(self) -> "AcmeConfig":
        """Log the resolved config once construction succeeds.

        Runs last (declaration order) so mode-dependent fields like
        ACME_DIRECTORY_URL are already resolved. Never logs secrets:
        EAB credentials, API keys, cloud provider tokens.
        """
        logger.info(
            "Settings resolved: mode=acme ca_provider=%s directory_url=%s "
            "managed_domains=%d challenge_mode=%s llm_disabled=%s llm_provider=%s",
            self.CA_PROVIDER, self.ACME_DIRECTORY_URL, len(self.MANAGED_DOMAINS),
            self.HTTP_CHALLENGE_MODE, self.LLM_DISABLED, self.LLM_PROVIDER,
        )
        return self


class SpiffeConfig(_BaseAppSettings):
    """CERT_ISSUANCE_MODE='spiffe' — SVID issuance via a self-hosted SPIRE server.

    No public CA, no HTTP-01/DNS-01 challenge — authentication happens via
    node + workload attestation against your own SPIRE server, reached
    through the SPIRE Agent's local Workload API socket. There is no
    ACME_DIRECTORY_URL/EAB equivalent: trust is rooted in your own SPIRE
    deployment, not the public WebPKI. See doc/DESIGN_SPIFFE_SVID_EXTENSION.md.
    """

    CERT_ISSUANCE_MODE: Literal["spiffe"] = "spiffe"

    SPIRE_AGENT_SOCKET_PATH: str = "/tmp/spire-agent/public/api.sock"
    SPIFFE_TRUST_DOMAIN: str = ""
    # SPIFFE IDs this agent expects to hold/renew — the selector-based
    # registration entries on the SPIRE server are the actual source of
    # truth for what's issuable; this is only used for planner classification
    # and monitoring, analogous to MANAGED_DOMAINS for the ACME flow.
    MANAGED_SPIFFE_IDS: List[str] = []

    @field_validator("MANAGED_SPIFFE_IDS", mode="before")
    @classmethod
    def parse_spiffe_ids(cls, v: object) -> List[str]:
        """Accept comma-separated string or list, same as MANAGED_DOMAINS."""
        if isinstance(v, str):
            return [d.strip() for d in v.split(",") if d.strip()]
        return v  # type: ignore[return-value]

    @model_validator(mode="after")
    def require_trust_domain(self) -> "SpiffeConfig":
        """SPIFFE_TRUST_DOMAIN has no sensible default — must be set explicitly."""
        if not self.SPIFFE_TRUST_DOMAIN:
            raise ValueError(
                "SPIFFE_TRUST_DOMAIN must be set when CERT_ISSUANCE_MODE='spiffe'"
            )
        return self

    @model_validator(mode="after")
    def log_resolved_settings(self) -> "SpiffeConfig":
        """Log the resolved config once construction succeeds.

        Never logs secrets: EAB credentials, API keys, cloud provider tokens.
        """
        logger.info(
            "Settings resolved: mode=spiffe trust_domain=%s agent_socket=%s "
            "managed_spiffe_ids=%d llm_disabled=%s llm_provider=%s",
            self.SPIFFE_TRUST_DOMAIN, self.SPIRE_AGENT_SOCKET_PATH,
            len(self.MANAGED_SPIFFE_IDS), self.LLM_DISABLED, self.LLM_PROVIDER,
        )
        return self


class _ModeBootstrap(BaseSettings):
    """Reads just CERT_ISSUANCE_MODE, so make_settings() can pick a class before
    constructing it — mirrors acme/client.py's _client_registry dispatch shape,
    one level up (class instead of partial-kwargs)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    CERT_ISSUANCE_MODE: Literal["acme", "spiffe"] = "acme"


# Field names belonging to the *other* mode's class — used only to warn if
# left set in the environment while that mode isn't active (see below).
_ACME_ONLY_FIELD_NAMES = set(AcmeConfig.model_fields) - set(_BaseAppSettings.model_fields)
_SPIFFE_ONLY_FIELD_NAMES = set(SpiffeConfig.model_fields) - set(_BaseAppSettings.model_fields)


def _warn_stray_other_mode_env_vars(mode: str) -> None:
    """Loudly warn (not silently drop) if the *inactive* mode's env vars are set.

    Replaces the old validate_cert_issuance_mode_fields coercion (commit
    a42dc1a) — that validator mutated fields on a single shared class; now
    that AcmeConfig/SpiffeConfig simply don't have the other mode's fields at
    all (extra="ignore" drops them silently on construction), this is the one
    remaining place — before either class is built — that still sees the raw
    environment and can flag a likely leftover-config mistake.
    """
    other_fields = _SPIFFE_ONLY_FIELD_NAMES if mode == "acme" else _ACME_ONLY_FIELD_NAMES
    for name in sorted(other_fields):
        if os.environ.get(name):
            logger.warning(
                "CERT_ISSUANCE_MODE=%r: ignoring %s=%r set in environment "
                "(not consulted in this mode)",
                mode, name, os.environ[name],
            )


def make_settings() -> "AcmeConfig | SpiffeConfig":
    """Construct the one settings object matching CERT_ISSUANCE_MODE — never both."""
    mode = _ModeBootstrap().CERT_ISSUANCE_MODE
    _warn_stray_other_mode_env_vars(mode)
    registry = {"acme": AcmeConfig, "spiffe": SpiffeConfig}
    try:
        return registry[mode]()
    except KeyError:
        raise ValueError(f"Unknown CERT_ISSUANCE_MODE: {mode!r}")


# Type alias — kept so existing `settings: Settings | None` annotations still
# resolve; note `Settings` itself is no longer constructible (it's a Union).
Settings = AcmeConfig | SpiffeConfig

# Module-level singleton — import and use everywhere.
settings = make_settings()
