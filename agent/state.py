"""
Agent state definition for the ACME certificate lifecycle agent.

Key design decisions vs. the original plan:
  - AcmeOrder uses List fields (auth_urls, challenge_urls, etc.) to support
    multi-domain SAN certificates where each domain gets its own authorization.
  - acme_account_key is NOT stored in state (security: would leak into
    LangSmith traces).  The account key is loaded from disk by the account
    node and passed through a secure side-channel (the key path is in state).
  - retry_delay_seconds is included for exponential-backoff logic.
  - cert_metadata stores per-domain metadata dicts populated by storage_manager.
"""
from __future__ import annotations

from typing import Annotated, Dict, List, Optional

from langgraph.graph.message import add_messages
from typing_extensions import TypedDict

try:
    from langchain_core.messages import BaseMessage as _BaseMessage
except ImportError:
    _BaseMessage = dict  # type: ignore[assignment,misc]


class CertRecord(TypedDict):
    domain: str
    cert_path: Optional[str]             # Path to existing cert.pem (None if not found)
    key_path: Optional[str]              # Path to privkey.pem
    expiry_date: Optional[str]           # ISO-8601 UTC string parsed from cert
    days_until_expiry: Optional[int]     # Computed at scan time
    needs_renewal: bool                  # True when < renewal_threshold_days remain
    detected_ca_provider: Optional[str]  # CA that issued the existing cert (advisory)


class AcmeOrder(TypedDict):
    """
    Represents one ACME order, potentially covering multiple domains (SANs).

    For a single-domain order:
      auth_urls       = [one auth url]
      challenge_urls  = [one challenge url]
      challenge_tokens = [one token]
      key_authorizations = [one key auth string]

    For a multi-domain SAN order, all lists are parallel (same length).

    DNS-01 fields (populated when HTTP_CHALLENGE_MODE="dns", else empty lists):
      auth_domains    = domain string per authorization (e.g. "api.example.com")
      dns_txt_values  = base64url(SHA-256(key_auth)) per domain
    """
    order_url: str
    status: str                       # pending | ready | processing | valid | invalid
    auth_urls: List[str]              # One per identifier (domain)
    challenge_urls: List[str]         # Challenge URL per authorization
    challenge_tokens: List[str]       # Token per authorization
    key_authorizations: List[str]     # token + "." + thumbprint per authorization
    finalize_url: str
    certificate_url: Optional[str]    # Set after order is valid
    auth_domains: List[str]           # Domain string per authorization (for DNS-01)
    dns_txt_values: List[str]         # base64url(SHA-256(key_auth)) per domain; [] for HTTP-01


class AgentState(TypedDict):
    # ── Configuration ──────────────────────────────────────────────────────
    managed_domains: List[str]
    renewal_threshold_days: int
    cert_store_path: str
    account_key_path: str             # Path to account private key on disk
    webroot_path: Optional[str]

    # ── Scan results ───────────────────────────────────────────────────────
    cert_records: List[CertRecord]
    pending_renewals: List[str]       # Domains needing renewal, ordered by urgency

    # ── Active ACME flow ───────────────────────────────────────────────────
    current_domain: Optional[str]
    current_order: Optional[AcmeOrder]
    acme_account_url: Optional[str]   # Cached after first registration
    current_nonce: Optional[str]      # Last-used ACME nonce (refreshed each request)

    # ── LLM reasoning ──────────────────────────────────────────────────────
    messages: Annotated[List[_BaseMessage], add_messages]
    renewal_plan: Optional[str]       # LLM's JSON renewal strategy
    error_analysis: Optional[str]     # Human-readable failure summary (prose, not JSON — read error_action for routing)
    error_action: Optional[str]       # "retry" | "skip" | "abort" — set by error_handler, read directly by error_action_router

    # ── Progress tracking ──────────────────────────────────────────────────
    completed_renewals: List[str]
    failed_renewals: List[str]
    error_log: List[str]
    retry_count: int
    retry_delay_seconds: int          # Current delay; doubles on each retry
    retry_not_before: Optional[float] # Unix timestamp set by error_handler; retry_scheduler waits until this
    max_retries: int

    # ── Per-domain metadata ────────────────────────────────────────────────
    cert_metadata: Dict[str, dict]    # domain → metadata dict from storage_manager

    # ── Revocation flow ────────────────────────────────────────────────────
    revocation_targets: List[str]            # domains queued for revocation
    current_revocation_domain: Optional[str] # domain being revoked right now
    revocation_reason: int                   # RFC 5280: 0=unspecified,1=keyCompromise,4=superseded,5=cessation
    revoked_domains: List[str]               # successfully revoked
    failed_revocations: List[str]            # domains that failed revocation
