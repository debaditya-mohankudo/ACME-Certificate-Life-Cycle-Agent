"""
LangGraph StateGraph builder for the certificate lifecycle agent.

build_graph() branches on settings.CERT_ISSUANCE_MODE — "acme" and "spiffe"
are strictly either/or (see config.py), so exactly one of the two node sets
and edge chains below is ever wired into a given graph, never both.

Shared spine (both modes): certificate_scanner → renewal_planner (LLM) →
pick_next_domain (loop entry) → ... issuance-specific chain ... →
storage_manager → domain_loop_router → next_domain (loop) / all_done →
summary_reporter → END. error_handler/retry_scheduler are ACME-only (see
below) — spiffe_attestor's failures are terminal per-domain, same treatment
storage_manager already gives its own failures.

ACME mode topology:
  START
    → certificate_scanner
    → renewal_planner (LLM)
    → [conditional: no_renewals → summary_reporter → END]
    → acme_account_setup
    → pick_next_domain          ← loop entry point
    → order_initializer
    → challenge_setup
    → challenge_verifier
    → [conditional: challenge_failed → error_handler (LLM)]
         error_handler → [conditional: retry → retry_scheduler → pick_next_domain (reset)]
                                        skip  → pick_next_domain
                                        abort → summary_reporter
    → csr_generator
    → order_finalizer
    → cert_downloader
    → storage_manager
    → domain_loop_router
    → [conditional: next_domain → pick_next_domain]
                   all_done   → summary_reporter
    → END

SPIFFE mode topology:
  START
    → certificate_scanner
    → renewal_planner (LLM)
    → [conditional: no_renewals → summary_reporter → END]
    → pick_next_domain          ← loop entry point (no acme_account_setup —
                                   there's no ACME account in SPIFFE mode)
    → spiffe_attestor            (fetch SVID via SPIRE Agent Workload API —
                                   no HTTP-01/DNS-01 challenge, see
                                   doc/SPIRE_TESTING_SERVER.md)
    → storage_manager
    → domain_loop_router
    → [conditional: next_domain → pick_next_domain]
                   all_done   → summary_reporter
    → END

Note: retry_scheduler applies backoff (time.sleep) before retrying, ACME
mode only. See: agent/nodes/retry_scheduler.py
"""
from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from config import settings
from agent.nodes.registry import get_node
from agent.nodes.router import (
    challenge_router,
    domain_loop_router,
    error_action_router,
    renewal_router,
)
from agent.state import AgentState


def build_graph(use_checkpointing: bool = False):
    """
    Build and compile the certificate lifecycle agent's StateGraph.

    Branches on settings.CERT_ISSUANCE_MODE ("acme" or "spiffe") to select
    which issuance node set and edge chain get wired in — never both.

    Args:
        use_checkpointing: If True, attach a MemorySaver for resumable runs.

    Returns:
        CompiledGraph ready to invoke / stream.
    """
    builder = StateGraph(AgentState)

    if settings.CERT_ISSUANCE_MODE == "acme":
        _build_acme_graph(builder)
    else:
        _build_spiffe_graph(builder)

    checkpointer = MemorySaver() if use_checkpointing else None
    return builder.compile(checkpointer=checkpointer)


def _build_acme_graph(builder: StateGraph) -> None:
    """Wire the ACME issuance node set and edge chain into `builder`."""
    acme_nodes = [
        "certificate_scanner",
        "renewal_planner",
        "acme_account_setup",
        "pick_next_domain",
        "order_initializer",
        "challenge_setup",
        "challenge_verifier",
        "csr_generator",
        "order_finalizer",
        "cert_downloader",
        "storage_manager",
        "error_handler",
        "retry_scheduler",
        "summary_reporter",
    ]
    for node_name in acme_nodes:
        builder.add_node(node_name, get_node(node_name))

    builder.add_edge(START, "certificate_scanner")
    builder.add_edge("certificate_scanner", "renewal_planner")

    # After planner: route on whether renewals are needed
    builder.add_conditional_edges(
        "renewal_planner",
        renewal_router,
        {
            "renewals_needed": "acme_account_setup",
            "no_renewals": "summary_reporter",
        },
    )

    builder.add_edge("acme_account_setup", "pick_next_domain")

    # pick_next_domain feeds into the per-domain renewal pipeline
    builder.add_edge("pick_next_domain", "order_initializer")
    builder.add_edge("order_initializer", "challenge_setup")
    builder.add_edge("challenge_setup", "challenge_verifier")

    # After challenge verification: success or failure
    builder.add_conditional_edges(
        "challenge_verifier",
        challenge_router,
        {
            "challenge_ok": "csr_generator",
            "challenge_failed": "error_handler",
        },
    )

    # Happy path: CSR → finalize → download → store
    builder.add_edge("csr_generator", "order_finalizer")
    builder.add_edge("order_finalizer", "cert_downloader")
    builder.add_edge("cert_downloader", "storage_manager")

    # After storage: loop router decides next domain or done
    builder.add_conditional_edges(
        "storage_manager",
        domain_loop_router,
        {
            "next_domain": "pick_next_domain",
            "all_done": "summary_reporter",
        },
    )

    # Error handler routing
    # NOTE: On retry, route through retry_scheduler to apply backoff before retrying
    builder.add_conditional_edges(
        "error_handler",
        error_action_router,
        {
            "retry": "retry_scheduler",       # Apply backoff via scheduler
            "skip_domain": "pick_next_domain", # skip pops next domain (no wait)
            "abort": "summary_reporter",
        },
    )

    # Retry scheduler → pick_next_domain (loop for retry)
    builder.add_edge("retry_scheduler", "pick_next_domain")

    builder.add_edge("summary_reporter", END)


def _build_spiffe_graph(builder: StateGraph) -> None:
    """Wire the SPIFFE issuance node set and edge chain into `builder`.

    No acme_account_setup (no ACME account in SPIFFE mode), no challenge
    setup/verification (no HTTP-01/DNS-01 — auth already happened via
    attestation before spiffe_attestor can fetch anything), no
    error_handler/retry_scheduler (spiffe_attestor failures are terminal
    per-domain, same treatment storage_manager already gives its own
    failures — see agent/nodes/spiffe_attestor.py).
    """
    spiffe_nodes = [
        "certificate_scanner",
        "renewal_planner",
        "pick_next_domain",
        "spiffe_attestor",
        "storage_manager",
        "summary_reporter",
    ]
    for node_name in spiffe_nodes:
        builder.add_node(node_name, get_node(node_name))

    builder.add_edge(START, "certificate_scanner")
    builder.add_edge("certificate_scanner", "renewal_planner")

    builder.add_conditional_edges(
        "renewal_planner",
        renewal_router,
        {
            "renewals_needed": "pick_next_domain",
            "no_renewals": "summary_reporter",
        },
    )

    builder.add_edge("pick_next_domain", "spiffe_attestor")
    builder.add_edge("spiffe_attestor", "storage_manager")

    builder.add_conditional_edges(
        "storage_manager",
        domain_loop_router,
        {
            "next_domain": "pick_next_domain",
            "all_done": "summary_reporter",
        },
    )

    builder.add_edge("summary_reporter", END)


def initial_state(
    managed_domains: list[str],
    cert_store_path: str = "./certs",
    account_key_path: str = "./account.key",
    renewal_threshold_days: int = 30,
    max_retries: int = 3,
    webroot_path: str | None = None,
) -> dict:
    """
    Build the initial AgentState dict for a fresh agent run.
    Callers can override any field by merging the returned dict.
    """
    return {
        "managed_domains": managed_domains,
        "renewal_threshold_days": renewal_threshold_days,
        "cert_store_path": cert_store_path,
        "account_key_path": account_key_path,
        "webroot_path": webroot_path,
        "cert_records": [],
        "pending_renewals": [],
        "current_domain": None,
        "current_order": None,
        "acme_account_url": None,
        "current_nonce": None,
        "messages": [],
        "renewal_plan": None,
        "error_analysis": None,
        "error_action": None,
        "completed_renewals": [],
        "failed_renewals": [],
        "error_log": [],
        "retry_count": 0,
        "retry_delay_seconds": 5,
        "retry_not_before": None,
        "max_retries": max_retries,
        "cert_metadata": {},
        "revocation_targets": [],
        "current_revocation_domain": None,
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
    }
