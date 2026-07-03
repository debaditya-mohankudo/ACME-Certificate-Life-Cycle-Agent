"""
domain_loop_router — conditional edge logic for the main renewal loop.

This is not a node itself but a routing function used with
graph.add_conditional_edges().  It decides whether to:
  - Process the next pending domain (loop back to order_initializer)
  - Go to the summary reporter (all domains done)
"""
from __future__ import annotations

from agent.state import AgentState

from logger import logger


class PickNextDomainNode:
    """Callable domain router implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        """
        Node that pops the next domain from pending_renewals and sets current_domain.
        Also resets per-domain state (retry_count, current_order, current_nonce).
        """
        pending = list(state.get("pending_renewals", []))
        if not pending:
            return {}

        next_domain = pending[0]
        remaining = pending[1:]

        logger.info("Starting renewal for domain: %s", next_domain)
        return {
            "current_domain": next_domain,
            "pending_renewals": remaining,
            "current_order": None,
            "current_nonce": None,
            "retry_count": 0,
            "retry_delay_seconds": 5,
        }


# ─── Compatibility wrapper ────────────────────────────────────────────────────


def pick_next_domain(state: AgentState) -> dict:
    """Compatibility wrapper delegating to PickNextDomainNode."""
    return PickNextDomainNode().run(state)


def domain_loop_router(state: AgentState) -> str:
    """
    Routing function for add_conditional_edges().

    Returns:
      "next_domain"  — more domains to process
      "all_done"     — no more pending, go to reporter
    """
    pending = state.get("pending_renewals", [])
    current = state.get("current_domain")

    if pending:
        return "next_domain"
    return "all_done"


def spiffe_attestation_router(state: AgentState) -> str:
    """
    After spiffe_attestor: route to storage_manager (attestation produced an
    SVID) — or, on failure, skip storage_manager entirely and make the same
    next_domain/all_done decision domain_loop_router would make after a
    successful store. A failed attestation has no current_order to store,
    and routing it through storage_manager anyway would double-count the
    same domain into failed_renewals/error_log.

    Must not route failures unconditionally back to pick_next_domain: if
    the failed domain was the last one pending, pick_next_domain would
    no-op on an empty list and spiffe_attestor would replay the same
    stale current_domain forever, never reaching summary_reporter. So on
    failure this inlines domain_loop_router's own decision rather than
    delegating a second hop to it.

    Returns: "attestation_ok" | "next_domain" | "all_done"
    """
    current = state.get("current_domain")
    if current is not None and current in state.get("failed_renewals", []):
        return domain_loop_router(state)
    return "attestation_ok"


def challenge_router(state: AgentState) -> str:
    """
    After challenge_verifier: route to csr_generator (success) or
    error_handler (failure).

    Returns: "challenge_ok" | "challenge_failed"
    """
    order = state.get("current_order") or {}
    if order.get("status") == "invalid":
        return "challenge_failed"
    return "challenge_ok"


def renewal_router(state: AgentState) -> str:
    """
    After planner: route to acme_account_setup (renewals needed) or
    directly to summary_reporter (nothing to do).

    Returns: "renewals_needed" | "no_renewals"
    """
    pending = state.get("pending_renewals", [])
    return "renewals_needed" if pending else "no_renewals"


def error_action_router(state: AgentState) -> str:
    """
    After error_handler: route on the "retry" | "skip" | "abort" decision
    error_handler set directly in state["error_action"] (a plain field, not
    JSON-encoded text — error_handler.py's error_analysis is human-readable
    prose, never machine-parseable, so this router must never re-parse it).

    Returns: "retry" | "skip_domain" | "abort"
    """
    action = state.get("error_action")
    domain = state.get("current_domain", "unknown")

    if action not in ("retry", "skip", "abort"):
        logger.warning(
            "error_action_router: missing or unrecognized error_action=%r for %s — defaulting to skip_domain",
            action, domain,
        )
        return "skip_domain"

    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)

    if action == "retry" and retry_count < max_retries:
        logger.info("error_action_router: RETRY for %s (%d/%d)", domain, retry_count, max_retries)
        return "retry"
    elif action == "abort":
        logger.info("error_action_router: ABORT for %s", domain)
        return "abort"
    else:
        logger.info(
            "error_action_router: SKIP for %s (action=%s, retry_count=%d/%d)",
            domain, action, retry_count, max_retries,
        )
        return "skip_domain"
