"""
Revocation graph routing nodes.

pick_next_revocation_domain — pops the next domain from revocation_targets.
revocation_loop_router — routes between next domain and completion.
"""
from __future__ import annotations

from agent.state import AgentState

from logger import logger


class PickNextRevocationDomainNode:
    """Callable revocation domain router implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        """
        Pop the next domain from revocation_targets and set current_revocation_domain.
        Also clear current_nonce so the next cert_revoker invocation fetches a fresh one.

        If revocation_targets is empty, this node should not be called (the router
        should have routed to all_done).
        """
        targets = list(state.get("revocation_targets", []))
        if not targets:
            logger.warning("pick_next_revocation_domain called with empty revocation_targets")
            return {}

        next_domain = targets[0]
        remaining = targets[1:]

        logger.info("Starting revocation for domain: %s", next_domain)
        return {
            "current_revocation_domain": next_domain,
            "revocation_targets": remaining,
            "current_nonce": None,  # Clear so cert_revoker fetches a fresh nonce
            "retry_count": 0,       # retry budget is per-domain, not per-run
            "retry_delay_seconds": 5,
        }


# ─── Compatibility wrapper ────────────────────────────────────────────────────


def pick_next_revocation_domain(state: AgentState) -> dict:
    """Compatibility wrapper delegating to PickNextRevocationDomainNode."""
    return PickNextRevocationDomainNode().run(state)


def revocation_loop_router(state: AgentState) -> str:
    """
    Routing function for add_conditional_edges() from cert_revoker.

    Returns:
      "retry"        — cert_revoker scheduled a retry for the CURRENT domain
                        (retry_not_before is set); route to retry_scheduler,
                        which loops back to cert_revoker for the same domain.
      "next_domain"  — more domains to revoke in revocation_targets
      "all_done"     — no more revocation targets, go to reporter
    """
    if state.get("retry_not_before") is not None:
        return "retry"
    targets = state.get("revocation_targets", [])
    if targets:
        return "next_domain"
    return "all_done"
