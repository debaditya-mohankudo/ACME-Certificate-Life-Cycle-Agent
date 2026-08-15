"""
Revocation subgraph — separate StateGraph for certificate revocation.

Topology:
  START
    → revocation_account_setup      [reuses acme_account_setup]
    → pick_next_revocation_domain   [new node: pops revocation_targets]
    → cert_revoker                  [new node: POST /revokeCert]
    → revocation_loop_router
      ├─(retry)→       retry_scheduler → cert_revoker [loop, same domain]
      ├─(next_domain)→ pick_next_revocation_domain     [loop, next domain]
      └─(all_done)→   revocation_reporter              [deterministic summary]
    → END

Retries are bounded and narrow: cert_revoker only retries errors it
classifies as transient (rate limiting, server-side 5xx, connection
failures — see agent/nodes/revoker.py); policy/protocol failures
(unauthorized, alreadyRevoked, malformed, missing local cert file) are
still logged and the loop moves straight to the next domain, unretried.
Exhausting the per-domain retry budget (max_retries) falls back to that
same best-effort behavior rather than aborting the whole run.
"""
from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from agent.nodes.registry import get_node
from agent.nodes.revocation_router import revocation_loop_router
from agent.state import AgentState


def build_revocation_graph(use_checkpointing: bool = False):
    """
    Build and compile the revocation StateGraph.

    Args:
        use_checkpointing: If True, attach a MemorySaver for resumable runs.

    Returns:
        CompiledGraph ready to invoke / stream.
    """
    builder = StateGraph(AgentState)

    # ── Register nodes from registry ──────────────────────────────────────
    revocation_nodes = [
        "revocation_account_setup",
        "pick_next_revocation_domain",
        "cert_revoker",
        "retry_scheduler",
        "revocation_reporter",
    ]
    for node_name in revocation_nodes:
        builder.add_node(node_name, get_node(node_name))

    # ── Deterministic edges ───────────────────────────────────────────────
    builder.add_edge(START, "revocation_account_setup")
    builder.add_edge("revocation_account_setup", "pick_next_revocation_domain")
    builder.add_edge("pick_next_revocation_domain", "cert_revoker")

    # After cert_revoker: retry (same domain), advance (next domain), or finish
    builder.add_conditional_edges(
        "cert_revoker",
        revocation_loop_router,
        {
            "retry": "retry_scheduler",
            "next_domain": "pick_next_revocation_domain",
            "all_done": "revocation_reporter",
        },
    )
    # Retry loops straight back to cert_revoker — current_revocation_domain
    # is preserved by cert_revoker on the retry path, so this does NOT go
    # through pick_next_revocation_domain (that would advance to the next
    # domain instead of retrying this one).
    builder.add_edge("retry_scheduler", "cert_revoker")

    builder.add_edge("revocation_reporter", END)

    # ── Compile ───────────────────────────────────────────────────────────
    checkpointer = MemorySaver() if use_checkpointing else None
    return builder.compile(checkpointer=checkpointer)


def revocation_initial_state(
    domains: list[str],
    reason: int,
    cert_store_path: str = "./certs",
    account_key_path: str = "./account.key",
    max_retries: int = 3,
) -> dict:
    """
    Build the initial AgentState dict for a revocation run.

    Args:
        domains: Domains to revoke
        reason: RFC 5280 reason code
        cert_store_path: Path to cert store
        account_key_path: Path to account key
        max_retries: Per-domain retry budget for transient cert_revoker
            failures (see agent/nodes/revoker.py). Same knob/default as the
            renewal graph's config.MAX_RETRIES.

    Returns:
        Minimal state with revocation_* fields initialized.
    """
    return {
        "managed_domains": domains,
        "renewal_threshold_days": 30,  # unused in revocation
        "cert_store_path": cert_store_path,
        "account_key_path": account_key_path,
        "webroot_path": None,
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
        "revocation_targets": domains,
        "current_revocation_domain": None,
        "revocation_reason": reason,
        "revoked_domains": [],
        "failed_revocations": [],
    }
