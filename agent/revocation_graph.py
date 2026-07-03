"""
Revocation subgraph — separate StateGraph for certificate revocation.

Topology:
  START
    → revocation_account_setup      [reuses acme_account_setup]
    → pick_next_revocation_domain   [new node: pops revocation_targets]
    → cert_revoker                  [new node: POST /revokeCert]
    → revocation_loop_router
      ├─(next_domain)→ pick_next_revocation_domain  [loop]
      └─(all_done)→   revocation_reporter           [LLM summary]
    → END

No error_handler/retry in the revocation graph — failures are logged and
the loop continues (revocation is best-effort).
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
        "revocation_reporter",
    ]
    for node_name in revocation_nodes:
        builder.add_node(node_name, get_node(node_name))

    # ── Deterministic edges ───────────────────────────────────────────────
    builder.add_edge(START, "revocation_account_setup")
    builder.add_edge("revocation_account_setup", "pick_next_revocation_domain")
    builder.add_edge("pick_next_revocation_domain", "cert_revoker")

    # After cert_revoker: route based on remaining revocation_targets
    builder.add_conditional_edges(
        "cert_revoker",
        revocation_loop_router,
        {
            "next_domain": "pick_next_revocation_domain",
            "all_done": "revocation_reporter",
        },
    )

    builder.add_edge("revocation_reporter", END)

    # ── Compile ───────────────────────────────────────────────────────────
    checkpointer = MemorySaver() if use_checkpointing else None
    return builder.compile(checkpointer=checkpointer)


def revocation_initial_state(
    domains: list[str],
    reason: int,
    cert_store_path: str = "./certs",
    account_key_path: str = "./account.key",
) -> dict:
    """
    Build the initial AgentState dict for a revocation run.

    Args:
        domains: Domains to revoke
        reason: RFC 5280 reason code
        cert_store_path: Path to cert store
        account_key_path: Path to account key

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
        "max_retries": 0,
        "cert_metadata": {},
        "revocation_targets": domains,
        "current_revocation_domain": None,
        "revocation_reason": reason,
        "revoked_domains": [],
        "failed_revocations": [],
    }
