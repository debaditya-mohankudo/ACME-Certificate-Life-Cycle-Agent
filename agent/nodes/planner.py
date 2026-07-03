"""
renewal_planner node — analyzes scan results, writes a renewal plan,
and populates pending_renewals in priority order.

Uses an LLM to classify domains into urgent/routine/skip when LLM_DISABLED
is False; otherwise falls back to the deterministic priority order: no-cert
domains first, then expiring-soon sorted by days ascending.

Output validation: ensures every domain in LLM JSON output is in managed_domains.
"""
from __future__ import annotations

import config
import json
from typing import Any

from agent.state import AgentState

from logger import logger


class RenewalPlannerNode:
    """Callable renewal planner implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        """
        Renewal planner: produce a renewal plan from cert_records.
        Uses LLM if LLM_DISABLED=False, otherwise deterministic logic.
        Returns: renewal_plan (str), pending_renewals (list[str]), messages update.
        """
        if config.settings.LLM_DISABLED:
            return self._run_deterministic(state)
        else:
            return self._run_llm(state)

    def _run_llm(self, state: AgentState) -> dict:
        """LLM-based renewal planner."""
        from langchain_core.messages import HumanMessage, SystemMessage

        from agent.prompts import PLANNER_SYSTEM, PLANNER_USER
        from llm.factory import make_llm

        cert_records = state["cert_records"]
        managed_domains = set(state["managed_domains"])
        threshold = state["renewal_threshold_days"]

        lines = []
        for rec in cert_records:
            if rec["days_until_expiry"] is None:
                lines.append(f"  {rec['domain']} → no certificate found (needs renewal)")
            else:
                lines.append(
                    f"  {rec['domain']} → expires {rec['expiry_date'][:10]} "
                    f"({rec['days_until_expiry']} days)"
                )
        cert_summary = "\n".join(lines)

        llm = make_llm(model=config.settings.LLM_MODEL_PLANNER, max_tokens=512)

        messages = [
            SystemMessage(content=PLANNER_SYSTEM),
            HumanMessage(
                content=PLANNER_USER.format(
                    cert_summary=cert_summary,
                    managed_domains=", ".join(sorted(managed_domains)),
                    threshold=threshold,
                )
            ),
        ]

        response = llm.invoke(messages)
        raw = response.content.strip()
        logger.debug("Planner LLM raw response: %s", raw)

        plan = _parse_and_validate(raw, managed_domains)

        pending: list[str] = plan.get("urgent", []) + plan.get("routine", [])

        return {
            "renewal_plan": raw,
            "pending_renewals": pending,
            "messages": messages + [response],
        }

    def _run_deterministic(self, state: AgentState) -> dict:
        """
        Deterministic renewal planner when LLM is disabled.
        Renews ALL domains expiring within threshold + domains with no certificate.
        """
        cert_records = state["cert_records"]
        managed_domains = set(state["managed_domains"])
        threshold = state["renewal_threshold_days"]

        pending_renewals = _renewal_planner_deterministic(cert_records, managed_domains, threshold)

        renewed_count = len(pending_renewals)
        skipped_count = len(managed_domains) - renewed_count

        plan_summary = (
            f"Deterministic renewal plan (LLM disabled):\n"
            f"- Threshold: {threshold} days\n"
            f"- Renewing: {renewed_count} domains\n"
            f"- Skipping: {skipped_count} domains\n"
            f"- Order: no-cert domains first, then by expiry date"
        )

        logger.info("Renewal planner: %s", plan_summary)

        return {
            "renewal_plan": plan_summary,
            "pending_renewals": pending_renewals,
            "messages": [],  # No LLM messages in deterministic mode
        }


def renewal_planner(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `RenewalPlannerNode`."""
    return RenewalPlannerNode().run(state)


def _renewal_planner_deterministic(cert_records, managed_domains, threshold_days):
    """
    Deterministic renewal planner when LLM is disabled.

    Args:
        cert_records: List of certificate records from scanner
        managed_domains: Set of domains under management
        threshold_days: Renewal threshold

    Returns:
        pending_renewals: list[str] in deterministic order.
        Order: [no_cert_domains, expiring_soon_domains_by_date]
    """
    no_cert = []
    expiring_soon = []

    for rec in cert_records:
        domain = rec["domain"]
        days = rec["days_until_expiry"]

        if days is None:
            # No certificate found - always renew
            no_cert.append(domain)
        elif days <= threshold_days:
            # Certificate expiring within threshold - renew
            expiring_soon.append((domain, days, rec["expiry_date"]))

    # Sort expiring_soon by days ascending (closest expiry first)
    expiring_soon.sort(key=lambda x: (x[1], x[2]))
    expiring_soon_domains = [d for d, _, _ in expiring_soon]

    # Return order: no_cert_domains first, then expiring_soon
    return no_cert + expiring_soon_domains


def _parse_and_validate(raw: str, managed_domains: set[str]) -> dict[str, Any]:
    """
    Parse LLM JSON output and validate that all domains are from managed_domains.
    Falls back to a safe default on any parse failure.
    """
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Planner returned invalid JSON — falling back to renew all")
        return {"urgent": [], "routine": list(managed_domains), "skip": [], "notes": "JSON parse failed"}

    # Validate: strip any hallucinated domains not in the managed list
    for key in ("urgent", "routine", "skip"):
        original = plan.get(key, [])
        validated = [d for d in original if d in managed_domains]
        if len(validated) != len(original):
            removed = set(original) - set(validated)
            logger.warning(
                "Planner hallucinated domains — removing: %s", removed
            )
        plan[key] = validated

    # Ensure every managed domain appears in exactly one bucket
    accounted = set(plan.get("urgent", [])) | set(plan.get("routine", [])) | set(plan.get("skip", []))
    missing = managed_domains - accounted
    if missing:
        logger.warning("Planner did not classify domains %s — adding to routine", missing)
        plan.setdefault("routine", []).extend(sorted(missing))

    return plan
