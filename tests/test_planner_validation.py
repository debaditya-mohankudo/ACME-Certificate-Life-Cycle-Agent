"""
Tests for planner node validation logic: hallucinated domain stripping,
missing domain recovery, and JSON parse failure handling.

Tests the private _parse_and_validate function and the renewal_planner node
with mocked LLMs to ensure LLM output is validated correctly.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage
import pytest

from agent.nodes.planner import _parse_and_validate, renewal_planner
import config


# ── Constants ──────────────────────────────────────────────────────────────

DOMAIN_A = "api.example.com"
DOMAIN_B = "shop.example.com"
MANAGED = {DOMAIN_A, DOMAIN_B}


def _mock_llm_response(content: str) -> MagicMock:
    """Return a mock LLM that responds with the given content."""
    llm = MagicMock()
    llm.invoke.return_value = AIMessage(content=content)
    return llm


@pytest.fixture(autouse=True)
def _ensure_llm_enabled():
    """Ensure LLM_DISABLED is False for all tests in this module (LLM-based tests)."""
    original = config.settings.LLM_DISABLED
    config.settings.LLM_DISABLED = False
    yield
    config.settings.LLM_DISABLED = original


def _make_state(domains: list[str], threshold: int = 30) -> dict:
    """Build a minimal AgentState-compatible dict for testing renewal_planner."""
    return {
        "managed_domains": domains,
        "cert_records": [
            {
                "domain": d,
                "days_until_expiry": threshold - 1,
                "expiry_date": "2026-03-15",
                "needs_renewal": True,
                "cert_path": None,
                "key_path": None,
            }
            for d in domains
        ],
        "renewal_threshold_days": threshold,
        "messages": [],
    }


# ── Tests: _parse_and_validate (pure function) ─────────────────────────────


class TestParseAndValidate:
    """Test the _parse_and_validate function in isolation."""

    def test_invalid_json_falls_back_to_renew_all(self):
        """When LLM returns invalid JSON, fallback is to renew all managed domains."""
        raw = "this is not json at all!!"
        result = _parse_and_validate(raw, MANAGED)

        assert result["urgent"] == []
        assert set(result["routine"]) == MANAGED
        assert result["skip"] == []
        assert result["notes"] == "JSON parse failed"

    def test_markdown_fenced_json_is_parsed_not_fallen_back(self):
        """Regression for task:df13bec8 — some providers (observed with
        claude -p) wrap JSON output in ```json ... ``` fences despite being
        told not to. This must be stripped and parsed, not treated as a
        parse failure."""
        raw = "```json\n" + json.dumps({
            "urgent": [DOMAIN_A],
            "routine": [DOMAIN_B],
            "skip": [],
        }) + "\n```"
        result = _parse_and_validate(raw, MANAGED)

        assert result["urgent"] == [DOMAIN_A]
        assert result["routine"] == [DOMAIN_B]

    def test_hallucinated_domain_in_urgent_stripped(self):
        """Hallucinated domain in urgent bucket is removed."""
        raw = json.dumps({
            "urgent": ["evil.com"],
            "routine": [DOMAIN_A],
            "skip": [DOMAIN_B],
        })
        result = _parse_and_validate(raw, MANAGED)

        assert result["urgent"] == []
        assert result["routine"] == [DOMAIN_A]
        assert result["skip"] == [DOMAIN_B]

    def test_hallucinated_domain_in_routine_stripped(self):
        """Hallucinated domain in routine bucket is removed."""
        raw = json.dumps({
            "urgent": [],
            "routine": ["evil.com", DOMAIN_A],
            "skip": [DOMAIN_B],
        })
        result = _parse_and_validate(raw, MANAGED)

        assert result["routine"] == [DOMAIN_A]

    def test_hallucinated_domain_in_skip_stripped(self):
        """Hallucinated domain in skip bucket is removed."""
        raw = json.dumps({
            "urgent": [DOMAIN_A, DOMAIN_B],
            "routine": [],
            "skip": ["evil.com"],
        })
        result = _parse_and_validate(raw, MANAGED)

        assert result["skip"] == []
        assert set(result["urgent"]) == MANAGED

    def test_mixed_real_and_hallucinated_preserves_real(self):
        """When urgent contains both real and hallucinated domains, only real survive."""
        raw = json.dumps({
            "urgent": ["evil.com", DOMAIN_A],
            "routine": [DOMAIN_B],
            "skip": [],
        })
        result = _parse_and_validate(raw, MANAGED)

        assert result["urgent"] == [DOMAIN_A]
        assert result["routine"] == [DOMAIN_B]

    def test_lookalike_domain_stripped(self):
        """Domain that looks similar but doesn't exactly match is stripped."""
        raw = json.dumps({
            "urgent": ["api.example.com.evil.com"],
            "routine": [DOMAIN_A, DOMAIN_B],
            "skip": [],
        })
        result = _parse_and_validate(raw, MANAGED)

        assert "api.example.com.evil.com" not in result["urgent"]
        assert set(result["routine"]) == MANAGED

    def test_missing_domain_added_to_routine(self):
        """When a managed domain isn't classified, it's added to routine."""
        raw = json.dumps({
            "urgent": [],
            "routine": [DOMAIN_A],
            "skip": [],
        })
        result = _parse_and_validate(raw, MANAGED)

        assert DOMAIN_B in result["routine"]

    def test_all_missing_domains_added_to_routine(self):
        """When planner returns empty buckets, all managed domains go to routine."""
        raw = json.dumps({
            "urgent": [],
            "routine": [],
            "skip": [],
        })
        result = _parse_and_validate(raw, MANAGED)

        assert set(result["routine"]) == MANAGED
        assert result["urgent"] == []
        assert result["skip"] == []

    def test_all_hallucinated_triggers_missing_domain_fallback(self):
        """When all buckets contain only hallucinations, missing domain logic adds all."""
        raw = json.dumps({
            "urgent": ["evil.com"],
            "routine": ["attacker.io"],
            "skip": ["hacker.net"],
        })
        result = _parse_and_validate(raw, MANAGED)

        # All hallucinations stripped → all managed domains missing → added to routine
        assert set(result["routine"]) == MANAGED
        assert result["urgent"] == []
        assert result["skip"] == []

    def test_malformed_object_item_does_not_crash(self):
        """Regression for task:df13bec8 — a small/less-compliant LLM (observed
        with qwen2.5:3b) can return well-formed JSON with the wrong item shape,
        e.g. {"domain": "..."} objects instead of plain domain strings. This
        must degrade gracefully (drop + backfill), never crash with
        TypeError: unhashable type: 'dict'."""
        raw = json.dumps({
            "urgent": [{"domain": DOMAIN_A}],
            "routine": [],
            "skip": [],
        })
        result = _parse_and_validate(raw, MANAGED)

        # The malformed entry is dropped, not crashed on...
        assert result["urgent"] == []
        # ...and the domain it named still ends up classified via the
        # missing-domain backfill, not silently dropped.
        assert set(result["routine"]) == MANAGED

    def test_mixed_valid_and_malformed_items_in_same_bucket(self):
        """A malformed item alongside valid ones only drops the malformed
        one — the valid domain string survives."""
        raw = json.dumps({
            "urgent": [DOMAIN_A, {"domain": DOMAIN_B}],
            "routine": [],
            "skip": [],
        })
        result = _parse_and_validate(raw, MANAGED)

        assert result["urgent"] == [DOMAIN_A]
        assert set(result["routine"]) == {DOMAIN_B}


# ── Tests: renewal_planner node ────────────────────────────────────────────


class TestRenewalPlannerNode:
    """Test renewal_planner node with mocked LLM."""

    def test_planner_node_strips_hallucinated_from_pending_renewals(self):
        """Hallucinated domains never reach pending_renewals."""
        llm_response = json.dumps({
            "urgent": ["evil.com", DOMAIN_A],
            "routine": [],
            "skip": [],
        })

        state = _make_state([DOMAIN_A])

        with patch("llm.factory.make_llm", return_value=_mock_llm_response(llm_response)):
            result = renewal_planner(state)

        assert result["pending_renewals"] == [DOMAIN_A]
        assert "evil.com" not in result["pending_renewals"]

    def test_planner_node_invalid_json_queues_all_domains(self):
        """When LLM returns invalid JSON, all managed domains are queued."""
        llm_response = "BROKEN OUTPUT NOT JSON!!!"

        state = _make_state([DOMAIN_A, DOMAIN_B])

        with patch("llm.factory.make_llm", return_value=_mock_llm_response(llm_response)):
            result = renewal_planner(state)

        assert set(result["pending_renewals"]) == {DOMAIN_A, DOMAIN_B}

    def test_planner_node_urgent_before_routine_in_pending(self):
        """Urgent domains appear before routine domains in pending_renewals."""
        llm_response = json.dumps({
            "urgent": [DOMAIN_B],
            "routine": [DOMAIN_A],
            "skip": [],
        })

        state = _make_state([DOMAIN_A, DOMAIN_B])

        with patch("llm.factory.make_llm", return_value=_mock_llm_response(llm_response)):
            result = renewal_planner(state)

        assert result["pending_renewals"] == [DOMAIN_B, DOMAIN_A]
