"""
Unit tests for agent/nodes/error_handler.py (deterministic).

Tests: retry with exponential backoff, skip on max retries, abort on fatal errors.
"""
from __future__ import annotations

from typing import cast

from agent.nodes.error_handler import ErrorHandlerNode, _error_handler_deterministic, _is_fatal_error
from agent.state import AgentState


def _base_state(**overrides) -> dict:
    state: dict = {
        "current_domain": "example.com",
        "current_order": {"status": "invalid"},
        "error_log": ["ACME returned 400"],
        "retry_count": 0,
        "max_retries": 3,
        "retry_delay_seconds": 5,
        "failed_renewals": [],
        "pending_renewals": ["example.com"],
        "messages": [],
    }
    state.update(overrides)
    return cast("AgentState", state)


# ─── retry action ─────────────────────────────────────────────────────────────


def test_retries_while_under_max_retries():
    """Returns retry action when retry_count < max_retries."""
    result = ErrorHandlerNode().run(_base_state(retry_count=0, max_retries=3))

    assert result["retry_count"] == 1
    assert "retry" in result["error_analysis"].lower()


def test_retry_increments_retry_count():
    """Each retry increments the retry_count."""
    for current_count in [0, 1, 2]:
        result = ErrorHandlerNode().run(_base_state(retry_count=current_count, max_retries=3))
        assert result["retry_count"] == current_count + 1


def test_retry_sets_retry_not_before():
    """Retry action sets retry_not_before timestamp."""
    result = ErrorHandlerNode().run(_base_state(retry_count=0, max_retries=3))

    assert "retry_not_before" in result
    assert result["retry_not_before"] > 0


def test_retry_updates_retry_delay():
    """Retry action updates retry_delay_seconds with exponential backoff."""
    result = ErrorHandlerNode().run(_base_state(retry_count=0, max_retries=3, retry_delay_seconds=5))

    # 5 * 2^(0+1) = 10
    assert result["retry_delay_seconds"] == 10


# ─── Exponential backoff ────────────────────────────────────────────────────


def test_exponential_backoff_delay_retry_0():
    result = ErrorHandlerNode().run(_base_state(retry_count=0, retry_delay_seconds=5))
    assert result["retry_delay_seconds"] == 10  # 5 * 2^1


def test_exponential_backoff_delay_retry_1():
    result = ErrorHandlerNode().run(_base_state(retry_count=1, retry_delay_seconds=5))
    assert result["retry_delay_seconds"] == 20  # 5 * 2^2


def test_exponential_backoff_delay_retry_2():
    result = ErrorHandlerNode().run(_base_state(retry_count=2, retry_delay_seconds=5))
    assert result["retry_delay_seconds"] == 40  # 5 * 2^3


def test_exponential_backoff_delay_retry_3():
    result = ErrorHandlerNode().run(_base_state(retry_count=3, retry_delay_seconds=5, max_retries=4))
    assert result["retry_delay_seconds"] == 80  # 5 * 2^4


def test_exponential_backoff_with_different_base_delay():
    result = ErrorHandlerNode().run(_base_state(retry_count=1, retry_delay_seconds=10, max_retries=3))
    assert result["retry_delay_seconds"] == 40  # 10 * 2^2


# ─── Delay cap ─────────────────────────────────────────────────────────────


def test_delay_capped_at_300_seconds():
    result = ErrorHandlerNode().run(_base_state(retry_count=10, retry_delay_seconds=5, max_retries=11))
    assert result["retry_delay_seconds"] == 300
    assert result["retry_delay_seconds"] <= 300


def test_delay_cap_approaching_300():
    result = ErrorHandlerNode().run(_base_state(retry_count=8, retry_delay_seconds=5, max_retries=9))
    assert result["retry_delay_seconds"] == 300


# ─── skip action ───────────────────────────────────────────────────────────


def test_skips_when_max_retries_exceeded():
    result = ErrorHandlerNode().run(_base_state(retry_count=3, max_retries=3))

    assert "failed_renewals" in result
    assert "example.com" in result["failed_renewals"]
    assert "skip" in result["error_analysis"].lower()


def test_skip_adds_domain_to_failed_renewals():
    result = ErrorHandlerNode().run(
        _base_state(retry_count=3, max_retries=3, failed_renewals=["other.example.com"])
    )

    assert "example.com" in result["failed_renewals"]
    assert "other.example.com" in result["failed_renewals"]


def test_skip_does_not_set_retry_fields():
    result = ErrorHandlerNode().run(_base_state(retry_count=3, max_retries=3))

    assert "retry_count" not in result or result.get("retry_count") == 3
    assert result.get("retry_not_before") is None


# ─── abort action (fatal errors) ───────────────────────────────────────────


def test_aborts_on_unauthorized_error():
    """unauthorized error triggers abort, draining pending_renewals."""
    state = _base_state(
        retry_count=0,
        max_retries=3,
        error_log=["ACME 401: urn:ietf:params:acme:error:unauthorized — account key mismatch"],
        pending_renewals=["other1.com", "other2.com"],
    )
    result = ErrorHandlerNode().run(state)

    assert result["pending_renewals"] == []
    assert "example.com" in result["failed_renewals"]
    assert "other1.com" in result["failed_renewals"]
    assert "abort" in result["error_analysis"].lower()


def test_aborts_on_account_does_not_exist():
    state = _base_state(
        error_log=["ACME 400: accountDoesNotExist — account not registered"],
    )
    result = ErrorHandlerNode().run(state)

    assert result["pending_renewals"] == []
    assert "abort" in result["error_analysis"].lower()


def test_aborts_on_bad_key():
    state = _base_state(error_log=["ACME 400: badKey — malformed account key"])
    result = ErrorHandlerNode().run(state)

    assert result["pending_renewals"] == []


def test_aborts_on_external_account_required():
    state = _base_state(error_log=["ACME 400: externalAccountRequired — EAB required"])
    result = ErrorHandlerNode().run(state)

    assert result["pending_renewals"] == []


def test_abort_clears_retry_not_before():
    state = _base_state(error_log=["ACME 401: unauthorized — key mismatch"])
    result = ErrorHandlerNode().run(state)

    assert result.get("retry_not_before") is None


def test_non_fatal_error_does_not_abort():
    """Transient errors (network, server error) follow retry/skip logic."""
    state = _base_state(
        retry_count=0,
        max_retries=3,
        error_log=["ACME 500: serverInternal — try again later"],
    )
    result = ErrorHandlerNode().run(state)

    assert "retry_count" in result
    assert result["retry_count"] == 1


# ─── fatal error detection ─────────────────────────────────────────────────


def test_is_fatal_error_unauthorized():
    assert _is_fatal_error("ACME 401: unauthorized — key mismatch") is True


def test_is_fatal_error_case_insensitive():
    assert _is_fatal_error("ACME 400: Unauthorized") is True


def test_is_fatal_error_transient_returns_false():
    assert _is_fatal_error("ACME 500: serverInternal — internal error") is False
    assert _is_fatal_error("ACME 400: badNonce — use fresh nonce") is False


# ─── error analysis text ───────────────────────────────────────────────────


def test_error_analysis_is_readable_text():
    result = ErrorHandlerNode().run(_base_state(retry_count=1, max_retries=3))

    analysis = result["error_analysis"]
    assert isinstance(analysis, str)
    assert not analysis.startswith("{")
    assert "deterministic" in analysis.lower()


def test_error_analysis_contains_domain():
    result = ErrorHandlerNode().run(_base_state(current_domain="api.example.com"))

    assert "api.example.com" in result["error_analysis"]


def test_error_analysis_contains_error_message():
    result = ErrorHandlerNode().run(
        _base_state(error_log=["ACME returned 403: forbidden"], retry_count=0, max_retries=3)
    )

    assert "403" in result["error_analysis"] or "forbidden" in result["error_analysis"].lower()


def test_no_llm_messages_returned():
    result = ErrorHandlerNode().run(_base_state(retry_count=0, max_retries=3))

    assert result["messages"] == []


# ─── _error_handler_deterministic function ─────────────────────────────────


def test_deterministic_function_retry():
    action, delay = _error_handler_deterministic(retry_count=0, max_retries=3, retry_delay_seconds=5)
    assert action == "retry"
    assert delay == 10


def test_deterministic_function_skip():
    action, delay = _error_handler_deterministic(retry_count=3, max_retries=3, retry_delay_seconds=5)
    assert action == "skip"
    assert delay == 0


def test_deterministic_function_cap():
    action, delay = _error_handler_deterministic(retry_count=10, max_retries=11, retry_delay_seconds=5)
    assert action == "retry"
    assert delay == 300


# ─── error_action (plain field consumed directly by error_action_router) ──────
# Regression coverage for task:06284d87 — error_action_router must never
# re-parse error_analysis (prose, not JSON); error_handler must always also
# set error_action as a plain string.


def test_retry_sets_error_action():
    result = ErrorHandlerNode().run(_base_state(retry_count=0, max_retries=3, current_order=None))
    assert result["error_action"] == "retry"


def test_skip_sets_error_action():
    result = ErrorHandlerNode().run(_base_state(retry_count=3, max_retries=3, current_order=None))
    assert result["error_action"] == "skip"


def test_abort_sets_error_action():
    result = ErrorHandlerNode().run(_base_state(
        error_log=["urn:ietf:params:acme:error:unauthorized"], current_order=None,
    ))
    assert result["error_action"] == "abort"
