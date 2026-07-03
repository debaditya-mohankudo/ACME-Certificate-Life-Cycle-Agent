"""
error_handler node — analyze a renewal failure and decide: retry, skip, or abort.

Decision rules (deterministic):
- Fatal ACME errors (unauthorized, account missing, bad key, EAB required) → abort
- retry_count < max_retries → retry with exponential backoff (cap 300s)
- retry_count >= max_retries → skip domain
"""
from __future__ import annotations

import time

from agent.state import AgentState
from logger import logger

# ACME error types that indicate a configuration/auth problem that retrying cannot fix.
_FATAL_ERROR_PATTERNS = (
    "unauthorized",
    "accountdoesnotexist",
    "badkey",
    "externalaccountrequired",
)


def _is_fatal_error(error_text: str) -> bool:
    lower = error_text.lower()
    return any(pat in lower for pat in _FATAL_ERROR_PATTERNS)


class ErrorHandlerNode:
    """Callable error-handler implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        domain = state.get("current_domain", "unknown")
        error_log = state.get("error_log", [])
        last_error = error_log[-1] if error_log else "Unknown error"
        retry_count = state.get("retry_count", 0)
        max_retries = state.get("max_retries", 3)
        retry_delay = state.get("retry_delay_seconds", 5)

        if _is_fatal_error(last_error):
            action = "abort"
            new_delay = 0
        else:
            action, new_delay = _error_handler_deterministic(retry_count, max_retries, retry_delay)

        analysis = (
            f"Deterministic error handler:\n"
            f"Domain: {domain}\n"
            f"Error: {last_error}\n"
            f"Retry count: {retry_count}/{max_retries}\n"
            f"Action: {action.upper()}"
        )
        if action == "retry":
            analysis += f"\nBackoff delay: {new_delay}s"

        logger.info("Error handler: %s for %s", action.upper(), domain)

        updates: dict = {
            "error_analysis": analysis,
            "error_action": action,
            "messages": [],
        }

        if action == "retry":
            new_retry_count = retry_count + 1
            now = time.time()
            retry_not_before = now + new_delay
            logger.info(
                "Error handler: RETRY #%d for %s (backoff %ds, retry at %d)",
                new_retry_count, domain, new_delay, int(retry_not_before),
            )
            updates["retry_count"] = new_retry_count
            updates["retry_delay_seconds"] = new_delay
            updates["retry_not_before"] = retry_not_before

        elif action == "abort":
            logger.error("Error handler: ABORT — fatal error, stopping all renewals: %s", last_error)
            pending = state.get("pending_renewals", [])
            failed = state.get("failed_renewals", []) + [domain] + list(pending)
            updates["failed_renewals"] = failed
            updates["pending_renewals"] = []
            updates["retry_not_before"] = None

        else:  # skip
            logger.warning("Error handler: SKIP domain %s (max retries reached)", domain)
            updates["failed_renewals"] = state.get("failed_renewals", []) + [domain]
            updates["retry_not_before"] = None

        return updates


def _error_handler_deterministic(retry_count: int, max_retries: int, retry_delay_seconds: int):
    """
    Returns (action, delay_seconds).
    Retry with exponential backoff (capped at 300s) until max_retries, then skip.
    """
    if retry_count < max_retries:
        exponent = retry_count + 1
        new_delay = min(retry_delay_seconds * (2 ** exponent), 300)
        return "retry", int(new_delay)
    return "skip", 0


def error_handler(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `ErrorHandlerNode`."""
    return ErrorHandlerNode().run(state)
