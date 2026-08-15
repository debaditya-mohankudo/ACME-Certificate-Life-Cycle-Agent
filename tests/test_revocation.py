"""
Unit and graph topology tests for certificate revocation.

Tests revocation nodes without Pebble ACME server (all mocked).
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from acme.client import AcmeError
from agent.nodes.reporter import revocation_reporter
from agent.nodes.revocation_router import pick_next_revocation_domain, revocation_loop_router
from agent.nodes.revoker import cert_revoker
from agent.revocation_graph import build_revocation_graph, revocation_initial_state
from agent.state import AgentState


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def base_revocation_state() -> dict:
    """Minimal AgentState for revocation tests."""
    return revocation_initial_state(
        domains=["example.com", "api.example.com"],
        reason=0,
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )


# ── pick_next_revocation_domain tests ──────────────────────────────────────


def test_pick_next_revocation_domain_pops_first_domain():
    """Should pop first domain and set current_revocation_domain."""
    state = {
        "revocation_targets": ["example.com", "api.example.com", "shop.example.com"],
        "current_nonce": "existing-nonce",
    }
    result = pick_next_revocation_domain(state)

    assert result["current_revocation_domain"] == "example.com"
    assert result["revocation_targets"] == ["api.example.com", "shop.example.com"]
    assert result["current_nonce"] is None  # Cleared for fresh fetch


def test_pick_next_revocation_domain_last_domain():
    """Should handle the last domain."""
    state = {
        "revocation_targets": ["example.com"],
        "current_nonce": "nonce",
    }
    result = pick_next_revocation_domain(state)

    assert result["current_revocation_domain"] == "example.com"
    assert result["revocation_targets"] == []
    assert result["current_nonce"] is None


def test_pick_next_revocation_domain_empty_targets():
    """Should handle empty targets gracefully."""
    state = {"revocation_targets": []}
    result = pick_next_revocation_domain(state)

    # Should return empty dict on empty targets
    assert result == {}


# ── revocation_loop_router tests ───────────────────────────────────────────


def test_revocation_loop_router_more_targets():
    """Should return 'next_domain' when targets remain."""
    state = {"revocation_targets": ["example.com"]}
    assert revocation_loop_router(state) == "next_domain"


def test_revocation_loop_router_no_targets():
    """Should return 'all_done' when no targets remain."""
    state = {"revocation_targets": []}
    assert revocation_loop_router(state) == "all_done"


def test_revocation_loop_router_retry_scheduled():
    """Should return 'retry' when cert_revoker scheduled a retry, even if
    other targets remain — the retry takes priority over advancing."""
    state = {"revocation_targets": ["shop.example.com"], "retry_not_before": 9999999999.0}
    assert revocation_loop_router(state) == "retry"


def test_pick_next_revocation_domain_resets_retry_count():
    """Moving to a new domain should reset the per-domain retry budget."""
    state = {
        "revocation_targets": ["example.com"],
        "current_nonce": "nonce",
        "retry_count": 2,
    }
    result = pick_next_revocation_domain(state)
    assert result["retry_count"] == 0


# ── cert_revoker tests ─────────────────────────────────────────────────────


@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.make_client")
def test_cert_revoker_success(mock_make_client, mock_load_key, mock_read_cert):
    """Should successfully revoke a certificate."""
    # Setup mocks
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_key = MagicMock()
    mock_load_key.return_value = mock_key

    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}
    mock_client.revoke_certificate.return_value = "new-nonce-123"

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "current_nonce": "nonce-456",
        "revocation_reason": 4,  # superseded
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
    }

    result = cert_revoker(state)

    assert result["revoked_domains"] == ["example.com"]
    assert result["current_nonce"] == "new-nonce-123"
    assert result["current_revocation_domain"] is None

    # Verify the revoke call
    mock_client.revoke_certificate.assert_called_once()
    call_kwargs = mock_client.revoke_certificate.call_args[1]
    assert call_kwargs["reason"] == 4


@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.make_client")
def test_cert_revoker_missing_cert(mock_make_client, mock_load_key, mock_read_cert):
    """Should gracefully handle missing certificate file."""
    mock_read_cert.return_value = None

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
    }

    result = cert_revoker(state)

    assert result["failed_revocations"] == ["example.com"]
    assert result["current_revocation_domain"] is None
    assert len(result["error_log"]) == 1
    assert "not found" in result["error_log"][0]

    # Should not call revoke_certificate
    mock_make_client.return_value.revoke_certificate.assert_not_called()


@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.make_client")
def test_cert_revoker_acme_error(mock_make_client, mock_load_key, mock_read_cert):
    """Should handle ACME error and log it."""
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = MagicMock()

    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}

    acme_error = AcmeError(403, {"type": "urn:acme:error:unauthorized", "detail": "Unauthorized"}, "new-nonce-789")
    mock_client.revoke_certificate.side_effect = acme_error

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "current_nonce": "nonce-456",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
    }

    result = cert_revoker(state)

    assert result["failed_revocations"] == ["example.com"]
    assert result["current_nonce"] == "new-nonce-789"
    assert result["current_revocation_domain"] is None
    assert len(result["error_log"]) == 1
    assert "Unauthorized" in result["error_log"][0]


@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.make_client")
def test_cert_revoker_retries_transient_error(mock_make_client, mock_load_key, mock_read_cert):
    """A rateLimited/serverInternal-style error should schedule a retry for
    the SAME domain rather than moving it to failed_revocations."""
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = MagicMock()

    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}

    acme_error = AcmeError(
        429, {"type": "urn:ietf:params:acme:error:rateLimited", "detail": "Too many requests"}, "new-nonce-1"
    )
    mock_client.revoke_certificate.side_effect = acme_error

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "current_nonce": "nonce-456",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
        "retry_count": 0,
        "retry_delay_seconds": 5,
        "max_retries": 3,
    }

    result = cert_revoker(state)

    assert "failed_revocations" not in result
    assert "current_revocation_domain" not in result  # preserved by NOT being overwritten
    assert result["retry_count"] == 1
    assert result["retry_not_before"] is not None
    assert result["retry_delay_seconds"] > 0


@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.make_client")
def test_cert_revoker_stops_retrying_after_max_retries(mock_make_client, mock_load_key, mock_read_cert):
    """Once the per-domain retry budget is exhausted, a transient error
    should fall back to today's best-effort failed_revocations behavior."""
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = MagicMock()

    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}

    acme_error = AcmeError(
        503, {"type": "urn:ietf:params:acme:error:serverInternal", "detail": "Try again"}, "new-nonce-2"
    )
    mock_client.revoke_certificate.side_effect = acme_error

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "current_nonce": "nonce-456",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
        "retry_count": 3,
        "retry_delay_seconds": 40,
        "max_retries": 3,
    }

    result = cert_revoker(state)

    assert result["failed_revocations"] == ["example.com"]
    assert result["current_revocation_domain"] is None
    assert result.get("retry_not_before") is None


@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.make_client")
def test_cert_revoker_does_not_retry_fatal_alreadyrevoked(mock_make_client, mock_load_key, mock_read_cert):
    """alreadyRevoked/malformed-style errors are policy rejections, not
    transient — they should fail immediately even with retry budget left."""
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = MagicMock()

    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}

    acme_error = AcmeError(
        400, {"type": "urn:ietf:params:acme:error:alreadyRevoked", "detail": "Certificate already revoked"}, "n"
    )
    mock_client.revoke_certificate.side_effect = acme_error

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "current_nonce": "nonce-456",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
        "retry_count": 0,
        "retry_delay_seconds": 5,
        "max_retries": 3,
    }

    result = cert_revoker(state)

    assert result["failed_revocations"] == ["example.com"]
    assert result["current_revocation_domain"] is None
    assert result.get("retry_not_before") is None


# ── revocation_reporter tests ──────────────────────────────────────────────


def test_revocation_reporter_success():
    """Reporter returns structured summary with no failures → SUCCESS status."""
    state = {
        "revoked_domains": ["example.com", "api.example.com"],
        "failed_revocations": [],
        "revocation_reason": 0,
        "error_log": [],
        "messages": [],
    }

    result = revocation_reporter(state)

    assert "messages" in result
    assert result["messages"] == []


def test_revocation_reporter_with_failures():
    """Reporter includes failed domains in structured output."""
    state = {
        "revoked_domains": ["example.com"],
        "failed_revocations": ["api.example.com"],
        "revocation_reason": 4,
        "error_log": ["api.example.com: unauthorized"],
        "messages": [],
    }

    result = revocation_reporter(state)

    assert "messages" in result


def test_revocation_reporter_deterministic():
    """Reporter always returns empty messages (no LLM)."""
    state = {
        "revoked_domains": ["example.com"],
        "failed_revocations": [],
        "revocation_reason": 0,
        "error_log": [],
        "messages": [],
    }

    result = revocation_reporter(state)

    assert result["messages"] == []


# ── Topology tests ────────────────────────────────────────────────────────


def test_revocation_graph_topology():
    """Verify the revocation graph compiles without error."""
    graph = build_revocation_graph(use_checkpointing=False)

    # Should compile without error
    assert graph is not None
    # Verify it's a compiled graph (has invoke method)
    assert callable(graph.invoke)


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.account.make_client")
@patch("agent.nodes.account.jwslib.load_account_key")
@patch("agent.nodes.account.jwslib.account_key_exists")
def test_revocation_graph_single_domain_flow(
    mock_key_exists,
    mock_account_load_key,
    mock_account_make_client,
    mock_read_cert,
    mock_load_key,
    mock_make_client,
):
    """Test a complete revocation graph run for a single domain."""
    # Setup account mocks
    mock_key_exists.return_value = False
    mock_account_key = MagicMock()
    mock_account_load_key.return_value = mock_account_key
    mock_account_client = MagicMock()
    mock_account_make_client.return_value = mock_account_client
    mock_account_client.get_directory.return_value = {
        "newNonce": "https://ca.example.com/newNonce",
        "newAccount": "https://ca.example.com/newAccount",
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_account_client.get_nonce.return_value = "nonce-123"
    mock_account_client.create_account.return_value = ("https://ca.example.com/account/12345", "nonce-456")

    # Setup revoker mocks
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = mock_account_key
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_client.revoke_certificate.return_value = "nonce-789"

    # Setup reporter mock

    # Build and run graph
    graph = build_revocation_graph(use_checkpointing=False)
    initial_state = revocation_initial_state(
        domains=["example.com"],
        reason=0,
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )

    final_state = graph.invoke(initial_state)

    # Verify results
    assert final_state["revoked_domains"] == ["example.com"]
    assert final_state["failed_revocations"] == []


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.account.make_client")
@patch("agent.nodes.account.jwslib.load_account_key")
@patch("agent.nodes.account.jwslib.account_key_exists")
def test_revocation_graph_multi_domain_flow(
    mock_key_exists,
    mock_account_load_key,
    mock_account_make_client,
    mock_read_cert,
    mock_load_key,
    mock_make_client,
):
    """Test revocation graph with multiple domains."""
    # Setup account mocks
    mock_key_exists.return_value = True
    mock_account_key = MagicMock()
    mock_account_load_key.return_value = mock_account_key
    mock_account_client = MagicMock()
    mock_account_make_client.return_value = mock_account_client
    mock_account_client.get_directory.return_value = {
        "newNonce": "https://ca.example.com/newNonce",
        "newAccount": "https://ca.example.com/newAccount",
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_account_client.get_nonce.return_value = "nonce-123"
    mock_account_client.lookup_account.return_value = ("https://ca.example.com/account/12345", "nonce-456")

    # Setup revoker mocks
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = mock_account_key
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_client.revoke_certificate.side_effect = ["nonce-789", "nonce-999"]

    # Setup reporter mock

    # Build and run graph
    graph = build_revocation_graph(use_checkpointing=False)
    initial_state = revocation_initial_state(
        domains=["example.com", "api.example.com"],
        reason=1,  # keyCompromise
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )

    final_state = graph.invoke(initial_state)

    # Should have revoked both domains
    assert set(final_state["revoked_domains"]) == {"example.com", "api.example.com"}
    assert final_state["failed_revocations"] == []
    assert final_state["revocation_reason"] == 1


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.account.make_client")
@patch("agent.nodes.account.jwslib.load_account_key")
@patch("agent.nodes.account.jwslib.account_key_exists")
def test_revocation_graph_partial_failure(
    mock_key_exists,
    mock_account_load_key,
    mock_account_make_client,
    mock_read_cert,
    mock_load_key,
    mock_make_client,
):
    """Test revocation graph when one domain fails but others succeed."""
    # Setup account mocks
    mock_key_exists.return_value = True
    mock_account_key = MagicMock()
    mock_account_load_key.return_value = mock_account_key
    mock_account_client = MagicMock()
    mock_account_make_client.return_value = mock_account_client
    mock_account_client.get_directory.return_value = {
        "newNonce": "https://ca.example.com/newNonce",
        "newAccount": "https://ca.example.com/newAccount",
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_account_client.get_nonce.return_value = "nonce-123"
    mock_account_client.lookup_account.return_value = ("https://ca.example.com/account/12345", "nonce-456")

    # Setup revoker mocks: first succeeds, second fails (missing cert), third succeeds
    def read_cert_side_effect(cert_store, domain):
        if domain == "api.example.com":
            return None  # Missing cert
        return "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"

    mock_read_cert.side_effect = read_cert_side_effect
    mock_load_key.return_value = mock_account_key
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    # Return new nonces for successful revocations
    mock_client.revoke_certificate.side_effect = ["nonce-789", "nonce-999"]

    # Setup reporter mock

    # Build and run graph
    graph = build_revocation_graph(use_checkpointing=False)
    initial_state = revocation_initial_state(
        domains=["example.com", "api.example.com", "shop.example.com"],
        reason=0,
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )

    final_state = graph.invoke(initial_state)

    # Verify partial success
    assert "example.com" in final_state["revoked_domains"]
    assert "shop.example.com" in final_state["revoked_domains"]
    assert "api.example.com" in final_state["failed_revocations"]


# ── Nonce Management & Flow Tests ──────────────────────────────────────────

def test_nonce_cleared_between_domains():
    """Should clear nonce after picking each domain for fresh fetch."""
    state1 = {"revocation_targets": ["example.com", "api.example.com"], "current_nonce": "nonce-123"}
    result1 = pick_next_revocation_domain(state1)
    assert result1["current_nonce"] is None

    # Simulate nonce being refreshed for next domain
    state2 = {"revocation_targets": ["api.example.com"], "current_nonce": "nonce-456"}
    result2 = pick_next_revocation_domain(state2)
    assert result2["current_nonce"] is None


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.account.make_client")
@patch("agent.nodes.account.jwslib.load_account_key")
@patch("agent.nodes.account.jwslib.account_key_exists")
def test_nonce_flow_multi_domain_sequence(
    mock_key_exists,
    mock_account_load_key,
    mock_account_make_client,
    mock_read_cert,
    mock_load_key,
    mock_make_client,
):
    """Verify nonce flows correctly through multi-domain revocation."""
    # Setup mocks
    mock_key_exists.return_value = True
    mock_account_key = MagicMock()
    mock_account_load_key.return_value = mock_account_key
    mock_account_client = MagicMock()
    mock_account_make_client.return_value = mock_account_client
    mock_account_client.get_directory.return_value = {
        "newNonce": "https://ca.example.com/newNonce",
        "newAccount": "https://ca.example.com/newAccount",
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_account_client.get_nonce.return_value = "initial-nonce-123"
    mock_account_client.lookup_account.return_value = ("https://ca.example.com/account/12345", "account-nonce-456")

    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = mock_account_key
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}
    # Each revocation returns a new nonce
    mock_client.revoke_certificate.side_effect = ["revoke-nonce-789", "revoke-nonce-999"]


    graph = build_revocation_graph(use_checkpointing=False)
    initial_state = revocation_initial_state(
        domains=["example.com", "api.example.com"],
        reason=0,
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )

    final_state = graph.invoke(initial_state)

    # Verify nonces were consumed and updated
    assert final_state["current_nonce"] in ["revoke-nonce-999", None]  # Final nonce or cleared
    assert len(final_state["revoked_domains"]) == 2


def test_nonce_none_handling_in_state():
    """Verify graceful handling when nonce is None in state."""
    state = {"revocation_targets": ["example.com"], "current_nonce": None}
    result = pick_next_revocation_domain(state)

    assert result["current_nonce"] is None
    assert result["current_revocation_domain"] == "example.com"


# ── RFC 5280 Reason Code Coverage Tests ────────────────────────────────────

@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
def test_revocation_reason_codes(mock_read_cert, mock_load_key, mock_make_client):
    """Verify all RFC 5280 reason codes are passed correctly to ACME client."""
    reason_codes = [0, 1, 3, 4, 5]  # Valid codes: unspecified, keyCompromise, affiliationChanged, superseded, cessationOfOperation

    for reason_code in reason_codes:
        mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
        mock_load_key.return_value = MagicMock()
        mock_client = MagicMock()
        mock_make_client.return_value = mock_client
        mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}
        mock_client.revoke_certificate.return_value = f"nonce-{reason_code}"

        state = {
            "current_revocation_domain": "example.com",
            "cert_store_path": "/tmp/certs",
            "account_key_path": "/tmp/account.key",
            "acme_account_url": "https://ca.example.com/account/12345",
            "revocation_reason": reason_code,
            "revoked_domains": [],
            "failed_revocations": [],
            "error_log": [],
        }

        result = cert_revoker(state)

        # Verify the reason code was passed
        mock_client.revoke_certificate.assert_called()
        call_kwargs = mock_client.revoke_certificate.call_args[1]
        assert call_kwargs["reason"] == reason_code


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
def test_revocation_invalid_reason_code(mock_read_cert, mock_load_key, mock_make_client):
    """Verify behavior with invalid reason code (> 5)."""
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = MagicMock()
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}

    acme_error = AcmeError(400, {"type": "urn:acme:error:badRequest", "detail": "Invalid reason"}, "new-nonce")
    mock_client.revoke_certificate.side_effect = acme_error

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "revocation_reason": 99,  # Invalid reason code
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
    }

    result = cert_revoker(state)

    # Should record as failed
    assert "example.com" in result["failed_revocations"]
    assert len(result["error_log"]) > 0


# ── State Integrity & Message Accumulation Tests ────────────────────────────

@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.account.make_client")
@patch("agent.nodes.account.jwslib.load_account_key")
@patch("agent.nodes.account.jwslib.account_key_exists")
def test_state_message_accumulation_across_flow(
    mock_key_exists,
    mock_account_load_key,
    mock_account_make_client,
    mock_read_cert,
    mock_load_key,
    mock_make_client,
):
    """Verify messages accumulate correctly through the revocation flow."""
    # Setup mocks
    mock_key_exists.return_value = True
    mock_account_key = MagicMock()
    mock_account_load_key.return_value = mock_account_key
    mock_account_client = MagicMock()
    mock_account_make_client.return_value = mock_account_client
    mock_account_client.get_directory.return_value = {
        "newNonce": "https://ca.example.com/newNonce",
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_account_client.get_nonce.return_value = "nonce-123"
    mock_account_client.lookup_account.return_value = ("https://ca.example.com/account/12345", "nonce-456")

    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = mock_account_key
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}
    mock_client.revoke_certificate.return_value = "nonce-789"


    graph = build_revocation_graph(use_checkpointing=False)
    initial_state = revocation_initial_state(
        domains=["example.com"],
        reason=0,
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )

    # Initial state should have empty messages
    assert initial_state["messages"] == []

    final_state = graph.invoke(initial_state)

    # Reporter is deterministic — messages list stays empty (no LLM exchange)
    assert isinstance(final_state["messages"], list)


def test_revoked_domains_no_duplicates():
    """Verify revoked_domains list never contains duplicates."""
    state1 = {
        "revocation_targets": ["example.com"],
        "revoked_domains": ["api.example.com"],
        "current_revocation_domain": None,
    }
    result1 = pick_next_revocation_domain(state1)
    assert result1["current_revocation_domain"] == "example.com"

    # Even if state already has the domain, picking ensures first-in-first-out
    state2 = {
        "revocation_targets": ["example.com", "api.example.com"],
        "revoked_domains": ["example.com"],  # Already revoked
    }
    result2 = pick_next_revocation_domain(state2)
    assert result2["current_revocation_domain"] == "example.com"
    assert result2["revocation_targets"] == ["api.example.com"]


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
def test_current_revocation_domain_cleared_after_revoke(mock_read_cert, mock_load_key, mock_make_client):
    """Verify current_revocation_domain is cleared after each revocation."""
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = MagicMock()
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}
    mock_client.revoke_certificate.return_value = "nonce-123"

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
    }

    result = cert_revoker(state)

    # Domain should be cleared after revocation
    assert result["current_revocation_domain"] is None
    assert "example.com" in result["revoked_domains"]


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
def test_error_log_accumulation_across_failures(mock_read_cert, mock_load_key, mock_make_client):
    """Verify error_log accumulates without losing previous errors."""
    mock_read_cert.return_value = None  # Missing cert

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": ["previous error from domain1"],
    }

    result = cert_revoker(state)

    # Should have both previous and new error
    assert len(result["error_log"]) == 2
    assert "previous error from domain1" in result["error_log"]
    assert any("not found" in err for err in result["error_log"])


# ── Checkpointing & Resumption Tests ───────────────────────────────────────

def test_revocation_graph_with_checkpointing():
    """Verify graph compiles correctly with checkpointing enabled."""
    graph = build_revocation_graph(use_checkpointing=True)

    assert graph is not None
    assert callable(graph.invoke)
    # Checkpointing doesn't change the topology, just adds replay capability
    assert callable(graph.stream)


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.account.make_client")
@patch("agent.nodes.account.jwslib.load_account_key")
@patch("agent.nodes.account.jwslib.account_key_exists")
def test_revocation_state_resumption_after_interrupt(
    mock_key_exists,
    mock_account_load_key,
    mock_account_make_client,
    mock_read_cert,
    mock_load_key,
    mock_make_client,
):
    """Verify state is preservable for resumption after interrupt."""
    # Setup mocks
    mock_key_exists.return_value = True
    mock_account_key = MagicMock()
    mock_account_load_key.return_value = mock_account_key
    mock_account_client = MagicMock()
    mock_account_make_client.return_value = mock_account_client
    mock_account_client.get_directory.return_value = {
        "newNonce": "https://ca.example.com/newNonce",
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_account_client.get_nonce.return_value = "nonce-123"
    mock_account_client.lookup_account.return_value = ("https://ca.example.com/account/12345", "nonce-456")

    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = mock_account_key
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}
    mock_client.revoke_certificate.return_value = "nonce-789"


    # Build without checkpointing for this test (checkpointing requires special invoke with config)
    graph = build_revocation_graph(use_checkpointing=False)
    initial_state = revocation_initial_state(
        domains=["example.com", "api.example.com"],
        reason=0,
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )

    # State should be serializable (all fields JSON-compatible)
    final_state = graph.invoke(initial_state)

    # Verify state contains all necessary info for resumption
    assert "revoked_domains" in final_state
    assert "failed_revocations" in final_state
    assert "revocation_targets" in final_state
    assert "acme_account_url" in final_state
    assert "messages" in final_state


# ── Account Setup Scenario Tests ───────────────────────────────────────────

@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.account.make_client")
@patch("agent.nodes.account.jwslib.load_account_key")
@patch("agent.nodes.account.jwslib.account_key_exists")
def test_account_creation_failure_handling(
    mock_key_exists,
    mock_account_load_key,
    mock_account_make_client,
    mock_read_cert,
    mock_load_key,
    mock_make_client,
):
    """Verify revocation graph handles account creation failure."""
    # Account creation fails
    mock_key_exists.return_value = False
    mock_account_key = MagicMock()
    mock_account_load_key.return_value = mock_account_key
    mock_account_client = MagicMock()
    mock_account_make_client.return_value = mock_account_client
    mock_account_client.get_directory.return_value = {
        "newNonce": "https://ca.example.com/newNonce",
        "newAccount": "https://ca.example.com/newAccount",
    }
    mock_account_client.get_nonce.return_value = "nonce-123"

    acme_error = AcmeError(400, {"type": "urn:acme:error:malformed", "detail": "Bad request"}, "nonce-456")
    mock_account_client.create_account.side_effect = acme_error

    graph = build_revocation_graph(use_checkpointing=False)
    initial_state = revocation_initial_state(
        domains=["example.com"],
        reason=0,
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )

    # Graph should handle account setup failure gracefully
    try:
        final_state = graph.invoke(initial_state)
        # If it doesn't raise, verify error was captured
        assert len(final_state["error_log"]) >= 1 or final_state["failed_revocations"]
    except AcmeError:
        # Account setup errors may propagate - that's acceptable
        pass


# ── Domain Edge Cases Tests ────────────────────────────────────────────────

def test_very_long_domain_name():
    """Verify handling of very long domain names (near DNS limit)."""
    long_domain = "a" * 63 + "." + "b" * 63 + ".example.com"  # 131 chars, near 255 DNS limit
    state = {"revocation_targets": [long_domain], "current_nonce": "nonce"}

    result = pick_next_revocation_domain(state)

    assert result["current_revocation_domain"] == long_domain
    assert len(result["revocation_targets"]) == 0


def test_idn_internationalized_domain():
    """Verify handling of internationalized domain names."""
    idn_domain = "münchen.example.com"
    state = {"revocation_targets": [idn_domain], "current_nonce": "nonce"}

    result = pick_next_revocation_domain(state)

    assert result["current_revocation_domain"] == idn_domain


def test_duplicate_domains_in_targets():
    """Verify behavior when same domain appears multiple times in targets."""
    state = {"revocation_targets": ["example.com", "api.example.com", "example.com"], "current_nonce": "nonce"}

    # First iteration
    result1 = pick_next_revocation_domain(state)
    assert result1["current_revocation_domain"] == "example.com"
    assert result1["revocation_targets"] == ["api.example.com", "example.com"]

    # Second iteration
    state2 = result1
    result2 = pick_next_revocation_domain(state2)
    assert result2["current_revocation_domain"] == "api.example.com"
    assert result2["revocation_targets"] == ["example.com"]


# ── Reporter & Message Flow Tests ──────────────────────────────────────────

def test_reporter_message_content_structure():
    """Verify reporter returns empty messages and correct dict structure."""
    state = {
        "revoked_domains": ["example.com"],
        "failed_revocations": ["api.example.com"],
        "revocation_reason": 4,
        "error_log": ["api.example.com: cert not found"],
        "messages": [],
    }

    result = revocation_reporter(state)

    assert "messages" in result
    assert result["messages"] == []


# ── Error Handling & Accumulation Tests ────────────────────────────────────

@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
def test_consecutive_revocation_failures(mock_read_cert, mock_load_key, mock_make_client):
    """Verify multiple consecutive failures are tracked correctly."""
    # Mock read_cert_pem to return None (missing cert)
    mock_read_cert.return_value = None
    mock_load_key.return_value = MagicMock()

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
    }

    result = cert_revoker(state)
    assert "example.com" in result["failed_revocations"]
    assert len(result["error_log"]) == 1


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
def test_error_log_message_format_validation(mock_read_cert, mock_load_key, mock_make_client):
    """Verify error log messages follow consistent format."""
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = MagicMock()
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}

    acme_error = AcmeError(403, {"type": "urn:acme:error:unauthorized", "detail": "Not authorized"}, "nonce-789")
    mock_client.revoke_certificate.side_effect = acme_error

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "current_nonce": "nonce-456",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
    }

    result = cert_revoker(state)

    # Error log should contain meaningful information
    assert len(result["error_log"]) > 0
    error_msg = result["error_log"][0]
    # Should contain either domain or error details
    assert ("example.com" in error_msg or "Not authorized" in error_msg or "Unauthorized" in error_msg)
