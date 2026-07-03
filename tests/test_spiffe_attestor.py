"""
Unit tests for agent/nodes/spiffe_attestor.py.

Covers:
  - Missing current_domain guard
  - Missing `spiffe` package guard
  - Success path: fetches an SVID, writes privkey.pem, populates current_order
  - Failure path: FetchX509SvidError (e.g. unregistered workload) is
    terminal per-domain, not a crash
  - SPIFFE ID mismatch is logged but non-fatal
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import datetime

from agent.nodes.spiffe_attestor import SpiffeAttestorNode
from agent.state import AgentState


def _make_self_signed_cert(common_name: str):
    """Build a throwaway self-signed cert + key pair for test fixtures."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(hours=1)
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _base_state(**overrides) -> AgentState:
    state: dict = {
        "current_domain": "spiffe://example.org/workload/demo",
        "cert_store_path": "/tmp/spiffe-test-certs",
        "error_log": [],
        "failed_renewals": [],
    }
    state.update(overrides)
    return state  # type: ignore[return-value]


def test_missing_current_domain_returns_error_log():
    node = SpiffeAttestorNode()
    result = node.run(_base_state(current_domain=None))
    assert "no current_domain" in result["error_log"][0]


def test_missing_spiffe_package_returns_error_log():
    node = SpiffeAttestorNode()
    with patch("agent.nodes.spiffe_attestor._SPIFFE_AVAILABLE", False):
        result = node.run(_base_state())
    assert "spiffe" in result["error_log"][0].lower()
    assert result["failed_renewals"] == ["spiffe://example.org/workload/demo"]


def test_fetch_failure_is_terminal_not_a_crash(tmp_path: Path):
    from spiffe.workloadapi.errors import FetchX509SvidError

    node = SpiffeAttestorNode()
    mock_client = MagicMock()
    mock_client.fetch_x509_svid.side_effect = FetchX509SvidError("no identity issued")

    with patch("agent.nodes.spiffe_attestor.WorkloadApiClient", return_value=mock_client):
        result = node.run(_base_state(cert_store_path=str(tmp_path)))

    assert result["failed_renewals"] == ["spiffe://example.org/workload/demo"]
    assert "no identity issued" in result["error_log"][0]
    mock_client.close.assert_called_once()


def test_invalid_socket_path_is_terminal_not_a_crash(tmp_path: Path):
    """WorkloadApiClient's constructor (not just fetch_x509_svid) can raise —
    e.g. a misconfigured or missing SPIRE_AGENT_SOCKET_PATH. This must be
    caught the same way a fetch failure is, not left to crash the graph."""
    from spiffe.errors import ArgumentError

    node = SpiffeAttestorNode()
    with patch(
        "agent.nodes.spiffe_attestor.WorkloadApiClient",
        side_effect=ArgumentError("invalid socket path"),
    ):
        result = node.run(_base_state(cert_store_path=str(tmp_path)))

    assert result["failed_renewals"] == ["spiffe://example.org/workload/demo"]
    assert "invalid SPIRE_AGENT_SOCKET_PATH" in result["error_log"][0]


def test_success_path_writes_privkey_and_populates_current_order(tmp_path: Path):
    cert, key = _make_self_signed_cert("workload/demo")

    mock_svid = MagicMock()
    mock_svid.leaf = cert
    mock_svid.cert_chain = [cert]
    mock_svid.private_key = key
    mock_svid.spiffe_id = "spiffe://example.org/workload/demo"

    mock_client = MagicMock()
    mock_client.fetch_x509_svid.return_value = mock_svid

    node = SpiffeAttestorNode()
    with patch("agent.nodes.spiffe_attestor.WorkloadApiClient", return_value=mock_client) as mock_ctor:
        result = node.run(_base_state(cert_store_path=str(tmp_path)))

    # Constructed with a unix:// URI wrapping the configured socket path
    assert mock_ctor.call_args.kwargs["socket_path"].startswith("unix://")

    assert "current_order" in result
    full_chain_pem = result["current_order"]["full_chain_pem"]
    assert "-----BEGIN CERTIFICATE-----" in full_chain_pem

    # Confirm privkey.pem was written under the sanitized cert_dir path
    written = list(tmp_path.rglob("privkey.pem"))
    assert len(written) == 1
    assert written[0].read_text().startswith("-----BEGIN PRIVATE KEY-----")

    mock_client.close.assert_called_once()


def test_spiffe_id_mismatch_logs_warning_but_still_succeeds(tmp_path: Path):
    cert, key = _make_self_signed_cert("workload/other")

    mock_svid = MagicMock()
    mock_svid.leaf = cert
    mock_svid.cert_chain = []
    mock_svid.private_key = key
    mock_svid.spiffe_id = "spiffe://example.org/workload/UNEXPECTED"

    mock_client = MagicMock()
    mock_client.fetch_x509_svid.return_value = mock_svid

    node = SpiffeAttestorNode()
    with patch("agent.nodes.spiffe_attestor.WorkloadApiClient", return_value=mock_client):
        result = node.run(_base_state(cert_store_path=str(tmp_path)))

    # Mismatch is a warning, not a failure — the fetched SVID is still used
    assert "current_order" in result
    assert "failed_renewals" not in result
