"""
Integration test: full SPIFFE issuance flow against a local SPIRE stub.

Prerequisites
-------------
  docker compose -f docker-compose.spire.yml up -d spire-server
  ./spire/register-workload.sh
  SPIRE_JOIN_TOKEN=$(cat spire/data/join_token.txt) \
      docker compose -f docker-compose.spire.yml up -d spire-agent

register-workload.sh registers spiffe://example.org/workload/demo against
uid 0 (root) — spire-test's default user, matching the base Dockerfile's
`test` stage. These tests must run *inside* the spire-test container, not
directly via a host-run pytest process: the Workload API socket is shared
via a named Docker volume (not a host bind mount), since Docker Desktop on
macOS does not proxy bind-mounted Unix domain sockets from container to
host (see doc/SPIRE_TESTING_SERVER.md).

Run with:
  docker compose -f docker-compose.spire.yml run --rm spire-test \
      uv run pytest tests/test_spiffe_spire.py -v -m integration
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from cryptography import x509

from tests.conftest import requires_spire

pytestmark = pytest.mark.integration


def _run_agent(spire_settings) -> dict:
    from agent.graph import build_graph, initial_state

    graph = build_graph(use_checkpointing=False)
    state = initial_state(
        managed_domains=spire_settings.MANAGED_SPIFFE_IDS,
        cert_store_path=spire_settings.CERT_STORE_PATH,
        max_retries=spire_settings.MAX_RETRIES,
    )
    return graph.invoke(state)


@requires_spire
def test_fetch_svid_for_registered_workload(spire_settings):
    """
    Happy-path: agent fetches an SVID for the registered demo workload and
    writes PEM files to the temp cert store.
    """
    result = _run_agent(spire_settings)

    workload_id = "spiffe://example.org/workload/demo"
    assert workload_id in result["completed_renewals"], (
        f"Expected {workload_id} in completed_renewals, got: {result['completed_renewals']}\n"
        f"error_log: {result['error_log']}"
    )
    assert result["failed_renewals"] == []

    candidates = list(Path(spire_settings.CERT_STORE_PATH).rglob("cert.pem"))
    assert len(candidates) == 1, f"Expected exactly one cert.pem, found: {candidates}"

    cert = x509.load_pem_x509_certificate(candidates[0].read_bytes())
    assert cert.not_valid_after_utc > cert.not_valid_before_utc


@requires_spire
def test_second_fetch_returns_valid_svid(spire_settings):
    """
    A second run against the same registered workload also succeeds and
    returns a currently-valid SVID.

    Note: this does not force an actual expiry/rotation window (SPIRE's
    default X509-SVID TTL is short-lived but not trivially forceable in a
    black-box integration test without either a very long test sleep or
    reconfiguring the harness's ca_ttl) — it's a proxy confirming repeat
    fetches keep working and keep returning valid, unexpired material.
    """
    first = _run_agent(spire_settings)
    assert first["completed_renewals"] != []

    second = _run_agent(spire_settings)
    workload_id = "spiffe://example.org/workload/demo"
    assert workload_id in second["completed_renewals"]

    cert_path = next(Path(spire_settings.CERT_STORE_PATH).rglob("cert.pem"))
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert cert.not_valid_after_utc > cert.not_valid_before_utc


_UNREGISTERED_FETCH_SNIPPET = """
import sys
from spiffe import WorkloadApiClient
from spiffe.workloadapi.errors import FetchX509SvidError

client = WorkloadApiClient(socket_path="unix://{socket_path}")
try:
    client.fetch_x509_svid()
    print("UNEXPECTED SUCCESS")
    sys.exit(1)
except FetchX509SvidError as exc:
    print(f"FetchX509SvidError: {{exc}}")
    sys.exit(0)
finally:
    client.close()
"""


@requires_spire
def test_unregistered_workload_refused_cleanly(spire_settings):
    """
    A workload with no registration entry gets a clean, non-crashing
    failure — not the agent's `error_log`/`failed_renewals` path (that's
    exercised by the happy-path test above via a *registered* workload),
    but the raw Workload API boundary itself: PermissionDenied for a UID
    with no matching registration entry.

    Drops privilege to a non-root UID via subprocess's `user=` kwarg
    (spire-test runs as root, so this is a real, different, unregistered
    identity attesting against the real socket — not a mocked client).
    """
    socket_path = spire_settings.SPIRE_AGENT_SOCKET_PATH
    # Dropping to uid 1000 means /root/.cache (uv's default cache dir, owned
    # by root) is unwritable — point UV_CACHE_DIR somewhere the dropped-
    # privilege process can actually write to.
    env = {**os.environ, "UV_CACHE_DIR": "/tmp/uv-cache-uid1000"}
    proc = subprocess.run(
        ["uv", "run", "python3", "-c", _UNREGISTERED_FETCH_SNIPPET.format(socket_path=socket_path)],
        user=1000,
        env=env,
        capture_output=True, text=True, timeout=15,
    )
    assert proc.returncode == 0, (
        f"Expected a clean FetchX509SvidError, got exit {proc.returncode}\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    assert "no identity issued" in proc.stdout or "PermissionDenied" in proc.stdout
