"""
Unit tests confirming agent/graph.py::build_graph() wires the right node
set for each CERT_ISSUANCE_MODE value.
"""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture(autouse=True)
def _restore_config_module_state():
    """importlib.reload(config) re-executes make_settings(), permanently
    replacing config.settings for the rest of the process (AcmeConfig and
    SpiffeConfig are separate classes now — there's no shared fallback
    attribute the way the old flat Settings class had). Reload back to the
    default acme-mode state after each test in this file so later tests
    (elsewhere in the suite) don't inherit a SpiffeConfig singleton."""
    yield
    import config
    importlib.reload(config)
    import agent.graph
    importlib.reload(agent.graph)


def test_acme_mode_wires_acme_nodes(monkeypatch):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "acme")
    import config
    importlib.reload(config)

    import agent.graph
    importlib.reload(agent.graph)

    graph = agent.graph.build_graph(use_checkpointing=False)
    nodes = set(graph.nodes.keys())

    for expected in (
        "certificate_scanner", "renewal_planner", "acme_account_setup",
        "pick_next_domain", "order_initializer", "challenge_setup",
        "challenge_verifier", "csr_generator", "order_finalizer",
        "cert_downloader", "storage_manager", "error_handler",
        "retry_scheduler", "summary_reporter",
    ):
        assert expected in nodes

    assert "spiffe_attestor" not in nodes


def test_spiffe_mode_wires_spiffe_nodes(monkeypatch):
    monkeypatch.setenv("CERT_ISSUANCE_MODE", "spiffe")
    monkeypatch.setenv("SPIFFE_TRUST_DOMAIN", "example.org")
    import config
    importlib.reload(config)

    import agent.graph
    importlib.reload(agent.graph)

    graph = agent.graph.build_graph(use_checkpointing=False)
    nodes = set(graph.nodes.keys())

    for expected in (
        "certificate_scanner", "renewal_planner", "pick_next_domain",
        "spiffe_attestor", "storage_manager", "summary_reporter",
    ):
        assert expected in nodes

    # ACME-only nodes must not be present in the spiffe-mode graph
    for absent in (
        "acme_account_setup", "order_initializer", "challenge_setup",
        "challenge_verifier", "csr_generator", "order_finalizer",
        "cert_downloader", "error_handler", "retry_scheduler",
    ):
        assert absent not in nodes
