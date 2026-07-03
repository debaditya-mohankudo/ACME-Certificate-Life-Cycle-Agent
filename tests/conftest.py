"""
Shared pytest fixtures.

Pebble fixture
--------------
The `pebble_settings` fixture patches the module-level `config.settings`
singleton so every node in the graph talks to a local Pebble instance instead
of the configured CA. It also patches ANTHROPIC_API_KEY so no real credential
is needed for the planner's LLM-based tests.
"""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

import pytest


# ─── Pebble availability check ────────────────────────────────────────────────

_PEBBLE_HOST = os.getenv("PEBBLE_HOST", "localhost")


def _pebble_running(host: str = _PEBBLE_HOST, port: int = 14000) -> bool:
    """Return True if Pebble's ACME port is open."""
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


requires_pebble = pytest.mark.skipif(
    not _pebble_running(),
    reason="Pebble not running — start with: docker compose -f docker-compose.pebble.yml up -d",
)


# ─── SPIRE availability check ─────────────────────────────────────────────────
# Unlike Pebble's TCP port, the Workload API is a Unix domain socket, shared
# via a named Docker volume (not a host bind mount — Docker Desktop on
# macOS does not proxy bind-mounted Unix sockets from container to host).
# These integration tests therefore run *inside* the spire-test container
# (see doc/SPIRE_TESTING_SERVER.md), where SPIRE_AGENT_SOCKET_PATH resolves
# to the in-container path docker-compose.spire.yml sets.

_SPIRE_AGENT_SOCKET_PATH = os.getenv(
    "SPIRE_AGENT_SOCKET_PATH", "/tmp/spire-agent/public/api.sock"
)


def _spire_running(socket_path: str = _SPIRE_AGENT_SOCKET_PATH) -> bool:
    """Return True if the SPIRE Agent's Workload API socket is reachable."""
    if not Path(socket_path).exists():
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect(socket_path)
        return True
    except OSError:
        return False


requires_spire = pytest.mark.skipif(
    not _spire_running(),
    reason=(
        "SPIRE not running — see doc/SPIRE_TESTING_SERVER.md: "
        "docker compose -f docker-compose.spire.yml up -d spire-server && "
        "./spire/register-workload.sh && "
        "SPIRE_JOIN_TOKEN=$(cat spire/data/join_token.txt) "
        "docker compose -f docker-compose.spire.yml up -d spire-agent"
    ),
)


# ─── Settings patch ───────────────────────────────────────────────────────────

@pytest.fixture()
def pebble_settings(tmp_path: Path):
    """
    Mutate the live settings singleton to point at local Pebble,
    restore original values after the test.
    """
    from config import settings

    originals = {
        "CA_PROVIDER":        settings.CA_PROVIDER,
        "ACME_DIRECTORY_URL": settings.ACME_DIRECTORY_URL,
        "ACME_EAB_KEY_ID":    settings.ACME_EAB_KEY_ID,
        "ACME_EAB_HMAC_KEY":  settings.ACME_EAB_HMAC_KEY,
        "MANAGED_DOMAINS":    settings.MANAGED_DOMAINS,
        "CERT_STORE_PATH":    settings.CERT_STORE_PATH,
        "ACCOUNT_KEY_PATH":   settings.ACCOUNT_KEY_PATH,
        "HTTP_CHALLENGE_MODE": settings.HTTP_CHALLENGE_MODE,
        "WEBROOT_PATH":       settings.WEBROOT_PATH,
        "ACME_INSECURE":      settings.ACME_INSECURE,
        "ACME_CA_BUNDLE":     settings.ACME_CA_BUNDLE,
        "MAX_RETRIES":        settings.MAX_RETRIES,
        "ANTHROPIC_API_KEY":  settings.ANTHROPIC_API_KEY,
        "LLM_DISABLED":       settings.LLM_DISABLED,
    }

    webroot = tmp_path / "webroot"
    webroot.mkdir()
    cert_store = tmp_path / "certs"
    cert_store.mkdir()
    account_key = tmp_path / "account.key"

    settings.CA_PROVIDER        = "custom"
    settings.ACME_DIRECTORY_URL = f"https://{_PEBBLE_HOST}:14000/dir"
    settings.ACME_EAB_KEY_ID    = ""
    settings.ACME_EAB_HMAC_KEY  = ""
    settings.MANAGED_DOMAINS    = ["acme-test.localhost"]
    settings.CERT_STORE_PATH    = str(cert_store)
    settings.ACCOUNT_KEY_PATH   = str(account_key)
    settings.HTTP_CHALLENGE_MODE = "webroot"
    settings.WEBROOT_PATH       = str(webroot)
    settings.ACME_INSECURE      = True
    settings.ACME_CA_BUNDLE     = ""
    settings.MAX_RETRIES        = 1
    settings.ANTHROPIC_API_KEY  = "dummy-key-for-testing"  # For LLM credential check

    yield settings

    for k, v in originals.items():
        setattr(settings, k, v)


# ─── DNS-01 settings fixture ──────────────────────────────────────────────────

@pytest.fixture()
def dns_settings(pebble_settings):
    """
    Extend pebble_settings to use DNS-01 challenge mode with a mocked provider.
    """
    from config import settings

    dns_originals = {
        "HTTP_CHALLENGE_MODE":        settings.HTTP_CHALLENGE_MODE,
        "DNS_PROVIDER":               settings.DNS_PROVIDER,
        "DNS_PROPAGATION_WAIT_SECONDS": settings.DNS_PROPAGATION_WAIT_SECONDS,
        "CLOUDFLARE_API_TOKEN":       settings.CLOUDFLARE_API_TOKEN,
    }

    settings.HTTP_CHALLENGE_MODE = "dns"
    settings.DNS_PROVIDER = "cloudflare"
    settings.DNS_PROPAGATION_WAIT_SECONDS = 0
    settings.CLOUDFLARE_API_TOKEN = "fake-token-for-testing"

    yield settings

    for k, v in dns_originals.items():
        setattr(settings, k, v)


# ─── SPIRE settings fixture ────────────────────────────────────────────────────

@pytest.fixture()
def spire_settings(tmp_path: Path):
    """
    Mutate the live settings singleton to point at the local SPIRE harness,
    restore original values after the test. Mirrors pebble_settings.
    """
    from config import settings

    originals = {
        "CERT_ISSUANCE_MODE":      settings.CERT_ISSUANCE_MODE,
        "SPIRE_AGENT_SOCKET_PATH": settings.SPIRE_AGENT_SOCKET_PATH,
        "SPIFFE_TRUST_DOMAIN":     settings.SPIFFE_TRUST_DOMAIN,
        "MANAGED_SPIFFE_IDS":      settings.MANAGED_SPIFFE_IDS,
        "CERT_STORE_PATH":         settings.CERT_STORE_PATH,
        "MAX_RETRIES":             settings.MAX_RETRIES,
        "ANTHROPIC_API_KEY":       settings.ANTHROPIC_API_KEY,
        "LLM_DISABLED":            settings.LLM_DISABLED,
    }

    cert_store = tmp_path / "certs"
    cert_store.mkdir()

    settings.CERT_ISSUANCE_MODE = "spiffe"
    settings.SPIRE_AGENT_SOCKET_PATH = _SPIRE_AGENT_SOCKET_PATH
    settings.SPIFFE_TRUST_DOMAIN = "example.org"
    settings.MANAGED_SPIFFE_IDS = ["spiffe://example.org/workload/demo"]
    settings.CERT_STORE_PATH = str(cert_store)
    settings.MAX_RETRIES = 1
    settings.ANTHROPIC_API_KEY = "dummy-key-for-testing"

    yield settings

    for k, v in originals.items():
        setattr(settings, k, v)


# ─── LLM mock helpers ─────────────────────────────────────────────────────────
# Scoped to the renewal planner only — error_handler/reporter's LLM paths were
# removed in task:0fecd30e and stay removed (task:362053db restores the
# planner's LLM path only).

def _mock_llm_response(content: str) -> MagicMock:
    """Return a mock that behaves like a chat model instance.

    llm.invoke() must return a real AIMessage so LangGraph's add_messages
    reducer can accept it — MagicMock is not a BaseMessage subclass.
    """
    llm = MagicMock()
    llm.invoke.return_value = AIMessage(content=content)
    return llm


PLANNER_RESPONSE = json.dumps({
    "urgent": [],
    "routine": ["acme-test.localhost"],
    "skip": [],
    "notes": "Test run — renew acme-test.localhost",
})


@pytest.fixture()
def mock_llm_nodes():
    """
    Patch init_chat_model in llm.factory so tests don't need an API key.
    Returns a planner-compatible response.
    """
    with patch(
        "llm.factory.init_chat_model",
        return_value=_mock_llm_response(PLANNER_RESPONSE),
    ):
        yield
