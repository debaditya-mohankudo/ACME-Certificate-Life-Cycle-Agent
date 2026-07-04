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
# AcmeConfig/SpiffeConfig are two separate classes — only one is ever
# instantiated (config.make_settings()), so these fixtures swap the whole
# config.settings singleton object rather than mutating individual fields.

@pytest.fixture()
def pebble_settings(tmp_path: Path):
    """
    Replace the live settings singleton with an AcmeConfig pointed at local
    Pebble, restore the original singleton object after the test.
    """
    import config
    from config import AcmeConfig

    original_settings = config.settings

    webroot = tmp_path / "webroot"
    webroot.mkdir()
    cert_store = tmp_path / "certs"
    cert_store.mkdir()
    account_key = tmp_path / "account.key"

    config.settings = AcmeConfig(
        CA_PROVIDER="custom",
        ACME_DIRECTORY_URL=f"https://{_PEBBLE_HOST}:14000/dir",
        ACME_EAB_KEY_ID="",
        ACME_EAB_HMAC_KEY="",
        MANAGED_DOMAINS=["acme-test.localhost"],
        CERT_STORE_PATH=str(cert_store),
        ACCOUNT_KEY_PATH=str(account_key),
        HTTP_CHALLENGE_MODE="webroot",
        WEBROOT_PATH=str(webroot),
        ACME_INSECURE=True,
        ACME_CA_BUNDLE="",
        MAX_RETRIES=1,
        ANTHROPIC_API_KEY="dummy-key-for-testing",  # For LLM credential check
    )

    yield config.settings

    config.settings = original_settings


# ─── DNS-01 settings fixture ──────────────────────────────────────────────────

@pytest.fixture()
def dns_settings(pebble_settings):
    """
    Extend pebble_settings to use DNS-01 challenge mode with a mocked provider.

    Mutates the already-swapped AcmeConfig instance's attrs directly — no
    separate restore needed, since pebble_settings' own teardown discards the
    whole object (DNS-field mutations included).
    """
    pebble_settings.HTTP_CHALLENGE_MODE = "dns"
    pebble_settings.DNS_PROVIDER = "cloudflare"
    pebble_settings.DNS_PROPAGATION_WAIT_SECONDS = 0
    pebble_settings.CLOUDFLARE_API_TOKEN = "fake-token-for-testing"

    yield pebble_settings


# ─── SPIRE settings fixture ────────────────────────────────────────────────────

@pytest.fixture()
def spire_settings(tmp_path: Path):
    """
    Replace the live settings singleton with a SpiffeConfig pointed at the
    local SPIRE harness, restore the original singleton object after the test.
    """
    import config
    from config import SpiffeConfig

    original_settings = config.settings

    cert_store = tmp_path / "certs"
    cert_store.mkdir()

    config.settings = SpiffeConfig(
        SPIRE_AGENT_SOCKET_PATH=_SPIRE_AGENT_SOCKET_PATH,
        SPIFFE_TRUST_DOMAIN="example.org",
        MANAGED_SPIFFE_IDS=["spiffe://example.org/workload/demo"],
        CERT_STORE_PATH=str(cert_store),
        MAX_RETRIES=1,
        ANTHROPIC_API_KEY="dummy-key-for-testing",
    )

    yield config.settings

    config.settings = original_settings


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
