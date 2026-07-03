"""
spiffe_attestor node — fetch (or rotate) an SVID for the current SPIFFE ID
via the SPIRE Agent's Workload API, over its local Unix domain socket.

This is the SPIFFE-mode analogue of the ACME account/order/challenge/csr/
finalizer chain: no HTTP-01/DNS-01 challenge and no directory URL, since
authentication already happened via node + workload attestation before the
Workload API will hand back an SVID at all (see doc/SPIRE_TESTING_SERVER.md).
A permission-denied response from an unregistered workload is expected,
non-fatal behavior, not a crash — same treatment as any other ACME error.

Writes privkey.pem itself (mirroring csr_generator's role in the ACME flow,
since the SPIRE Agent hands back both cert and key together) and populates
state["current_order"]["full_chain_pem"] so the existing storage_manager
node can be reused unchanged.
"""
from __future__ import annotations

import os
import stat

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

import config
from agent.state import AgentState
from storage import filesystem as fs

from logger import logger

try:
    from spiffe import WorkloadApiClient
    from spiffe.errors import ArgumentError
    from spiffe.workloadapi.errors import FetchX509SvidError
    _SPIFFE_AVAILABLE = True
except ImportError:
    _SPIFFE_AVAILABLE = False
    WorkloadApiClient = None  # type: ignore[assignment,misc]
    ArgumentError = Exception  # type: ignore[assignment,misc]
    FetchX509SvidError = Exception  # type: ignore[assignment,misc]


class SpiffeAttestorNode:
    """Callable SPIFFE attestor node implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        spiffe_id = state["current_domain"]
        if not spiffe_id:
            return {
                "error_log": state.get("error_log", [])
                + ["spiffe_attestor called with no current_domain (expected a SPIFFE ID)"]
            }

        if not _SPIFFE_AVAILABLE:
            error = (
                "spiffe_attestor: the `spiffe` package is not installed. "
                "Install with: uv sync --extra spiffe"
            )
            logger.error(error)
            return {
                "failed_renewals": state.get("failed_renewals", []) + [spiffe_id],
                "error_log": state.get("error_log", []) + [error],
            }

        socket_path = config.settings.SPIRE_AGENT_SOCKET_PATH
        logger.info(
            "spiffe_attestor: fetching SVID for %s via %s", spiffe_id, socket_path
        )

        try:
            client = WorkloadApiClient(socket_path=f"unix://{socket_path}")
        except ArgumentError as exc:
            error = f"spiffe_attestor: invalid SPIRE_AGENT_SOCKET_PATH ({socket_path!r}): {exc}"
            logger.error(error)
            return {
                "failed_renewals": state.get("failed_renewals", []) + [spiffe_id],
                "error_log": state.get("error_log", []) + [error],
            }

        try:
            svids = client.fetch_x509_svids()
        except FetchX509SvidError as exc:
            error = f"spiffe_attestor: failed to fetch SVID for {spiffe_id}: {exc}"
            logger.error(error)
            return {
                "failed_renewals": state.get("failed_renewals", []) + [spiffe_id],
                "error_log": state.get("error_log", []) + [error],
            }
        finally:
            client.close()

        svid = next((s for s in svids if str(s.spiffe_id) == spiffe_id), None)
        if svid is None:
            fetched_ids = [str(s.spiffe_id) for s in svids]
            error = (
                f"spiffe_attestor: no SVID matching {spiffe_id} among the SVIDs the "
                f"Workload API returned ({fetched_ids}) — refusing to store a "
                f"different identity's credentials under this domain's directory"
            )
            logger.error(error)
            return {
                "failed_renewals": state.get("failed_renewals", []) + [spiffe_id],
                "error_log": state.get("error_log", []) + [error],
            }

        cert_pem = svid.leaf.public_bytes(Encoding.PEM).decode()
        chain_pem = "".join(
            cert.public_bytes(Encoding.PEM).decode() for cert in svid.cert_chain
        )
        privkey_pem = svid.private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        ).decode()

        cert_store_path = state["cert_store_path"]
        privkey_path = fs.cert_dir(cert_store_path, spiffe_id) / "privkey.pem"
        privkey_path.write_text(privkey_pem)
        os.chmod(privkey_path, stat.S_IRUSR | stat.S_IWUSR)

        return {
            "current_order": {"full_chain_pem": cert_pem + chain_pem},
        }
