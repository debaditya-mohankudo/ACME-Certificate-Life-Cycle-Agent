"""
storage_manager node — write PEM files for the just-renewed certificate.

Splits the full PEM chain from DigiCert into:
  cert.pem      — leaf certificate (first PEM block)
  chain.pem     — intermediate CA chain (remaining PEM blocks)
  fullchain.pem — cert + chain concatenated
  privkey.pem   — already written by csr_generator (just chmod check)
  metadata.json — issued_at, expires_at, acme_order_url
"""
from __future__ import annotations

import config
from pathlib import Path

from storage import filesystem as fs
from agent.state import AgentState

from logger import logger


class StorageManagerNode:
    """Callable storage manager implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        domain = state["current_domain"]
        if not domain:
            return {"error_log": state.get("error_log", []) + ["storage_manager called with no current_domain"]}
        cert_store_path = state["cert_store_path"]
        order = state.get("current_order") or {}

        full_chain_pem: str = order.get("full_chain_pem", "")
        if not full_chain_pem:
            error = f"storage_manager: no full_chain_pem in state for {domain}"
            logger.error(error)
            return {
                "failed_renewals": state.get("failed_renewals", []) + [domain],
                "error_log": state.get("error_log", []) + [error],
            }

        cert_pem, chain_pem = _split_pem_chain(full_chain_pem)

        safe_domain = fs.sanitize_domain_for_path(domain)
        privkey_path = Path(cert_store_path) / safe_domain / "privkey.pem"
        if not privkey_path.exists():
            error = f"storage_manager: privkey.pem not found for {domain}"
            logger.error(error)
            return {
                "failed_renewals": state.get("failed_renewals", []) + [domain],
                "error_log": state.get("error_log", []) + [error],
            }
        privkey_pem = privkey_path.read_text()

        try:
            metadata = fs.write_cert_files(
                cert_store_path=cert_store_path,
                domain=domain,
                cert_pem=cert_pem,
                chain_pem=chain_pem,
                privkey_pem=privkey_pem,
                acme_order_url=order.get("order_url", ""),
                # CA_PROVIDER only exists on AcmeConfig — this node is shared with the
                # spiffe graph (agent/graph.py), where config.settings is a SpiffeConfig.
                ca_provider=getattr(config.settings, "CA_PROVIDER", "spiffe"),
            )
        except Exception as exc:
            error = f"storage_manager: failed to write PEM files for {domain}: {exc}"
            logger.error(error)
            return {
                "failed_renewals": state.get("failed_renewals", []) + [domain],
                "error_log": state.get("error_log", []) + [error],
            }

        logger.info(
            "Stored PEM files for %s (expires %s)",
            domain,
            metadata.get("expires_at", "?")[:10],
        )

        existing_metadata = dict(state.get("cert_metadata") or {})
        existing_metadata[domain] = metadata

        return {
            "completed_renewals": state.get("completed_renewals", []) + [domain],
            "cert_metadata": existing_metadata,
        }


def storage_manager(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `StorageManagerNode`."""
    return StorageManagerNode().run(state)


def _split_pem_chain(full_chain: str) -> tuple[str, str]:
    """
    Split a PEM chain into (leaf_cert_pem, chain_pem).

    DigiCert returns: [leaf] [intermediate1] [intermediate2] ...
    The first PEM block is the leaf; the rest form the chain.
    """
    # Split on BEGIN CERTIFICATE boundaries
    blocks = []
    current: list[str] = []
    for line in full_chain.splitlines(keepends=True):
        current.append(line)
        if "-----END CERTIFICATE-----" in line:
            blocks.append("".join(current))
            current = []

    if not blocks:
        return full_chain, ""

    cert_pem = blocks[0]
    chain_pem = "".join(blocks[1:])
    return cert_pem, chain_pem
