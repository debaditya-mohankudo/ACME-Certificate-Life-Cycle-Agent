"""
Node registry for centralized node management.

The registry maps node names to callable classes.
The factory function instantiates classes.
"""
from __future__ import annotations

from agent.nodes.account import AcmeAccountSetupNode
from agent.nodes.challenge import ChallengeSetupNode, ChallengeVerifierNode
from agent.nodes.csr import CsrGeneratorNode
from agent.nodes.error_handler import ErrorHandlerNode
from agent.nodes.finalizer import CertDownloaderNode, OrderFinalizerNode
from agent.nodes.order import OrderInitializerNode
from agent.nodes.planner import RenewalPlannerNode
from agent.nodes.reporter import RevocationReporterNode, SummaryReporterNode
from agent.nodes.retry_scheduler import RetrySchedulerNode
from agent.nodes.revocation_router import PickNextRevocationDomainNode
from agent.nodes.router import PickNextDomainNode
from agent.nodes.revoker import CertRevokerNode
from agent.nodes.scanner import CertificateScannerNode
from agent.nodes.spiffe_attestor import SpiffeAttestorNode
from agent.nodes.storage import StorageManagerNode


# Registry maps node name → callable class
NODE_REGISTRY = {
    # Renewal graph nodes
    "certificate_scanner": CertificateScannerNode,
    "renewal_planner": RenewalPlannerNode,
    "acme_account_setup": AcmeAccountSetupNode,
    "pick_next_domain": PickNextDomainNode,
    "order_initializer": OrderInitializerNode,
    "challenge_setup": ChallengeSetupNode,
    "challenge_verifier": ChallengeVerifierNode,
    "csr_generator": CsrGeneratorNode,
    "order_finalizer": OrderFinalizerNode,
    "cert_downloader": CertDownloaderNode,
    "storage_manager": StorageManagerNode,
    "spiffe_attestor": SpiffeAttestorNode,
    "error_handler": ErrorHandlerNode,
    "retry_scheduler": RetrySchedulerNode,
    "summary_reporter": SummaryReporterNode,
    # Revocation graph nodes
    "revocation_account_setup": AcmeAccountSetupNode,
    "pick_next_revocation_domain": PickNextRevocationDomainNode,
    "cert_revoker": CertRevokerNode,
    "revocation_reporter": RevocationReporterNode,
}


def get_node(name: str):
    """
    Factory: instantiate node callable by name.

    Classes are instantiated.

    Args:
        name: Node name from NODE_REGISTRY

    Returns:
        Callable node instance

    Raises:
        KeyError: If node name not in registry
    """
    node_cls = NODE_REGISTRY[name]

    if not isinstance(node_cls, type):
        raise TypeError(
            f"Registry entry '{name}' must be a class, got {type(node_cls).__name__}"
        )

    return node_cls()
