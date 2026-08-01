package AcmeAgentSystem {
    doc /* Structural model of the certificate lifecycle agent.
         *
         * Parts are named for responsibility, not for directory layout, and
         * the two diverge in places: the challenge responders live under both
         * acme/ and agent/nodes/ but form one part, while agent/nodes/ splits
         * across three parts because orchestration, failure policy, and
         * revocation own different rules.
         *
         * The central seam is that PROTOCOL MECHANICS and WORKFLOW ORDERING
         * are separate parts. The client knows how to sign, send, and parse;
         * it holds no workflow state and decides nothing about sequence. The
         * workflow knows what happens next and holds everything; it does not
         * know how a request is signed. That split is what allows the ordering
         * to be reviewed for determinism without re-reviewing the protocol,
         * and vice versa.
         *
         * ONE SYSTEM, TWO ISSUANCE MODES. AcmeRenewalWorkflow and
         * SpiffeIssuance are alternative middles sharing a common entry
         * (certificate scanning) and terminus (summary reporting). They are
         * never both wired into the same compiled graph. Modelling them as
         * peers rather than as one parameterised part matches the code and
         * keeps the ACME protocol requirements from appearing to constrain a
         * mode that does not speak ACME at all. */

    private import Foundation::Foundation;

    part def AcmeProtocolClient {
        doc /* The stateless protocol layer: directory lookup, JWS signing,
             * nonce handling, key and CSR cryptography, and CA detection.
             * Corresponds to acme/client.py, acme/jws.py, acme/crypto.py and
             * acme/ca_detection.py.
             *
             * Stateless is the whole claim. It holds no hidden mutable state
             * between calls, so a request is a pure function of its arguments
             * and the workflow remains the single place where sequence and
             * accumulated state live. */
        part foundation : Foundation;
    }

    part def ChallengeResponder {
        doc /* Proving control of a domain and, just as importantly, undoing
             * the proof afterwards. Covers the HTTP-01 standalone server, the
             * webroot writer, the DNS-01 TXT publisher, and the challenge node
             * that drives them. Corresponds to acme/http_challenge.py,
             * acme/dns_challenge.py and agent/nodes/challenge.py.
             *
             * This is the one part that deliberately holds mutable state
             * outside the workflow — a live listening socket or a published
             * DNS record cannot be represented as a value in a state
             * dictionary. That state is scoped to a single domain's challenge
             * and is torn down before control returns, which is what keeps the
             * exception to "explicit state over hidden state" narrow enough to
             * be safe. */
        part foundation : Foundation;
    }

    part def AcmeRenewalWorkflow {
        doc /* The deterministic orchestration: which domains need renewing,
             * in what order, and what happens after each step. Owns the
             * workflow state schema. Corresponds to agent/graph.py,
             * agent/state.py, and the business nodes — scanner, planner,
             * account, order, csr, finalizer, router, registry.
             *
             * Sequential by construction: one domain at a time, one protocol
             * operation at a time. That is a design commitment rather than an
             * unfinished optimisation, because concurrent operations would
             * make nonce handling and failure attribution ambiguous. */
        part foundation : Foundation;
    }

    part def FailurePolicy {
        doc /* Classification of failures and the bounded response to them:
             * fatal versus retryable, backoff computation, the retry gate, and
             * the routing decision that follows. Corresponds to
             * agent/nodes/error_handler.py, agent/nodes/retry_scheduler.py and
             * agent/nodes/router.py.
             *
             * Separated from AcmeRenewalWorkflow on purpose. Retry rules
             * embedded in business nodes are the classic way a bounded retry
             * policy silently becomes an unbounded one — each node grows its
             * own slightly different rule and no single place remains that can
             * be read to answer "how hard does this try?". Keeping the
             * classification and the gate in one part means that question has
             * exactly one answer. */
        part foundation : Foundation;
    }

    part def CertificateStore {
        doc /* Durable certificate material on disk: atomic writes, chain
             * splitting, and file permissions. Corresponds to
             * storage/atomic.py, storage/filesystem.py and
             * agent/nodes/storage.py.
             *
             * Atomicity here is a correctness property, not tidiness. A
             * partially written certificate is indistinguishable from a valid
             * one to whatever serves it, so the state after an interrupted run
             * has to be either the old material or the new material and never
             * a blend. */
        part foundation : Foundation;
    }

    part def RevocationWorkflow {
        doc /* Revoking certificates as a separate graph with its own routing.
             * Corresponds to agent/revocation_graph.py, agent/nodes/revoker.py
             * and agent/nodes/revocation_router.py.
             *
             * Best-effort by design, and deliberately unlike renewal: one
             * domain failing to revoke must not stop the others. Renewal can
             * afford to abort a run and try again on schedule; revocation is
             * usually reactive, so getting most of the way through beats
             * stopping at the first refusal. */
        part foundation : Foundation;
    }

    part def SpiffeIssuance {
        doc /* The alternative issuance mode: obtaining identity documents by
             * workload attestation rather than by ACME challenge. Corresponds
             * to agent/nodes/spiffe_attestor.py and the spire/ deployment.
             *
             * Terminal by design — a failed attestation is not retried within
             * the domain iteration, because attestation failure means the
             * workload is not who it claims to be, and retrying that is
             * neither meaningful nor safe. */
        part foundation : Foundation;
    }

    part def ControlSurfaces {
        doc /* The ways a human or another program drives the agent: the CLI,
             * the MCP server, and the terminal UI. Corresponds to main.py,
             * mcp_server.py and tui/.
             *
             * Everything reaching the system from outside crosses here, which
             * makes it the right place for input validation — notably the
             * guard preventing a caller-supplied domain from escaping the
             * configured certificate directory — and for serialising mutating
             * calls so two of them cannot reconfigure the process at once. */
        part foundation : Foundation;
    }

    part def System {
        doc /* The whole agent. Every part is reachable from here. */
        part protocolClient : AcmeProtocolClient;
        part challengeResponder : ChallengeResponder;
        part renewalWorkflow : AcmeRenewalWorkflow;
        part failurePolicy : FailurePolicy;
        part certificateStore : CertificateStore;
        part revocationWorkflow : RevocationWorkflow;
        part spiffeIssuance : SpiffeIssuance;
        part controlSurfaces : ControlSurfaces;
        part foundation : Foundation;
    }
}
