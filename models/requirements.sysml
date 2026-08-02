package Requirements {
    doc /* Requirements traced to the parts that satisfy them.
         *
         * SOURCING: every requirement below cites the file that implements it,
         * and none is aspirational — each one is satisfied by code that ships
         * today. Most were lifted from concept_store/concepts.json, whose
         * invariants are already stated against specific modules; the rest
         * from reading the modules directly.
         *
         * ALLOCATION: one satisfier per requirement. A requirement needing two
         * parts means a rule and the data it governs have drifted apart, and
         * the honest response is to record that rather than to split the
         * wording until it looks clean. No requirement below needed it.
         *
         * ONE BUILDER, TWO LIFETIMES — corrected from an earlier revision of
         * this file, which called the settings override a duplicated rule with
         * only one exception-safe copy. That was wrong, and the correction is
         * kept visible because the claim was committed and someone may have
         * read it.
         *
         * Construction is already shared: mcp_server.py imports
         * build_settings_from_override from main.py, so there is one
         * implementation of how an override is built. Only the application
         * differs, and it differs because the lifetimes do. The CLI replaces
         * the settings singleton once at startup and never restores it — the
         * process exits afterwards, so there is nothing to restore to and no
         * later caller to protect. The MCP server restores in a finally
         * because it is long-lived and serves many calls, where one call's
         * configuration leaking into the next would be a real defect.
         *
         * Two correct answers to different questions, not one rule
         * implemented twice. The lesson worth keeping: "the same thing is
         * done differently in two places" is a hypothesis, and the cheap test
         * is whether the two places have the same lifetime.
         *
         * DELIBERATELY ABSENT: no requirement constrains throughput, latency,
         * or concurrency-as-a-goal. Sequential processing is a commitment this
         * model records as structure, not a limitation to be lifted later.
         * There is also no requirement covering the terminal UI, which
         * presents state it does not own. */

    private import AcmeAgentSystem::*;

    part system : System;

    requirement def SingleIssuanceModeRequirement {
        doc /* Source: config.py. CERT_ISSUANCE_MODE resolves to exactly one
             * of acme or spiffe, and exactly one of AcmeConfig or SpiffeConfig
             * is instantiated per process. Mode-specific settings exist only
             * on the object for that mode, so reading an ACME field in SPIFFE
             * mode is an attribute error at the point of the mistake rather
             * than a silently empty value carried into a protocol call. */
    }
    satisfy requirement SingleIssuanceModeRequirement by system.foundation;

    requirement def ExternalAccountBindingCompletenessRequirement {
        doc /* Source: config.py. For providers that require external account
             * binding, the key id and the HMAC key must both be present or
             * both absent. A half-configured binding is rejected at startup
             * instead of failing mid-registration against the authority, where
             * the error surfaces as an opaque protocol rejection. */
    }
    satisfy requirement ExternalAccountBindingCompletenessRequirement by system.foundation;

    requirement def ReconstructableRunLogRequirement {
        doc /* Source: logger.py. Every log line is valid single-line JSON, and
             * one process-wide run id is generated at first construction and
             * never changes. Together these make a run reconstructable after
             * the fact from the log alone, which is the project's stated bar
             * for auditability. */
    }
    satisfy requirement ReconstructableRunLogRequirement by system.foundation;

    requirement def StatelessProtocolClientRequirement {
        doc /* Source: acme/client.py. The client carries no hidden mutable
             * state between calls; everything a request depends on is passed
             * in. This is what keeps the workflow the single place where
             * sequence and accumulated state live, and it is why the ordering
             * can be reviewed for determinism without re-reviewing the
             * protocol layer. */
    }
    satisfy requirement StatelessProtocolClientRequirement by system.protocolClient;

    requirement def PrivateKeyNeverInWorkflowStateRequirement {
        doc /* Source: agent/state.py, agent/nodes/account.py,
             * agent/nodes/csr.py. Neither the account key nor any domain
             * private key appears in AgentState — the account key stays on
             * disk and is loaded at point of use, and generated domain keys
             * are written straight to disk with owner-only permissions.
             *
             * Absolute rather than best-effort, because workflow state is
             * checkpointed, logged, and passed between nodes: a key that
             * enters it has effectively been published, and that is the one
             * failure here no rerun can undo. */
    }
    satisfy requirement PrivateKeyNeverInWorkflowStateRequirement by system.renewalWorkflow;

    requirement def SequentialDomainProcessingRequirement {
        doc /* Source: agent/graph.py. Domains are processed one at a time
             * through a single loop, and no protocol operation overlaps
             * another. Sequential execution is what makes nonce consumption
             * and failure attribution unambiguous; concurrency here would
             * require redesigning both. */
    }
    satisfy requirement SequentialDomainProcessingRequirement by system.renewalWorkflow;

    requirement def DomainScopeIntegrityRequirement {
        doc /* Source: agent/nodes/planner.py. Every managed domain lands in
             * exactly one of urgent, routine, or skip, and nothing outside the
             * managed set can enter the renewal queue — including from an
             * inferred classification, whose output is validated against the
             * managed set before use.
             *
             * This is the concrete form of "automated judgment is advisory":
             * a suggestion may reorder or defer work, never widen its
             * scope. */
    }
    satisfy requirement DomainScopeIntegrityRequirement by system.renewalWorkflow;

    requirement def PerDomainStateResetRequirement {
        doc /* Source: agent/nodes/router.py. Picking a new domain resets the
             * order, the nonce, and the retry count. Without this, state from
             * a failed domain leaks into the next one and produces failures
             * attributable to the wrong domain — the exact class of bug
             * sequential processing exists to prevent. */
    }
    satisfy requirement PerDomainStateResetRequirement by system.renewalWorkflow;

    requirement def ChallengeTeardownRequirement {
        doc /* Source: agent/nodes/challenge.py. Whatever proved control is
             * removed before control returns: the standalone server stopped,
             * the webroot token deleted, or the DNS TXT record withdrawn. The
             * responder's mutable state exists only while a challenge is being
             * served for the current domain.
             *
             * Teardown is a security property, not tidiness — a listening
             * socket or a stale published record that outlives its challenge
             * is exposed surface nobody is watching. */
    }
    satisfy requirement ChallengeTeardownRequirement by system.challengeResponder;

    requirement def NoRedundantChallengeResponseRequirement {
        doc /* Source: agent/nodes/challenge.py. An authorization already in
             * the valid state is never answered again. Re-answering a settled
             * authorization is wasted protocol traffic against someone else's
             * production system and risks rate limiting for no gain. */
    }
    satisfy requirement NoRedundantChallengeResponseRequirement by system.challengeResponder;

    requirement def BoundedRetryRequirement {
        doc /* Source: agent/nodes/error_handler.py,
             * agent/nodes/retry_scheduler.py. Retries are honoured only below
             * the configured limit, backoff is capped, and the retry marker is
             * always cleared after the scheduler runs whether or not it
             * waited.
             *
             * The cap and the clear are what keep "bounded" true in practice:
             * an uncapped backoff is indistinguishable from a hang, and a
             * marker that survives its own wait causes the next pass to wait
             * again. */
    }
    satisfy requirement BoundedRetryRequirement by system.failurePolicy;

    requirement def FatalErrorTerminatesRunRequirement {
        doc /* Source: agent/nodes/error_handler.py. Errors matching the fatal
             * patterns force an abort regardless of remaining retries, and the
             * abort clears pending renewals and marks them failed.
             *
             * Deliberately asymmetric with retryable failures: a fatal error
             * means the configuration or credentials are wrong, and retrying
             * that against an authority earns a rate limit rather than a
             * certificate. Failing the whole run loudly is the cheaper
             * outcome. */
    }
    satisfy requirement FatalErrorTerminatesRunRequirement by system.failurePolicy;

    requirement def StructuredErrorRoutingRequirement {
        doc /* Source: agent/nodes/router.py. The routing decision is read from
             * a structured action field and never re-parsed out of error prose.
             * Deciding control flow by matching on human-readable text makes
             * behaviour depend on message wording, which changes without
             * notice and is not part of anyone's contract. */
    }
    satisfy requirement StructuredErrorRoutingRequirement by system.failurePolicy;

    requirement def AtomicCertificateWriteRequirement {
        doc /* Source: storage/atomic.py. Certificate material is written so
             * that an interrupted run leaves either the previous material or
             * the new material, never a blend. A truncated certificate is
             * indistinguishable from a valid one to whatever serves it, so
             * partial writes fail in production rather than at write time. */
    }
    satisfy requirement AtomicCertificateWriteRequirement by system.certificateStore;

    requirement def LeafFirstChainOrderRequirement {
        doc /* Source: agent/nodes/storage.py. The first PEM block of the
             * stored chain is always the leaf for the requested domain, with
             * intermediates following. Servers and clients rely on this
             * ordering; getting it wrong produces a chain that validates in
             * some tools and fails in others, which is far harder to diagnose
             * than an outright rejection. */
    }
    satisfy requirement LeafFirstChainOrderRequirement by system.certificateStore;

    requirement def RevocationBestEffortRequirement {
        doc /* Source: agent/revocation_graph.py. One domain failing to revoke
             * never halts the remaining targets.
             *
             * Deliberately unlike renewal, which aborts the run on a fatal
             * error. Renewal can wait for the next schedule; revocation is
             * usually reactive, so revoking most of the set beats stopping at
             * the first refusal and leaving the rest live. */
    }
    satisfy requirement RevocationBestEffortRequirement by system.revocationWorkflow;

    requirement def AttestationFailureIsTerminalRequirement {
        doc /* Source: agent/graph.py, agent/nodes/spiffe_attestor.py. A failed
             * attestation is never retried within the domain iteration, and
             * the failure must still allow the loop to advance to the next
             * domain.
             *
             * Not retrying is the point: attestation failing means the
             * workload is not who it claims to be, and asking again does not
             * change that. Renewal's retry policy would be actively wrong
             * here, which is why the two modes are modelled as peers rather
             * than sharing one failure path. */
    }
    satisfy requirement AttestationFailureIsTerminalRequirement by system.spiffeIssuance;

    requirement def CertificatePathConfinementRequirement {
        doc /* Source: mcp_server.py. A caller-supplied domain cannot contain
             * path separators, parent-directory references, or a leading dot,
             * and generated material always lands under the configured
             * certificate directory.
             *
             * The MCP surface accepts input from another program rather than
             * from a person reading a prompt, so a domain name reaching it is
             * untrusted input in the ordinary security sense. */
    }
    satisfy requirement CertificatePathConfinementRequirement by system.controlSurfaces;

    requirement def SerializedMutatingCallRequirement {
        doc /* Source: mcp_server.py. Mutating tool calls are serialised so
             * only one reconfigures process-global settings at a time, while
             * read-only tools never block on that lock.
             *
             * The agent keeps resolved settings in a process singleton, so two
             * concurrent callers each overriding it would interleave into a
             * configuration neither asked for. Serialising the mutators is the
             * narrow fix; making the settings immutable per call would be the
             * broad one. */
    }
    satisfy requirement SerializedMutatingCallRequirement by system.controlSurfaces;

    requirement def ReadOnlyQueryPurityRequirement {
        doc /* Source: main.py. The status and expiry query commands neither
             * mutate the certificate store nor contact any issuing authority.
             * An inspection command with side effects is a trap: it gets run
             * reflexively during an incident, which is exactly when an
             * unintended write or an unexpected protocol call is least
             * affordable. */
    }
    satisfy requirement ReadOnlyQueryPurityRequirement by system.controlSurfaces;
}
