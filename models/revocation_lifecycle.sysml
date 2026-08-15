package RevocationLifecycle {
    doc /* The ACME revocation workflow as a state machine.
         *
         * Ground truth, not inferred: every transition below is transcribed
         * from an add_edge or add_conditional_edges call in
         * agent/revocation_graph.py:build_revocation_graph. Where the code
         * routes conditionally, the branch names here are the code's own
         * route keys from agent/nodes/revocation_router.py — retry,
         * nextDomain, allDone — so a reader can match the model to the
         * routing function without guessing.
         *
         * A separate compiled graph, not a branch of RenewalLifecycle. It
         * shares no nodes with the renewal graph except by reuse of
         * acme_account_setup for account setup, and the two are never
         * compiled together.
         *
         * Read the shape rather than the node list: this is a LOOP over
         * domains with a single funnel out, same skeleton as
         * RenewalLifecycle's pickNextDomain loop. pickNextRevocationDomain is
         * re-entered only from certRevoker's allDone-adjacent nextDomain
         * branch; every path — a completed domain or an exhausted queue —
         * converges on revocationReporter before END.
         *
         * THE RETRY EDGE IS THE NARROWEST ONE IN EITHER GRAPH. retry loops
         * straight back to certRevoker for the SAME domain, not through
         * pickNextRevocationDomain — going through pick would advance to the
         * next domain instead of retrying this one, silently dropping the
         * failed domain. Contrast with RenewalLifecycle's errorHandler,
         * which is a separate node from the thing it routes out of; here the
         * retry-vs-advance decision is made by certRevoker's own router in
         * one step, because revocation has no distinct error-classification
         * node — cert_revoker classifies transient-vs-terminal inline (see
         * agent/nodes/revoker.py) and the router only reads
         * retry_not_before.
         *
         * BEST-EFFORT, NOT ABORT. There is no abort transition here, unlike
         * RenewalLifecycle's errorHandler-to-summaryReporter abort edge. A
         * domain that exhausts its retry budget or fails for a non-transient
         * reason (unauthorized, alreadyRevoked, malformed, missing local
         * cert file) is logged and the loop advances to the next domain via
         * nextDomain — never aborts the run. One domain's failure never
         * blocks another's revocation. See RevocationBestEffortRequirement
         * in requirements.sysml. */

    state def RevocationLifecycle {
        doc /* One run of the revocation agent, from account setup to report.
             * A loop over domains with a single funnel out: certRevoker is
             * re-entered for the same domain on retry, and
             * pickNextRevocationDomain is re-entered for the next domain on
             * either success or exhausted/terminal failure. Every path
             * converges on revocationReporter before END. */

        entry;

        state revocationAccountSetup;
        state pickNextRevocationDomain;
        state certRevoker;
        state retryScheduler;
        state revocationReporter;

        transition startToAccountSetup
            first revocationAccountSetup
            then pickNextRevocationDomain;

        transition pickDomainToRevoker
            first pickNextRevocationDomain
            then certRevoker;

        transition retry
            first certRevoker
            then retryScheduler;

        transition retrySchedulerToRevoker
            first retryScheduler
            then certRevoker;

        transition nextDomain
            first certRevoker
            then pickNextRevocationDomain;

        transition allDone
            first certRevoker
            then revocationReporter;
    }
}
