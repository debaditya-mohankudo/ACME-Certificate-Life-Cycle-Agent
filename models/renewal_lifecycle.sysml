package RenewalLifecycle {
    doc /* The ACME renewal workflow as a state machine.
         *
         * Ground truth, not inferred: every transition below is transcribed
         * from an add_edge or add_conditional_edges call in
         * agent/graph.py:build_graph. Where the code routes conditionally, the
         * branch names here are the code's own route keys — renewalsNeeded,
         * noRenewals, challengeOk, challengeFailed, nextDomain, allDone, retry,
         * skipDomain, abort — so a reader can match the model to the routing
         * functions without guessing.
         *
         * Read the shape rather than the node list: this is a LOOP over
         * domains with a single funnel out. pickNextDomain is re-entered from
         * three distinct places — a successful store, a skipped domain, and a
         * scheduled retry — and every terminal path, success or failure,
         * converges on summaryReporter before END. Nothing exits the machine
         * early, which is what makes a run always produce a report.
         *
         * THE RETRY EDGE IS THE SUBTLE ONE. errorHandler never returns
         * straight to pickNextDomain on a retry decision; it routes through
         * retryScheduler first, so backoff is applied by a node in the graph
         * rather than by a sleep buried in business logic. skipDomain, by
         * contrast, goes directly back with no wait. Collapsing those two into
         * one edge would silently remove the backoff.
         *
         * Not modelled: the SPIFFE variant built by the same module. It shares
         * the entry and terminus but replaces the whole middle, and drawing
         * both here would suggest a single machine with optional states when
         * the code compiles one or the other. Its distinguishing rule — a
         * failed attestation is terminal for that domain, never retried —
         * lives in the requirements model instead. */

    state def RenewalLifecycle {
        doc /* One run of the renewal agent, from scan to report. A loop over
             * domains with a single funnel out: pickNextDomain is re-entered
             * from a successful store, a skipped domain, and a scheduled
             * retry, and every path — success, skip, abort — converges on
             * summaryReporter before END. */

        entry;

        state certificateScanner;
        state renewalPlanner;
        state acmeAccountSetup;
        state pickNextDomain;
        state orderInitializer;
        state challengeSetup;
        state challengeVerifier;
        state csrGenerator;
        state orderFinalizer;
        state certDownloader;
        state storageManager;
        state errorHandler;
        state retryScheduler;
        state summaryReporter;

        transition startToScanner
            first certificateScanner
            then renewalPlanner;

        transition renewalsNeeded
            first renewalPlanner
            then acmeAccountSetup;

        transition noRenewals
            first renewalPlanner
            then summaryReporter;

        transition accountToPickDomain
            first acmeAccountSetup
            then pickNextDomain;

        transition pickDomainToOrder
            first pickNextDomain
            then orderInitializer;

        transition orderToChallengeSetup
            first orderInitializer
            then challengeSetup;

        transition challengeSetupToVerifier
            first challengeSetup
            then challengeVerifier;

        transition challengeOk
            first challengeVerifier
            then csrGenerator;

        transition challengeFailed
            first challengeVerifier
            then errorHandler;

        transition csrToFinalizer
            first csrGenerator
            then orderFinalizer;

        transition finalizerToDownloader
            first orderFinalizer
            then certDownloader;

        transition downloaderToStorage
            first certDownloader
            then storageManager;

        transition nextDomain
            first storageManager
            then pickNextDomain;

        transition allDone
            first storageManager
            then summaryReporter;

        transition retry
            first errorHandler
            then retryScheduler;

        transition skipDomain
            first errorHandler
            then pickNextDomain;

        transition abort
            first errorHandler
            then summaryReporter;

        transition retrySchedulerToPickDomain
            first retryScheduler
            then pickNextDomain;
    }
}
