package Foundation {
    doc /* Cross-cutting settings resolution and structured logging. A shared
         * dependency of every other part rather than a peer subsystem.
         *
         * Corresponds to config.py and logger.py.
         *
         * Two properties are load-bearing elsewhere in this model and are
         * recorded here because they are easy to lose in a refactor:
         *
         *   1. Issuance mode is resolved ONCE, into exactly one settings
         *      object. config.settings is either an AcmeConfig or a
         *      SpiffeConfig, never a union carrying both field sets. Every
         *      "which mode are we in" decision downstream — including which
         *      node set gets wired into the graph — reads that single
         *      resolution rather than re-deriving it.
         *
         *   2. The logger is a process singleton whose run id is generated at
         *      first construction and never changes. Every log line is
         *      single-line JSON. This is what makes a run reconstructable
         *      after the fact, which is the project's stated bar for
         *      auditability. */

    part def Foundation {
        doc /* One resolved settings object, one process logger with one
             * immutable run id — see the package doc for why both are
             * load-bearing. */
    }
}
