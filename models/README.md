# models/

SysML v2 model of this codebase — structure and requirements, kept in sync
with the code rather than describing an aspiration. Per the project's
top-level rule, these files (alongside the rest of `doc/`) are constitutional:
where they and the code disagree, read the code and fix whichever is wrong,
but treat drift as a bug either way.

- **`foundation.sysml`** — the cross-cutting settings resolution and
  structured logging shared by every other part (`config.py`, `logger.py`).
- **`acme_agent_system.sysml`** — the structural model: protocol client vs.
  workflow orchestration, the two issuance modes (ACME / SPIFFE), and how
  responsibilities map onto `agent/`, `acme/`, and related modules.
- **`renewal_lifecycle.sysml`** — the ACME renewal workflow as a state
  machine, transcribed from the `add_edge`/`add_conditional_edges` calls in
  `agent/graph.py:build_graph`.
- **`revocation_lifecycle.sysml`** — the ACME revocation workflow as a state
  machine, transcribed from `agent/revocation_graph.py:build_revocation_graph`.
  A separate compiled graph from renewal, best-effort per domain (no abort
  path) rather than a run-level abort.
- **`requirements.sysml`** — requirements traced one-to-one to the code that
  satisfies each of them, sourced from `concept_store/concepts.json` and the
  modules themselves.

Use the `sysml-mcp` tools (`preview`/`visualize`, `getSymbols`, `validate`,
etc.) to explore or render these models rather than reading the raw SysML by
eye for anything beyond a quick check.
