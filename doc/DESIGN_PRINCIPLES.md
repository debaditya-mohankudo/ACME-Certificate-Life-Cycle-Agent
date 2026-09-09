# Design Principles

This is the architectural constitution for the ACME Certificate Lifecycle Agent.
Each principle is a deliberate trade-off, documented with rationale and a link to the full analysis.

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- Protocol pattern rationale: [DESIGN_PROTOCOL_PATTERN.md](DESIGN_PROTOCOL_PATTERN.md)
- RFC compliance mapping: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)

## Retrieval keywords

`design principles`, `invariants`, `determinism`, `agent state`, `stateless client`, `nonce lifecycle`, `no concurrency`, `llm boundaries`, `retry isolation`, `atomic writes`, `security auditability`, `graph topology`
[negative keywords / not-this-doc]
async, concurrency, parallel, checkpoint, nonce, stateful, CI, MCP, revoke, HTTP-01, DNS-01, EAB, configuration, storage, atomic, filesystem, docker, container, test, coverage, audit, performance, optimization, operator

---

## 0. RFC Compliance and Security Auditability Are the Highest Priority

This is the overriding principle. All other principles exist to serve it.

**RFC compliance is non-negotiable.** Every ACME operation must conform to the relevant RFC sections — RFC 8555 (ACME protocol, including §7.3.4 for EAB), RFC 7638 (JWK thumbprint), and RFC 5280 (revocation reason codes). Deviations from the protocol are defects, not trade-offs. Where the RFC permits optionality, this project chooses the safer interpretation. Any change that introduces a protocol deviation — even a minor one — must be treated as a breaking change and requires explicit justification.

**Security auditability is a first-class design constraint.** The system must be auditable by a third party without requiring deep familiarity with the codebase. This means:

- All network calls are named graph nodes — no hidden side effects
- All state is explicit in `AgentState` — no hidden mutable state in clients or helpers
- The account private key never appears in any log, trace, checkpoint, or serialized state
- All file writes are atomic — no partial state is ever observable
- All LLM outputs are validated before any protocol action is taken
- Retry and backoff logic is isolated and bounded — no unbounded retries

**Operational priority order:**

1. RFC protocol correctness
2. Security (key isolation, atomic writes, no hidden state)
3. Auditability (every action traceable through the graph)
4. Determinism (reproducible behaviour given the same inputs)
5. Reliability (bounded retries, safe checkpoint/resume)
6. Throughput (last — never worth compromising the above)

A change that improves performance at the cost of any item above it in this list is wrong by definition.

→ Full RFC mapping: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)

---

## 1. Stateless ACME Client — All State in LangGraph

The `AcmeClient` holds no mutable state. Every value the client needs — the current nonce, the account URL, the order URL — lives in `AgentState` and is passed in explicitly.

**Why:** A stateless client is trivially testable, reproducible, and safe to recreate across nodes or machines. Hiding nonce in a client instance breaks checkpoint/restore and makes parallelization unsafe. The small cost of passing one extra argument is worth the gains in debuggability.

**Nonce ownership:** `AgentState.current_nonce` is the single source of truth for nonces between graph node boundaries. The `AcmeClient` must never store a nonce as instance state (`self.*`). Method-local nonce handling is acceptable and in two cases RFC-required:
- `_post_signed` consumes a fresh nonce from a `badNonce` error response within the same call (RFC 8555 § 6.5)
- `get_authorization` / `get_order` fetch a one-shot nonce for a single POST-as-GET poll iteration

Instance-level nonce caching across calls is never acceptable, regardless of perceived performance benefit.

**`resp.ok` (200–399) in `_post_signed`:** `resp.ok` technically accepts 3xx codes, but this is not a defect in practice: `requests.Session.post()` does not follow redirects by default (unlike GET/HEAD), so any 3xx returned by an ACME server arrives as a raw response. Subsequent `resp.json()` calls in every caller would then raise immediately, making the failure loud rather than silent. RFC 8555 also forbids 3xx responses on POST endpoints. No change warranted.

→ Full analysis: [DESIGN_STATEFUL_CLIENT_ANALYSIS.md](DESIGN_STATEFUL_CLIENT_ANALYSIS.md)

---

## 2. Sequential Domain Processing — Parallelism is an Explicit Non-Goal

Domains are renewed one at a time through the LangGraph state machine. Concurrent domain processing is not supported.

**Why:** ACME nonces are single-use per connection. Parallel domains sharing a nonce would violate RFC 8555 § 6.5 and cause `badNonce` rejections. The sequential design keeps nonce flow simple and correct. If parallelism is ever needed, the migration path is per-domain nonce queues — not a stateful client.

→ Full analysis: [DESIGN_NONCE_MANAGEMENT_STRATEGY.md](DESIGN_NONCE_MANAGEMENT_STRATEGY.md)

---

## 3. LLM Advisory, Never Authoritative

The LLM (planner node) produces a renewal priority plan. Its output is always passed through a deterministic validation layer before any action is taken.

**Why:** LLMs can hallucinate domains not under management, drop domains silently, or return unparseable output. The validation layer strips hallucinated domains, recovers missing ones, and falls back to "renew everything" on JSON parse failure. The LLM's job is classification and observability — not access control over which domains get renewed.

→ Full analysis: [DESIGN_RENEWAL_PLANNER_LLM_RATIONALE.md](DESIGN_RENEWAL_PLANNER_LLM_RATIONALE.md)

---

## 4. Every Node is Idempotent

The graph is safe to resume or re-run at any node boundary. A crash at any point — before, during, or after any node — converges to correct state after resume or re-run.

**Why:** LangGraph checkpoints after each node. ACME operations (account creation, finalization, certificate download) are replay-safe by protocol design. Atomic writes ensure no corrupt intermediate state is ever visible on disk. Together these make the system robust for unattended, long-running ops.

→ Full analysis: [DESIGN_STATEFUL_CLIENT_ANALYSIS.md — Idempotency Philosophy](DESIGN_STATEFUL_CLIENT_ANALYSIS.md#idempotency-philosophy)

→ Related node execution model: [DESIGN_PROTOCOL_PATTERN.md](DESIGN_PROTOCOL_PATTERN.md)

---

## 5. Retry Logic Isolated from Business Logic

The `error_handler` node decides *whether* to retry and *when* (sets `retry_not_before` timestamp). The `retry_scheduler` node *waits* for that time. No business logic node sleeps or loops.

**Why:** Mixing backoff sleep into ACME nodes makes them untestable without real time delays, unobservable in LangGraph traces, and impossible to interrupt cleanly. Separation means each node is a pure function of state, and the scheduler can be swapped for an async version without touching protocol code.

→ Full analysis: [DESIGN_BACKOFF_INTEGRATION_ANALYSIS.md](DESIGN_BACKOFF_INTEGRATION_ANALYSIS.md)

---

## 6. Atomic Writes for All Cert Artifacts

Every PEM file write (cert, key, chain, metadata) uses the pattern: write to temp file → fsync → `os.replace()`.

**Why:** A crash during a plain `write_text()` call leaves a truncated, corrupt file in place. The old file is gone. The atomic rename means a crash at any point leaves either the old file intact or the new file complete — never a partial state visible to readers.

→ Full analysis: [CERTIFICATE_STORAGE.md — Atomic Writes](CERTIFICATE_STORAGE.md#atomic-writes-for-data-safety)

---

## 7. Account Key Never in State

The ACME account private key is loaded from disk at the node that needs it and never stored in `AgentState`.

**Why:** LangGraph state can be persisted to LangSmith traces, database checkpoints, and log output. A private key in state would leak into all of these surfaces. The key lives at `ACCOUNT_KEY_PATH`, is read at the `acme_account_setup` node, used in-memory, and discarded. No risk of accidental exposure.

→ See: [CLAUDE.md — State & Security](../CLAUDE.md)

---

## 8. Determinism Over Throughput

When there is a choice between processing domains concurrently (faster) and processing them sequentially (simpler, correct), this system chooses sequential.

**Why:** Cert renewal is a low-frequency, high-reliability operation — typically once per domain per 60–90 days. Throughput is not the constraint. Correctness and operational predictability are. A single cert renewed successfully in 5 minutes is better than three renewals attempted in parallel with a 20% chance of nonce collisions.

**Determinism is load-bearing, not a preference.** Nonce sequencing (RFC 8555 § 6.5), LangGraph checkpoint reproducibility, and LLM output validation all depend on a deterministic execution order. Treating sequentiality as optional — even for a subset of domains — unravels multiple invariants simultaneously. This is why Hard Invariant 4 in CLAUDE.md (no concurrent ACME operations) admits no exceptions.

---

## 9. Configuration over Code for Provider Differences

All CA-specific behavior (directory URL, EAB requirement, key format) is isolated in the `AcmeClient` class hierarchy. All LLM-provider-specific behavior is isolated in `llm/factory.py`. Node code never branches on provider identity.

**Why:** Provider-specific branches in business logic make nodes harder to test in isolation, create hidden dependencies, and cause subtle bugs when a new provider is added. The factory pattern means adding a new CA or LLM provider requires changing exactly two files (`acme/client.py`, `llm/factory.py`) and zero node files.

→ See: [acme/client.py](../acme/client.py), [llm/factory.py](../llm/factory.py)

---

## 10. All Network Effects Explicitly Routed

Every node that makes a network call is a named node in the LangGraph graph. No network calls are buried in utility functions called silently from within a node.

**Why:** Named nodes appear in LangSmith traces, checkpoint history, and interrupt/resume boundaries. A network call hidden in a helper function is invisible to the graph — it can't be interrupted, observed, or retried independently. The graph topology *is* the program's visible behavior.

→ See: [HOW_IT_WORKS.md](HOW_IT_WORKS.md), [agent/graph.py](../agent/graph.py)

---

## 12. CA Detection is Advisory and Gated on `CA_PROVIDER=custom`

The `certificate_scanner` node optionally detects which CA issued an existing certificate by inspecting the X.509 issuer O field and AIA OCSP URL (`acme/ca_detection.py`). This detection is **advisory only** — it never alters configuration or changes renewal behaviour.

**Gating rule:** Detection runs only when `CA_PROVIDER=custom`. For all named providers (`letsencrypt`, `letsencrypt_staging`, `digicert`, `zerossl`, `sectigo`), the configured `CA_PROVIDER` is the ground truth and detection is skipped entirely — `detected_ca_provider` is left as `None`.

**Why:** When an operator selects a named CA provider, they have explicitly declared their intent. Silently overriding or second-guessing that with cert inspection would be surprising and could produce misleading warnings (e.g. on the very first renewal where the existing cert was issued by a different CA on purpose). For `custom` CAs, where the ACME directory URL is operator-supplied and no named CA is selected, detection provides a useful advisory warning if the cert was previously issued by a known CA.

**Mismatch warning:** When `CA_PROVIDER=custom` and the detected CA differs from `"custom"`, a `WARNING` is logged advising the operator to update `CA_PROVIDER`. Let's Encrypt production and staging are treated as equivalent (both report `"letsencrypt"` in the issuer O field). No action is taken — the configured CA always governs renewal.

→ See: [acme/ca_detection.py](../acme/ca_detection.py), [agent/nodes/scanner.py](../agent/nodes/scanner.py)

---

## 13. Node Architecture — Callable Classes with Minimal Structural Contract

All LangGraph nodes are implemented as callable classes conforming to the `NodeCallable` Protocol. No inheritance hierarchy or adapter layer is required.

**Pattern:**
```python
class SomeNode:
    """Node description."""
    
    def __call__(self, state: AgentState) -> dict:
        """LangGraph entry point."""
        return self.run(state)
    
    def run(self, state: AgentState) -> dict:
        """Business logic."""
        # ... implementation
        return {"key": value}
```

**Graph registration:**
```python
builder.add_node("node_name", SomeNode())
```

**Why callable classes over abstract base classes:**

1. **Minimal contract** — Only `__call__(state) -> dict` is required. No properties, no abstract methods, no hooks to implement.

2. **Structural typing** — The `NodeCallable` Protocol uses structural subtyping (duck typing with type safety). Any class with the right signature is automatically compatible. No explicit inheritance needed.

3. **No adapter layer** — Previous designs required `FunctionNodeAdapter` to wrap functions. Direct callable registration eliminates this indirection.

4. **Pythonic** — Follows Python's "consenting adults" philosophy. Classes that look like callables are callables.

5. **Testable** — Mock by patching class constructors: `patch("agent.graph.SomeNode", MagicMock(...))`. Clear, explicit, no hidden state.

**Why keep function wrappers:**

Original node functions remain as thin wrappers calling class instances:
```python
def some_function_node(state: AgentState) -> dict:
    return SomeNode().run(state)
```

This preserves backward compatibility for imports and documentation references with negligible overhead.

**Why no `name` property:**

LangGraph requires names at registration time: `add_node("name", callable)`. The node instance doesn't need to know its own name, eliminating synchronization between class-level names and graph-level names.

**Constraints:**

- Node classes must remain stateless (no mutable instance attributes shared between invocations)
- All state flows through `AgentState` parameter
- Network calls must be explicit (no hidden side effects in helpers)
- Return value must be a dict suitable for LangGraph's state merging

**Testing:**

- `tests/test_node_base.py` validates the `NodeCallable` Protocol contract
- `tests/test_node_parity.py` validates function wrapper → class delegation
- Checkpoint tests mock callable classes by patching constructors

→ See: [doc/DESIGN_PROTOCOL_PATTERN.md](DESIGN_PROTOCOL_PATTERN.md), [agent/nodes/base.py](../agent/nodes/base.py), [tests/test_node_base.py](../tests/test_node_base.py), [tests/test_node_parity.py](../tests/test_node_parity.py)

---

## 11. Revocation as a Separate Subgraph

Certificate revocation uses a dedicated LangGraph state machine (`agent/revocation_graph.py`) rather than being integrated into the renewal graph. The revocation subgraph is simpler: account setup → loop through domains → revoke each → reporter.

**Why:** Revocation has different semantics from renewal. It loops at domain granularity (no retry handler), produces no new certificates, and is typically triggered on-demand rather than scheduled. A separate graph keeps the renewal graph focused and makes revocation behavior explicit.

**No retry logic:** Revocation failures (404 Not Found, 403 Unauthorized) are logged and the loop continues (best-effort). Unlike renewal, which retries transient errors, revocation failures typically indicate protocol or policy violations that retrying won't fix.

→ See: [agent/revocation_graph.py](../agent/revocation_graph.py), [agent/nodes/revoker.py](../agent/nodes/revoker.py), [main.py](../main.py) (`run_revocation()`)

---

## Quick Reference

| Principle | Short Form | Key File |
|-----------|-----------|----------|
| **RFC compliance + security auditability** | **Overrides everything else** | `doc/RFC_COMPLIANCE.md` |
| Stateless client | `AcmeClient` is a function, not an object | `acme/client.py` |
| Sequential domains | One domain at a time | `agent/nodes/router.py` |
| LLM advisory only | Validate every LLM output | `agent/nodes/planner.py` |
| Idempotent nodes | Safe to resume at any boundary | `agent/graph.py` |
| Isolated retry logic | error_handler → retry_scheduler | `agent/nodes/retry_scheduler.py` |
| Atomic writes | temp + fsync + rename | `storage/atomic.py` |
| Key off state | Account key on disk only | `agent/nodes/account.py` |
| Sequential > parallel | Correctness first | `DESIGN_NONCE_MANAGEMENT_STRATEGY.md` |
| Factory pattern | No provider branches in nodes | `llm/factory.py` |
| Network calls named | All side effects in graph | `agent/graph.py` |
| CA detection gated | Advisory only; skipped for named providers | `acme/ca_detection.py` |
| Node architecture | Callable classes with Protocol | `agent/nodes/base.py` |

---

## Metadata

- **Owner**: Architecture team
- **Status**: active (constitutional layer — no breaking changes without explicit justification)
- **Last reviewed**: 2026-02-27
- **Next review due**: 2026-05-27 (quarterly)
