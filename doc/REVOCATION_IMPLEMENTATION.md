# Certificate Revocation Implementation

## See also

- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- RFC compliance: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)
- System flow: [HOW_IT_WORKS.md](HOW_IT_WORKS.md)

**Date:** February 2026
**Status:** ✅ Complete — 101 unit tests passing, zero regressions

---

## Overview

This document describes the certificate revocation feature added to the ACME Certificate Lifecycle Agent. Revocation uses a **separate, dedicated StateGraph** (`agent/revocation_graph.py`) to handle ACME RFC 8555 § 7.6 revocation requests (`POST /revokeCert`).

The feature provides:
- On-demand certificate revocation via CLI (`--revoke-cert`)
- RFC 5280 revocation reason codes (unspecified, keyCompromise, superseded, cessationOfOperation)
- Best-effort domain looping (failures logged, loop continues), with bounded
  retry for transient failures on the current domain before it's logged
  as failed
- LLM-generated summary reports
- Full checkpoint/resume support

---

## CLI Usage

### Basic Revocation

```bash
python main.py --revoke-cert example.com
python main.py --revoke-cert example.com api.example.com shop.example.com
```

### With Reason Code

```bash
# Unspecified (default)
python main.py --revoke-cert example.com

# Key compromise
python main.py --revoke-cert example.com --reason 1

# Superseded
python main.py --revoke-cert example.com --reason 4

# Cessation of operation
python main.py --revoke-cert example.com --reason 5
```

### With Checkpointing

```bash
python main.py --revoke-cert example.com api.example.com --checkpoint
```

---

## Architecture

### Revocation Graph Topology

```
START
  │
  ▼
[revocation_account_setup]
  │  Register/retrieve ACME account (same as renewal)
  │
  ▼
[pick_next_revocation_domain] ◄──────────────┐
  │  Pop domain from revocation_targets      │
  │  Reset per-domain retry_count            │
  │                                          │
  ▼                                          │
[cert_revoker] ◄────────────────┐            │
  │  POST /revokeCert for current domain     │
  │  (reads cert.pem from disk; fails        │
  │   gracefully if not found)               │
  │  Classifies AcmeError: transient (retry) │
  │  vs. policy/protocol (fatal)             │
  │                                          │
  ▼                                │         │
[revocation_loop_router]           │         │
  ├── retry ──► [retry_scheduler] ─┘         │
  ├── next_domain ────────────────────────────┘
  └── all_done ──► [revocation_reporter]
                         │
                        END
```

Retry is bounded per domain (`max_retries`, default `config.MAX_RETRIES`,
same knob the renewal graph uses) and only fires for errors classified as
transient — rate limiting, server-side 5xx, connection failures (see
`agent/nodes/revoker.py`). Exhausting the budget, or hitting a
policy/protocol error (unauthorized, alreadyRevoked, malformed, missing
local cert file), falls back to the original best-effort behavior: log to
`failed_revocations` and continue to the next domain.

### Key Differences from Renewal Graph

| Aspect | Renewal | Revocation |
|--------|---------|-----------|
| Error handling | Retry with backoff (all non-fatal errors) | Retry with backoff (transient errors only), then log and continue |
| Trigger | Scheduled daily | On-demand via CLI |
| Scope | All managed domains | User-specified list |
| LLM role | Planner + Reporter | Reporter only |
| State fields | renewal_* | revocation_* |
| Network calls | 8+ per domain | 2 per domain (account + revoke) |

---

## Implementation Details

### New State Fields (AgentState)

```python
revocation_targets: List[str]            # domains queued for revocation
current_revocation_domain: Optional[str] # domain being revoked right now
revocation_reason: int                   # RFC 5280: 0,1,4,5
revoked_domains: List[str]               # successfully revoked
failed_revocations: List[str]            # domains that failed revocation
```

### New Nodes

#### `cert_revoker()` — agent/nodes/revoker.py

Revokes a certificate via ACME POST /revokeCert.

**Inputs:**
- `current_revocation_domain` — domain to revoke
- `cert_store_path` — where to read cert.pem from
- `account_key_path` — account private key on disk
- `acme_account_url` — account URL from setup
- `current_nonce` — ACME nonce (fetched fresh if None)
- `revocation_reason` — RFC 5280 reason code

**Outputs:**
- Success: `revoked_domains += [domain]`, `current_nonce = new_nonce`
- Missing cert: `failed_revocations += [domain]`, error logged
- ACME error: `failed_revocations += [domain]`, error logged, nonce updated

**Key behavior:**
- Loads account key from disk (never returns it in state)
- Reads certificate PEM from `CERT_STORE_PATH/<domain>/cert.pem`
- Handles missing files gracefully (logs, no exception)
- Catches `AcmeError` and continues looping

#### `pick_next_revocation_domain()` — agent/nodes/revocation_router.py

Pops the next domain from `revocation_targets` and sets `current_revocation_domain`.

Also clears `current_nonce` so `cert_revoker` fetches a fresh one (RFC 8555 § 6.5).

#### `revocation_loop_router()` — agent/nodes/revocation_router.py

Routing function: returns `"next_domain"` if targets remain, else `"all_done"`.

#### `revocation_reporter()` — agent/nodes/reporter.py

LLM node that generates a human-readable revocation summary.

**Inputs:**
- `revoked_domains` — list of successfully revoked
- `failed_revocations` — list of failures
- `revocation_reason` — reason code for context
- `error_log` — list of error messages

**Output:**
- LLM-generated 2–4 sentence summary (or fallback if LLM fails)
- Printed to stdout with banner

### New Graph

#### `build_revocation_graph()` — agent/revocation_graph.py

Builds and compiles the revocation StateGraph.

```python
def build_revocation_graph(use_checkpointing: bool = False):
    """Build and compile the revocation StateGraph."""
    # Returns CompiledGraph ready to invoke()
```

#### `revocation_initial_state()` — agent/revocation_graph.py

Initializes `AgentState` for a revocation run.

```python
def revocation_initial_state(
    domains: list[str],
    reason: int,
    cert_store_path: str = "./certs",
    account_key_path: str = "./account.key",
) -> dict:
    """Build initial state with revocation_targets, reason, paths."""
```

### CLI Integration

**`main.py` changes:**

```python
def run_revocation(
    domains: list[str],
    reason: int = 0,
    use_checkpoint: bool = False,
) -> dict:
    """Execute a certificate revocation run and return final state."""
    # Validates reason in {0,1,4,5}
    # Warns on unmanaged domains
    # Invokes revocation graph
```

**Argument parser updates:**

```python
parser.add_argument(
    "--revoke-cert",
    nargs="+",
    metavar="DOMAIN",
    help="Revoke certificates for one or more domains",
)
parser.add_argument(
    "--reason",
    type=int,
    default=0,
    metavar="CODE",
    help="RFC 5280 revocation reason code (default: 0=unspecified; also: 1=keyCompromise, 4=superseded, 5=cessationOfOperation)",
)
```

---

## Design Decisions

### 1. Separate Graph, Not Integration

**Decision:** Create a dedicated `agent/revocation_graph.py` instead of adding revocation to the renewal graph.

**Rationale:**
- Revocation and renewal have fundamentally different semantics
- No dedicated `error_handler` node needed — `cert_revoker` classifies
  transient-vs-fatal itself and reuses the generic `retry_scheduler` node
  (see decision 2)
- Separate trigger model (on-demand vs. scheduled)
- Cleaner architectural separation, easier to reason about
- Graph topology remains explicit and visible

### 2. Bounded Retry for Transient Failures, Best-Effort for the Rest

**Decision:** `cert_revoker` retries a domain, with the same bounded
exponential backoff as the renewal graph, only when the ACME error is
classified as transient (rate limiting, server-side 5xx, connection
failures). All other failures — including exhausting the per-domain retry
budget — are logged to `failed_revocations`; the loop continues to the next
domain rather than aborting the run.

**Rationale (revised — the original no-retry-at-all design underestimated
this):**
- ACME revocation failures like "unauthorized" (403) or a missing local
  cert file are policy/protocol rejections — retrying cannot fix them, so
  they stay fatal, unretried
- But other revocation failures ARE transient (a CA's `/revokeCert`
  endpoint timing out, hitting a rate limit, a momentary 5xx) — treating
  those identically to a policy rejection meant a single network blip could
  leave a certificate revoked from nothing, with no automatic follow-up.
  This matters more for revocation than renewal: renewal gets a "next
  scheduled run" safety net for free; a failed on-demand revocation only
  gets retried if a human notices and reruns the CLI — the worst case for
  the most urgent reason code (`keyCompromise`)
- Exhausting the retry budget still falls back to best-effort log-and-continue
  rather than a new abort-the-whole-run path, so this preserves
  `CLAUDE.md`'s "fail toward doing nothing" property rather than trading it
  for a whole-run abort revocation never had before
- Users can still manually rerun the CLI for any domain that ends up in
  `failed_revocations` after retries are exhausted

### 3. Account Key Never in State

**Decision:** `cert_revoker` loads the account key from disk; never returns it in state.

**Rationale:**
- Prevents accidental leakage into LangSmith traces
- Matches renewal graph pattern (see `agent/nodes/account.py`)
- Simplifies state serialization

### 4. Nonce Management

**Decision:** `revocation_loop_router` clears `current_nonce` between domains.

**Rationale:**
- RFC 8555 § 6.5: each request consumes exactly one nonce
- Fresh nonce fetch ensures correctness across domain boundaries
- Matches renewal graph pattern (see `agent/nodes/router.py`)

### 5. Graceful Missing Certificates

**Decision:** If cert file not found, log failure and continue.

**Rationale:**
- Domain may have been removed or cert expired and not renewed
- Continuing lets other domains succeed
- Clear error message in error_log for operator visibility

### 6. LLM Advisory, Not Control

**Decision:** Revocation reason code comes from CLI, not LLM.

**Rationale:**
- Reason code is operational policy, not advisory
- User controls which domains and why (via CLI flags)
- LLM only generates observability (summary report)

---

## Tests

### Unit Tests (15 tests in `tests/test_revocation.py`)

All pass without Pebble ACME server:

| Test | Purpose |
|------|---------|
| `test_pick_next_revocation_domain_*` | Domain popping and list management |
| `test_revocation_loop_router_*` | Routing logic (next_domain vs. all_done) |
| `test_cert_revoker_success` | Successful revocation |
| `test_cert_revoker_missing_cert` | Graceful handling of missing cert file |
| `test_cert_revoker_acme_error` | ACME error handling |
| `test_revocation_reporter_*` | LLM summary generation + LLM failure fallback |
| `test_revocation_graph_topology` | Graph compiles without error |
| `test_revocation_graph_single_domain_flow` | End-to-end single domain |
| `test_revocation_graph_multi_domain_flow` | End-to-end multi-domain |
| `test_revocation_graph_partial_failure` | Loop continues on failure |

### Integration Tests (3 tests in `tests/test_revocation_pebble.py`)

Require `docker compose -f docker-compose.pebble.yml up -d`:

| Test | Purpose |
|------|---------|
| `test_revocation_graph_basic_against_pebble` | Real ACME revocation |
| `test_revocation_reason_codes_against_pebble` | RFC 5280 reason codes |
| `test_revocation_nonexistent_cert_against_pebble` | Graceful missing cert |

### Test Results

```
✅ 101 unit tests passing (91 original + 15 new)
✅ 3 Pebble integration tests ready (skipped when Pebble not running)
✅ Zero regressions — all existing tests still pass
✅ ~20s test runtime (unit only)
```

---

## Documentation Updates

- **`CLAUDE.md`**
  - Added `--revoke-cert` to command examples
  - Updated project structure listing

- **`doc/DESIGN_PRINCIPLES.md`**
  - Added Principle 11: "Revocation as a Separate Subgraph"
  - Explains design rationale and no-retry philosophy

- **`doc/ACME_AGENT_PLAN.md`**
  - Added § 3.4: Revocation Subgraph Topology diagram
  - Documented key differences from renewal

- **`doc/USAGE.md`**
  - Added "Revoke certificates" section with examples
  - RFC 5280 reason code table
  - Explanation of graph flow

---

## Invariant Compliance

All CLAUDE.md hard invariants are satisfied:

| Invariant | Satisfied | How |
|-----------|-----------|-----|
| One POST → one nonce | ✅ | `revocation_loop_router` clears nonce; `cert_revoker` fetches fresh |
| Account key never in state | ✅ | Loaded from disk by `cert_revoker`, never returned |
| LLM output validated | ✅ | `revocation_reporter` receives safe, controlled inputs |
| No concurrent ACME ops | ✅ | Sequential domain loop, one at a time |
| Retry logic isolated | ✅ | Bounded retry for transient errors only, reusing the generic `retry_scheduler` node; policy/protocol failures stay best-effort |
| Certificate writes atomic | ✅ | N/A (revocation doesn't write certs) |
| Graph topology changes → update docs | ✅ | Updated DESIGN_PRINCIPLES.md § 11 |
| Every network call = named node | ✅ | `revocation_account_setup` + `cert_revoker` |
| ACME client stateless | ✅ | All state passed in via AgentState |
| Planner never introduces domains | ✅ | No planner in revocation graph |

---

## Future Enhancements

Possible future work (not implemented):

- Batch revocation API (RFC 8555 extension)
- Revocation cancellation/undo (not defined by RFC 8555)
- Rate limiting on revocation requests
- Bulk revocation from a file
- Integration with certificate monitoring dashboards
- Audit trail per revocation

---

## Related Files

- [`agent/revocation_graph.py`](../agent/revocation_graph.py) — Graph builder
- [`agent/nodes/revoker.py`](../agent/nodes/revoker.py) — Revocation node
- [`agent/nodes/revocation_router.py`](../agent/nodes/revocation_router.py) — Routing nodes
- [`agent/nodes/reporter.py`](../agent/nodes/reporter.py) — `revocation_reporter()` function
- [`main.py`](../main.py) — `run_revocation()` CLI entry
- [`tests/test_revocation.py`](../tests/test_revocation.py) — Unit tests
- [`tests/test_revocation_pebble.py`](../tests/test_revocation_pebble.py) — Integration tests
