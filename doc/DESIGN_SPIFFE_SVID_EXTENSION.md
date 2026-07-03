# Extending This Agent for SPIFFE SVID Issuance

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- Configuration reference: [CONFIGURATION.md](CONFIGURATION.md)
- SPIRE test harness: [SPIRE_TESTING_SERVER.md](SPIRE_TESTING_SERVER.md)
- Pebble test harness (the ACME equivalent): [PEBBLE_TESTING_SERVER.md](PEBBLE_TESTING_SERVER.md)

**Date:** 2026-07-03
**Status:** Implemented (branch: `worktree-spiffe-svid-issuance`)
**Category:** Agent Design Pattern / Protocol Extension

---

## Overview

This agent's lifecycle logic — monitor → plan → issue → renew → revoke — is protocol-agnostic. The ACME RFC 8555 flow is one backend; this document explains how a second backend, **SPIFFE SVID issuance via SPIRE**, was added alongside it, and the design decisions that made the addition mostly *additive* rather than a rewrite.

This is not a hypothetical proposal — the extension described here is implemented, tested (586 unit tests + 3 SPIRE integration tests, validated live against a real SPIRE deployment), and lives in this worktree.

---

## The Core Insight: Same Lifecycle, Different Trust Model

ACME and SPIFFE solve the same underlying problem — "give this thing a short-lived, verifiable identity, and keep renewing it before it expires" — but they authenticate that identity in fundamentally different ways:

```
ACME (existing)
  Subject:      a domain name
  Auth:         HTTP-01 / DNS-01 challenge — prove you control the domain
  Trust root:   a public CA / the public WebPKI
  Issuance:     acme_account_setup → order_initializer → challenge_setup →
                challenge_verifier → csr_generator → order_finalizer →
                cert_downloader

SPIFFE (new)
  Subject:      a SPIFFE ID (workload identity, e.g. spiffe://example.org/workload/demo)
  Auth:         node + workload attestation — prove what/where the process is
  Trust root:   your own SPIRE server (never the public WebPKI)
  Issuance:     spiffe_attestor (a single node — attestation already
                happened before the Workload API hands back anything)
```

Because the *lifecycle* (scan → classify urgency → issue → store → report) is identical, and only the *issuance mechanics* differ, the extension is shaped as: **keep the shared spine, swap the issuance segment.**

---

## Design Decision 1: A Config Fork, Not a Rewrite

`config.py` gained one field:

```python
CERT_ISSUANCE_MODE: Literal["acme", "spiffe"] = "acme"
```

This is **strictly either/or per running instance** — a single agent process issues either ACME certs or SPIFFE SVIDs, never both. There is no dual-issuance mode, and none is planned: the two flows have incompatible subjects (domain vs. SPIFFE ID), incompatible auth models, and incompatible "what am I managing" identifiers (`MANAGED_DOMAINS` vs. `MANAGED_SPIFFE_IDS`). If an operator genuinely needs both, they run two separate instances with two separate configs.

### Why a flat class, not nested config objects

The textbook-SOLID answer here is composition — two independent nested config models (`AcmeConfig`, `SpiffeConfig`), each owning its own fields and validators, with `Settings` just holding whichever one applies. That was considered and explicitly rejected for one reason: **it isn't additive.** Every existing call site in this codebase does `settings.CA_PROVIDER`, `settings.MANAGED_DOMAINS`, etc. — flat attribute access. Migrating to `settings.acme.CA_PROVIDER` touches every one of those call sites for a change that has zero user-facing benefit for the ACME-only case.

Instead, `CERT_ISSUANCE_MODE` was added as a flat field, alongside new SPIFFE-only fields (`SPIRE_AGENT_SOCKET_PATH`, `SPIFFE_TRUST_DOMAIN`, `MANAGED_SPIFFE_IDS`), and the four existing ACME-only `model_validator`s (`validate_eab_credentials`, `validate_webroot`, `validate_dns_config`, `resolve_acme_directory`) each gained a one-line early-return guard:

```python
@model_validator(mode="after")
def resolve_acme_directory(self) -> "Settings":
    if self.CERT_ISSUANCE_MODE != "acme":
        return self
    ...  # unchanged
```

A new `validate_cert_issuance_mode_fields` validator rejects the wrong field group being set for the selected mode (e.g. `MANAGED_DOMAINS` set while `spiffe`), fail-fast at `Settings()` construction — the same contract the existing validators already guarantee (per the `settings-singleton-with-csv-fallback` concept in `concept_store/concepts.json`: "Settings() raises ValueError at construction time for any invalid combination, never silently degrades").

This is a real trade-off, not a free lunch: the flat class *is* a mild SRP violation (one class, two responsibilities, scattered guards). It's the one already established by this file's `DNS_PROVIDER` three-way fork (Cloudflare/Route53/Google fields all coexist flatly with guarded validators) — consistent with precedent, and additive was the harder constraint to satisfy here.

---

## Design Decision 2: A New Node, Not a New Client Module

The ACME issuance flow is already a **node-registry pattern**, not a monolithic client: `agent/nodes/account.py`, `order.py`, `challenge.py`, `csr.py`, `finalizer.py`, `storage.py` — each a small class deriving from `agent/nodes/base.py`'s `NodeCallable` protocol, registered in `agent/nodes/registry.py::NODE_REGISTRY`, wired into edges in `agent/graph.py::build_graph()`.

The SPIFFE flow follows this exact pattern: one new node, `agent/nodes/spiffe_attestor.py::SpiffeAttestorNode`, registered the same way. No bespoke client class, no parallel abstraction.

### Why one node instead of several

ACME's issuance segment is five nodes (`acme_account_setup` → `order_initializer` → `challenge_setup` → `challenge_verifier` → `csr_generator` → `order_finalizer` → `cert_downloader`) because ACME's protocol genuinely has that many distinct steps — an account, an order, a challenge round-trip, a CSR, a finalize-then-download split. SPIFFE's Workload API collapses all of that into a single RPC (`fetch_x509_svid()`): by the time that call is even reachable, node and workload attestation have already happened as a precondition of the socket handing back anything at all. There is no multi-step protocol to mirror — one node is the honest shape, not an artificially split one.

### Reusing `storage_manager` unchanged

`spiffe_attestor` writes `privkey.pem` itself (mirroring `csr_generator`'s role, since the SPIRE Agent hands back cert *and* key together — there's no separate CSR step to generate a key from) and populates `state["current_order"]["full_chain_pem"]` in exactly the shape `csr_generator`/`order_finalizer` already produce for ACME. The existing `storage_manager` node — which only reads `current_order.full_chain_pem` and an already-written `privkey.pem` — needed **zero changes** to work for both flows. This is the general pattern worth reusing: when adding a second backend to a shared pipeline, adapt the new node's output to match what a downstream shared node already expects, rather than writing a parallel version of that shared node.

`renewal_planner` (urgent/routine/skip classification), `error_handler`/`retry_scheduler` (ACME-only — see below), and `summary_reporter` were checked for ACME-specific assumptions and found generic enough to reuse as-is: `renewal_planner`'s hallucination-stripping validates against a generic string set (`managed_domains`), not domain-shaped strings specifically.

### Why no `error_handler`/`retry_scheduler` in the SPIFFE graph

`spiffe_attestor`'s failures (unregistered workload → `PermissionDenied`, misconfigured socket path → `ArgumentError`, transport failure → `FetchX509SvidError`) are all treated as **terminal per-domain failures** — caught inside the node itself, surfaced directly via `failed_renewals`/`error_log`, same treatment `storage_manager` already gives its own failures (missing `full_chain_pem`, missing `privkey.pem`). There's no retry-with-backoff concept here the way there is for ACME's rate-limited, network-flaky challenge round-trip: a `PermissionDenied` from an unregistered workload won't resolve itself on retry, and a working Workload API call is a single fast local RPC, not a multi-step network protocol with transient failure modes worth backing off from.

---

## Design Decision 3: `graph.py` Branches, Doesn't Duplicate

`build_graph()` was refactored into `_build_acme_graph(builder)` / `_build_spiffe_graph(builder)`, selected by `settings.CERT_ISSUANCE_MODE`:

```
ACME:    START → certificate_scanner → renewal_planner →
         [acme_account_setup → pick_next_domain → order_initializer →
          challenge_setup → challenge_verifier → csr_generator →
          order_finalizer → cert_downloader → storage_manager] →
         domain_loop_router → summary_reporter → END

SPIFFE:  START → certificate_scanner → renewal_planner →
         [pick_next_domain → spiffe_attestor → storage_manager] →
         domain_loop_router → summary_reporter → END
```

The bracketed segment is the only part that changes; everything outside it — `certificate_scanner`, `renewal_planner`, `pick_next_domain`, `storage_manager`, `domain_loop_router`, `summary_reporter` — is registered and wired identically in both branches. Confirmed via test: the ACME node list/edge chain is byte-for-byte what it was before this change (all pre-existing tests pass unmodified), and a `spiffe`-mode graph correctly excludes every ACME-only node (`test_graph_cert_issuance_mode.py`).

---

## Design Decision 4: The `spiffe` Python Package Is Optional

Like the existing `llm-*`/`dns-*` extras, SPIFFE support is gated behind `uv sync --extra spiffe` (the `spiffe` PyPI package — HPE's reference `py-spiffe` client). If it's not installed, `spiffe_attestor` degrades to a clean per-domain failure with an actionable log message, not an `ImportError` crash — consistent with how `llm/factory.py::make_llm()` handles a missing langchain install.

---

## The Local Test Harness: A Different Shape Than Pebble, and Why

Pebble (the ACME test CA) is a single Docker service, brought up with one `docker compose up -d`, reachable over a published TCP port from host-run pytest. The SPIRE harness (`docker-compose.spire.yml`, `doc/SPIRE_TESTING_SERVER.md`) required real design work to get right, because SPIRE's trust model is fundamentally different, and several assumptions that hold for Pebble don't transfer:

- **Two-phase startup, not one.** The agent authenticates to the server via a join token, which the server must generate *before* the agent can start — there's no way around this bootstrap step (a lighter version of the same bootstrap any real SPIRE deployment needs, normally automated via cloud/k8s node attestation instead of a manual token).
- **Shared PID namespaces required.** SPIRE's `unix` WorkloadAttestor resolves a connecting process's identity via `/proc`, which fails across Docker's default per-container PID namespaces (`"could not resolve caller information"`) — fixed with `pid: "host"`, the Compose analogue of Kubernetes' `hostPID: true` requirement for the SPIRE Agent DaemonSet.
- **No host-bind-mount shortcut on macOS.** The natural design — bind-mount the Workload API socket to a host path, let pytest connect directly, mirroring Pebble's published-port pattern — silently fails on Docker Desktop for macOS (file exists, connection gets `ECONNREFUSED`; only `docker.sock` gets special-cased socket forwarding). The harness uses a named Docker volume instead, and integration tests run *inside* the `spire-test` container.
- **Join tokens are single-use.** Restarting the agent (even accidentally, via `docker compose run`'s dependency reconciliation) after it has already attested crashes it — documented explicitly, with `--no-deps` as the fix for test invocations.

None of this is a testing shortcut to later remove, unlike Pebble's `ACME_INSECURE` (which exists purely because Pebble's self-signed cert isn't in any trust store). It's the real SPIFFE trust model — attestation rooted in your own infrastructure, never a public CA — working exactly as designed, even in a local test harness.

---

## What's Reused vs. What's New

| Component | Reused unchanged | New |
|---|---|---|
| `certificate_scanner` | ✅ | |
| `renewal_planner` (urgent/routine/skip) | ✅ | |
| `pick_next_domain` | ✅ | |
| `storage_manager` | ✅ | |
| `domain_loop_router` | ✅ | |
| `summary_reporter` | ✅ | |
| `error_handler` / `retry_scheduler` | ACME-only, not used by SPIFFE | |
| Issuance mechanics | | `spiffe_attestor` (new node) |
| Config | | `CERT_ISSUANCE_MODE`, `SPIRE_AGENT_SOCKET_PATH`, `SPIFFE_TRUST_DOMAIN`, `MANAGED_SPIFFE_IDS` |
| Graph wiring | | `_build_acme_graph()` / `_build_spiffe_graph()` split |
| Test harness | | `docker-compose.spire.yml`, `spire/` configs, `register-workload.sh` |
| Dependency | | `spiffe` package (optional extra) |

---

## Known Limitations / Deferred Work

- **`main.py`'s CLI entry points still hardcode `settings.MANAGED_DOMAINS`** when calling `initial_state()`. Wiring `main.py` to use `settings.MANAGED_SPIFFE_IDS` in `spiffe` mode was out of scope for the node/graph task and is left for whoever picks up end-to-end CLI usage. The integration tests bypass this by calling `initial_state()` directly.
- **Rotation/renewal timing is not exercised against a forced expiry window.** The integration suite's rotation test is a proxy (confirms repeat fetches keep succeeding and returning valid material) rather than actually forcing SPIRE's short-lived SVID TTL to expire mid-test — reconfiguring the harness's `ca_ttl` or sleeping for a real expiry window were both judged not worth the added test runtime/flakiness for this pass.
- **`fs.sanitize_domain_for_path`'s path-sanitization strips `/` entirely** from a SPIFFE ID (`spiffe://example.org/workload/demo` → a directory name with all slashes removed), which could collide for two different SPIFFE IDs that only differ in path segments. Not hit in practice with a single test workload; worth a closer look if managing many SPIFFE IDs under the same trust domain with similar path structures.
- **Dual-issuance is explicitly out of scope**, not just undone — see Design Decision 1.

---

## Metadata

- **Owner**: Certificate Lifecycle / Identity team
- **Status**: Implemented — see epic `task:a73513cf` (implementation) and `task:544893ff` (this doc)
- **Last reviewed**: 2026-07-03
