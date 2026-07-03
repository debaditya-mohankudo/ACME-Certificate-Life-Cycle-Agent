# Documentation Wiki Home

This page is the canonical entry point for project documentation. It is organized by intent so contributors can find one source of truth and avoid duplicate writeups.

---

## Agent Routing (Copilot / Claude)

Use this table when answering user questions with minimal hops.

> **Claude Code**: A compact version of this routing table is embedded in [`CLAUDE.md § Request Routing`](../CLAUDE.md#-request-routing-this-page). This page is the authoritative source; CLAUDE.md references it.

| User intent | Open first | Then open | Canonical answer source |
|---|---|---|---|
| "How does the protocol/graph work?" | [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md) | [HOW_IT_WORKS.md](HOW_IT_WORKS.md) | [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md), [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md) |
| "How do I run/configure this?" | [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md) | [SETUP.md](SETUP.md), [USAGE.md](USAGE.md) | [CONFIGURATION.md](CONFIGURATION.md) |
| "Is this secure/tested/observable?" | [WIKI_SECURITY_QUALITY.md](WIKI_SECURITY_QUALITY.md) | [SECURITY.md](SECURITY.md), [CI_TEST_COVERAGE.md](CI_TEST_COVERAGE.md) | [SECURITY.md](SECURITY.md) |
| "How does MCP mode work?" | [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md) | [MCP_SERVER.md](MCP_SERVER.md), [MCP_IMPLEMENTATION_DETAILS.md](MCP_IMPLEMENTATION_DETAILS.md) | [MCP_SERVER.md](MCP_SERVER.md) |
| "What Python patterns are used?" | [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md) | [PYTHONIC_IDIOMS.md](PYTHONIC_IDIOMS.md) | [PYTHONIC_IDIOMS.md](PYTHONIC_IDIOMS.md) |
| "How do I extend this for SPIFFE/SPIRE?" | [DESIGN_SPIFFE_SVID_EXTENSION.md](DESIGN_SPIFFE_SVID_EXTENSION.md) | [SPIRE_TESTING_SERVER.md](SPIRE_TESTING_SERVER.md) | [DESIGN_SPIFFE_SVID_EXTENSION.md](DESIGN_SPIFFE_SVID_EXTENSION.md) |

---

## Canonical Sources (Single Source of Truth)

- Runtime/config values: [CONFIGURATION.md](CONFIGURATION.md)
- Graph behavior and invariants: [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md)
- RFC mapping and scope boundaries: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)
- Operator execution flow: [HOW_IT_WORKS.md](HOW_IT_WORKS.md)
- Security controls and policy: [SECURITY.md](SECURITY.md)
- Test policy and CI status model: [CI_TEST_COVERAGE.md](CI_TEST_COVERAGE.md)
- Code patterns and idioms: [PYTHONIC_IDIOMS.md](PYTHONIC_IDIOMS.md)

---

## Start Here

- New contributor setup: [SETUP.md](SETUP.md) → [USAGE.md](USAGE.md)
- System overview: [HOW_IT_WORKS.md](HOW_IT_WORKS.md)
- Architecture constitution: [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md)
- Security baseline: [SECURITY.md](SECURITY.md)

---

## Wiki Hubs

- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- Security & quality hub: [WIKI_SECURITY_QUALITY.md](WIKI_SECURITY_QUALITY.md)

---

## Authoring Rules (Wiki Style)

- Prefer linking over duplicating content.
- Keep one page as source-of-truth per topic.
- Add a **See also** section to every new doc.
- If replacing content, leave a short pointer in the old location.
- Use the standard page template: [WIKI_TEMPLATE.md](WIKI_TEMPLATE.md)

---

## Fast Paths


[negative keywords / not-this-doc]
backoff, retry, exponential, scheduler, error handler, integration, protocol, bounded, cap, MAX_RETRIES, deterministic, safety, graph, node, pebble, langgraph, acme, workflow, async, concurrency, parallel, checkpoint, nonce, stateful, planner, LLM, CI, MCP, revoke, HTTP-01, DNS-01, EAB, CA, configuration, storage, atomic, filesystem, certificate, account, key, private, TLS, docker, container, test, coverage, audit, compliance, RFC, design principles, scaling, throughput, performance, optimization, operator
- Docker and runtime: [DOCKER.md](DOCKER.md), [DOCKER_NONROOT.md](DOCKER_NONROOT.md), [DOCKER_TEST_FLOW.md](DOCKER_TEST_FLOW.md)
