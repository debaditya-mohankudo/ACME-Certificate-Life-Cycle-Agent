# Configuration Reference

All settings are read from environment variables or `.env`. Any variable can be overridden by setting it in the shell before running.

## When to use this page

- "What environment variables are available?"
- "How do I configure the CA provider?"
- "What are the default values?"
- "How do I set up LLM models?"

## Canonicality

- **Canonical for**: Configuration field reference, defaults, valid values, environment variables
- **Not canonical for**: Setup instructions (→ [SETUP.md](SETUP.md)), operational guidance (→ [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)), CA-specific setup (→ [CA_PROVIDERS.md](CA_PROVIDERS.md))

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- Usage guide: [USAGE.md](USAGE.md)
- Security constraints: [SECURITY.md](SECURITY.md)

## Retrieval keywords

`env`, `.env`, `CA_PROVIDER`, `ACME_DIRECTORY_URL`, `EAB`, `MANAGED_DOMAINS`, `RENEWAL_THRESHOLD_DAYS`, `HTTP_CHALLENGE_MODE`, `WEBROOT_PATH`, `LLM_PROVIDER`, `MAX_RETRIES`, `ACME_INSECURE`, `ACME_CA_BUNDLE`
[negative keywords / not-this-doc]
backoff, retry, exponential, scheduler, error handler, integration, protocol, bounded, cap, deterministic, safety, graph, node, pebble, langgraph, acme, workflow, async, concurrency, parallel, checkpoint, nonce, stateful, planner, CI, MCP, revoke, HTTP-01, DNS-01, EAB, CA, storage, atomic, certificate, account, key, private, TLS, docker, container, test, coverage, audit, RFC, design principles, scaling, throughput, performance, optimization, operator, wiki, hub, navigation, see also

| Variable | Default | Description |
|---|---|---|
| `CERT_ISSUANCE_MODE` | `acme` | `acme` or `spiffe` — strict either/or, picks which issuance flow runs. One running instance issues either ACME certs or SPIFFE SVIDs, never both; run two separate instances/configs if you need both. Setting fields from the wrong group (e.g. `MANAGED_DOMAINS` while `spiffe`) is rejected at config load. See [DESIGN_SPIFFE_SVID_EXTENSION.md](DESIGN_SPIFFE_SVID_EXTENSION.md) *(pending)*. |
| `CA_PROVIDER` | `digicert` | *(acme mode only)* CA to use: `digicert` · `letsencrypt` · `letsencrypt_staging` · `zerossl` · `sectigo` · `custom`. For named providers the config is authoritative and X.509 issuer detection is skipped. For `custom`, the scanner detects the issuing CA from existing certs and warns on mismatch (advisory only). |
| `ACME_EAB_KEY_ID` | — | EAB key identifier (DigiCert only) |
| `ACME_EAB_HMAC_KEY` | — | Base64url-encoded HMAC key (DigiCert only) |
| `ACME_DIRECTORY_URL` | *(auto-set)* | ACME directory URL — auto-populated from `CA_PROVIDER`; required only when `CA_PROVIDER=custom` |
| `MANAGED_DOMAINS` | *(required)* | *(acme mode only)* Comma-separated list of domains to monitor |
| `RENEWAL_THRESHOLD_DAYS` | `30` | Renew when fewer than N days remain |
| `CERT_STORE_PATH` | `./certs` | Root directory for PEM files |
| `ACCOUNT_KEY_PATH` | `./account.key` | Path to persist the ACME account key |
| `HTTP_CHALLENGE_MODE` | `standalone` | *(acme mode only)* `standalone` or `webroot` |
| `HTTP_CHALLENGE_PORT` | `80` | *(acme mode only)* Port for the standalone HTTP-01 server |
| `WEBROOT_PATH` | — | *(acme mode only)* Required when `HTTP_CHALLENGE_MODE=webroot` |
| `SPIRE_AGENT_SOCKET_PATH` | `/tmp/spire-agent/public/api.sock` | *(spiffe mode only)* Local Unix domain socket for the SPIRE Agent's Workload API — no network directory URL, since SPIFFE authentication is attestation-based, not domain-validated |
| `SPIFFE_TRUST_DOMAIN` | — | *(spiffe mode only, required)* Your SPIRE deployment's trust domain (e.g. `example.org`) — there is no public CA equivalent; trust is rooted in your own SPIRE server |
| `MANAGED_SPIFFE_IDS` | *(empty)* | *(spiffe mode only)* Comma-separated list of SPIFFE IDs this agent expects to hold/renew — for planner classification and monitoring only; the SPIRE server's own registration entries are the actual source of truth for what's issuable |
| `LLM_DISABLED` | `true` | Gates the renewal planner only. If `false`, the planner classifies domains via LLM (urgent/routine/skip); error_handler and reporter are always deterministic regardless of this flag |
| `LLM_PROVIDER` | `claude_cli` | LLM vendor for the planner: `claude_cli` (default — shells to `claude -p`, no API key) · `anthropic` · `openai` · `ollama` |
| `ANTHROPIC_API_KEY` | — | Claude API key (required when `LLM_PROVIDER=anthropic` and `LLM_DISABLED=false`; not needed for `claude_cli`) |
| `OPENAI_API_KEY` | — | OpenAI API key (required when `LLM_PROVIDER=openai` and `LLM_DISABLED=false`) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama local server URL (used when `LLM_PROVIDER=ollama`) |
| `LLM_MODEL_PLANNER` | `haiku` | Model for renewal planning (adjust based on `LLM_PROVIDER` — `claude_cli`/`anthropic` accept short aliases like `haiku`/`sonnet` or full model IDs; `ollama` needs a locally pulled model tag) |
| `SCHEDULE_TIME` | `06:00` | Daily run time (HH:MM, UTC) |
| `MAX_RETRIES` | `3` | Per-domain retry attempts before skipping |
| `ACME_INSECURE` | `false` | Disable TLS verification — **testing only, never in production** |
| `ACME_CA_BUNDLE` | — | Path to custom CA certificate bundle for private ACME servers |
| `LANGCHAIN_TRACING_V2` | `false` | Enable LangSmith tracing |
| `LANGCHAIN_API_KEY` | — | LangSmith API key (required when tracing is enabled) |
| `LANGCHAIN_PROJECT` | `acme-cert-agent` | LangSmith project name |

---

## LLM_DISABLED Configuration

- **Type:** `bool`
- **Default:** `true`
- **Description:** Gates the renewal planner's LLM path only (task:362053db). When `true` (default), the planner uses deterministic priority logic. `error_handler` and `reporter` have no LLM path at all regardless of this flag — their LLM implementations were removed in task:0fecd30e and are out of scope for this flag.

### Deterministic Behavior (default, `LLM_DISABLED=true`)

- **Renewal Planner:** Renews ALL domains with certificates expiring within `RENEWAL_THRESHOLD_DAYS`, plus all domains missing certificates. No prioritization — see `_renewal_planner_deterministic()` in `agent/nodes/planner.py`.
- **Error Handler:** Always deterministic — retries up to `MAX_RETRIES` times with exponential backoff (capped at 300s), aborts on fatal ACME errors, skips after max retries.
- **Summary Reporter:** Always deterministic — plain-text formatted summary (no LLM-generated prose).
- **No LLM API calls:** No `LLM_PROVIDER`, `LLM_MODEL_PLANNER`, or API key validation required.

### LLM-Assisted Planner (`LLM_DISABLED=false`)

- **`LLM_PROVIDER=claude_cli` (default)**: shells to `claude -p --safe-mode --tools none`, reusing your existing Claude Code login. No API key, no `uv sync --extra llm-*` install — just the `claude` binary on PATH. This is the path of least setup, and was demonstrably more schema-compliant in testing than a small local Ollama model. It's also the best option for quick local testing on RAM-constrained hardware (e.g. 8GB machines): inference runs on Anthropic's infra, not your box, so there's no model to download or keep loaded in memory, unlike a local Ollama model competing with everything else running.
- **`anthropic`/`openai`/`ollama`**: go through langchain — require the matching optional extra (`uv sync --extra llm-anthropic` / `llm-openai` / `llm-ollama`) and, for `anthropic`/`openai`, the corresponding API key.
- The planner classifies each managed domain into `urgent`/`routine`/`skip` via an LLM call, then queues `urgent + routine` for renewal. Output is validated against `managed_domains` — any hallucinated domain is stripped, any non-string/malformed item is dropped (a small model returning `{"domain": "x"}` objects instead of plain strings won't crash the node), markdown code fences wrapping the JSON are stripped before parsing, and any domain the LLM fails to classify is added to `routine` so nothing silently falls through.
- `error_handler`/`reporter` remain deterministic even with this enabled.

### Use Cases

- Air-gapped environments without LLM API access
- Cost optimization (no API calls)
- Reproducible, auditable renewal logic
- Development/testing environments

### Example

```env
LLM_DISABLED=true
CA_PROVIDER=letsencrypt
MANAGED_DOMAINS=api.example.com,shop.example.com
```

---

## Metadata

- **Owner**: DevOps / Operations team
- **Status**: active (runtime configuration reference)
- **Last reviewed**: 2026-03-03
- **Next review due**: 2026-06-03 (quarterly, or on new config options)
