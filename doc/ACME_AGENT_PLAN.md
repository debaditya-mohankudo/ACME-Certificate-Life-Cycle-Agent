# ACME Certificate Lifecycle Agent — Architecture & Implementation Plan

> **Note:** This is the original design specification written before implementation. Some sections (AgentState shape, config fields, node list) reflect the initial plan and may differ from the current codebase.
> For the current system, see [HOW_IT_WORKS.md](HOW_IT_WORKS.md), [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md), and [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md).

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- Current graph flow: [HOW_IT_WORKS.md](HOW_IT_WORKS.md)
- Design constitution: [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md)

---

**Stack:** Python · LangGraph · Multi-CA ACME (DigiCert · Let's Encrypt · custom) · HTTP-01 Challenge · PEM Filesystem Storage
**Author:** Deb | **Date:** February 2026

---

## 1. Project Overview

An intelligent, agentic certificate lifecycle manager built on **LangGraph** that:
- Monitors TLS certificate expiry across multiple domains
- Uses an **LLM** to plan renewal strategy, prioritize, and reason about failures
- Executes the full **ACME RFC 8555** flow against **any RFC 8555-compliant CA** (DigiCert, Let's Encrypt, or custom)
- Validates domain ownership via **HTTP-01 challenges**
- Stores issued certificates as **PEM files** on the local filesystem
- Runs on a schedule (e.g., daily) — critical for the upcoming **47-day TLS mandate (2029)**

### Why LangGraph?

LangGraph is ideal for ACME because the protocol is inherently a **stateful multi-step workflow** with conditional branching (retries, multi-domain loops, error recovery). LangGraph gives you:
- Persistent state across every step of the ACME flow
- LLM "planner" node for intelligent decision-making
- Conditional edges for retry logic and failure routing
- Optional checkpointing (resume interrupted flows)
- Built-in support for human-in-the-loop (approve renewals)

---

## 2. DigiCert ACME Endpoint Details

DigiCert provides ACME directories for different certificate types:

| Certificate Type | ACME Directory URL |
|------------------|--------------------|
| **DV SSL** (Domain Validated) | `https://acme.digicert.com/v2/DV/directory` |
| **OV SSL** (Organization Validated) | `https://acme.digicert.com/v2/OV/directory` |
| **EV SSL** (Extended Validation) | `https://acme.digicert.com/v2/EV/directory` |

### External Account Binding (EAB)

DigiCert ACME requires **EAB credentials** (unlike Let's Encrypt which allows anonymous registration). Get from DigiCert Console → ACME:
- `EAB_KEY_ID` — Key identifier
- `EAB_HMAC_KEY` — Base64url-encoded HMAC key

These are passed during ACME account registration per **RFC 8555 §7.3.4**.

### ACME Protocol Flow (RFC 8555)

```
1. GET /directory           → Discover ACME endpoints
2. POST /newAccount         → Register account (with EAB)
3. POST /newOrder           → Create certificate order for domain(s)
4. GET  /order/challenges   → Get HTTP-01 challenge token + URL
5. Serve token at           → http://<domain>/.well-known/acme-challenge/<token>
6. POST /challenge          → Tell the CA to verify
7. Poll /order              → Wait for "valid" status
8. POST /finalize           → Submit CSR (with private key generated locally)
9. GET  /certificate        → Download cert chain (PEM)
10. Store cert + key        → Write to ./certs/<domain>/
```

---

## 3. LangGraph Architecture

### 3.1 Agent State (TypedDict)

```python
from typing import TypedDict, Annotated, List, Optional, Dict
from datetime import datetime
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class CertRecord(TypedDict):
    domain: str
    cert_path: Optional[str]           # Path to existing cert.pem
    key_path: Optional[str]            # Path to privkey.pem
    expiry_date: Optional[datetime]    # Parsed from existing cert
    days_until_expiry: Optional[int]   # Computed at scan time
    needs_renewal: bool                # True if < renewal_threshold days


class AcmeOrder(TypedDict):
    order_url: str
    status: str                        # pending | ready | processing | valid | invalid
    challenge_url: str
    challenge_token: str               # HTTP-01 token
    key_authorization: str             # token + "." + account_thumbprint
    finalize_url: str
    certificate_url: Optional[str]


class AgentState(TypedDict):
    # ── Configuration ──────────────────────────────────────────────────────
    managed_domains: List[str]         # All domains to monitor
    renewal_threshold_days: int        # Default: 30 days before expiry
    cert_store_path: str               # Local dir for PEM files (./certs/)
    webroot_path: Optional[str]        # If using webroot mode for HTTP-01

    # ── Scan Results ───────────────────────────────────────────────────────
    cert_records: List[CertRecord]     # One per managed domain
    pending_renewals: List[str]        # Domains needing renewal

    # ── Active ACME Flow ───────────────────────────────────────────────────
    current_domain: Optional[str]      # Domain being processed now
    current_order: Optional[AcmeOrder]
    acme_account_url: Optional[str]    # Cached account URL after registration
    acme_account_key: Optional[str]    # JWK private key (serialized)

    # ── LLM Reasoning ──────────────────────────────────────────────────────
    messages: Annotated[list, add_messages]   # LangGraph message accumulation
    renewal_plan: Optional[str]        # LLM's written renewal strategy
    error_analysis: Optional[str]      # LLM's failure reasoning

    # ── Progress Tracking ──────────────────────────────────────────────────
    completed_renewals: List[str]
    failed_renewals: List[str]
    error_log: List[str]
    retry_count: int                   # Per-domain retry attempts
    max_retries: int                   # Default: 3
```

---

### 3.2 Graph Nodes

| Node | Type | Responsibility |
|------|------|----------------|
| `certificate_scanner` | Tool | Read all managed domain cert files, parse expiry dates, compute `days_until_expiry`, populate `cert_records` |
| `renewal_planner` | **LLM** | Analyze scan results, write `renewal_plan` (priority order, strategy, notes), populate `pending_renewals` |
| `acme_account_setup` | Tool | Register or retrieve ACME account; EAB injected by the CA client subclass. Store `acme_account_url` |
| `order_initializer` | Tool | POST to `/newOrder` for `current_domain`. Get challenge URL and token |
| `challenge_setup` | Tool | Write HTTP-01 token to webroot OR start standalone HTTP server on port 80 |
| `challenge_verifier` | Tool | POST to challenge URL, poll authorization status until `valid` or `invalid` |
| `csr_generator` | Tool | Generate RSA-2048 or EC P-256 private key + CSR for `current_domain` |
| `order_finalizer` | Tool | POST CSR to `/finalize`, poll until certificate URL is available |
| `cert_downloader` | Tool | GET certificate chain from CA (POST-as-GET), save to PEM |
| `storage_manager` | Tool | Write `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem` to `./certs/<domain>/` |
| `domain_loop_router` | Logic | Check if more domains in `pending_renewals`, route to next or to summary |
| `error_handler` | **LLM** | Analyze failure, decide: retry/skip/abort; schedule retry via `retry_not_before` timestamp |
| `retry_scheduler` | Tool | Apply backoff delay (non-blocking if async); clear `retry_not_before` before proceeding |
| `summary_reporter` | **LLM** | Generate final renewal report (successes, failures, next check date) |

---

### 3.3 Graph Topology (Flow Diagram)

```
START
  │
  ▼
[certificate_scanner]
  │  Scans ./certs/ dir, reads existing PEM files, parses expiry
  │
  ▼
[renewal_planner]  ◄── LLM NODE
  │  "Domain api.example.com expires in 5 days — URGENT.
  │   Domain shop.example.com expires in 25 days — ROUTINE.
  │   Process urgent first."
  │
  ├── no_renewals_needed ──────────────────────────────► [summary_reporter] ──► END
  │
  ▼
[acme_account_setup]
  │  Register/retrieve ACME account (EAB handled by CA subclass)
  │  (Only runs once per session; subsequent domains reuse account)
  │
  ▼
[order_initializer]  ◄─────────────────────────────────────────────┐
  │  POST /newOrder for current_domain                              │
  │                                                                 │
  ▼                                                                 │
[challenge_setup]                                                   │
  │  Write token to /.well-known/acme-challenge/<token>             │
  │                                                                 │
  ▼                                                                 │
[challenge_verifier]                                                │
  │  Tell the CA to check; poll until valid/invalid                 │
  │                                                                 │
  ├── challenge_failed ──► [error_handler] ◄── LLM NODE            │
  │                           │                                     │
  │                           ├── retry ──► [retry_scheduler] ──────┘
  │                           │              (applies backoff)
  │                           │
  │                           └── skip_domain ──► [domain_loop_router]
  │                                                     │
  ▼                                                     │
[csr_generator]                                         │
  │  Generate private key + CSR                         │
  │                                                     │
  ▼                                                     │
[order_finalizer]                                       │
  │  Submit CSR, poll for cert URL                      │
  │                                                     │
  ▼                                                     │
[cert_downloader]                                       │
  │  Download full cert chain from CA                   │
  │                                                     │
  ▼                                                     │
[storage_manager]                                       │
  │  Write PEM files to ./certs/<domain>/               │
  │  completed_renewals.append(current_domain)          │
  │                                                     │
  ▼                                                     │
[domain_loop_router] ────── more_domains ───────────────┘
  │
  └── all_done ──► [summary_reporter] ◄── LLM NODE
                         │
                        END
```

### 3.4 Revocation Subgraph Topology

A separate `agent/revocation_graph.py` handles certificate revocation (RFC 8555 § 7.6):

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
  │                                          │
  ▼                                          │
[cert_revoker]                               │
  │  POST /revokeCert for current domain     │
  │  (reads cert.pem from disk; fails        │
  │   gracefully if not found)               │
  │                                          │
  ▼                                          │
[revocation_loop_router] ─ next_domain ──────┘
  │
  └── all_done ──► [revocation_reporter] ◄── LLM NODE
                         │
                        END
```

**Key differences from renewal:**
- No error_handler / retry logic — failures are logged and the loop continues (best-effort)
- Triggered on-demand (via `--revoke-cert` CLI), not scheduled
- Requires domains to have issued certificates (reads from disk)
- Accepts an RFC 5280 reason code (0=unspecified, 1=keyCompromise, 4=superseded, 5=cessationOfOperation)

---

## 4. Project Structure

```
acme-agent/
│
├── main.py                          # CLI entry point (run agent, schedule)
├── config.py                        # Pydantic settings (env vars, domains)
├── .env                             # ACME credentials and settings (gitignored)
│
├── agent/
│   ├── __init__.py
│   ├── state.py                     # AgentState TypedDict, CertRecord, AcmeOrder
│   ├── graph.py                     # Build & compile the LangGraph StateGraph
│   ├── prompts.py                   # LLM system prompts for each LLM node
│   │
│   └── nodes/
│       ├── __init__.py
│       ├── scanner.py               # certificate_scanner node
│       ├── planner.py               # renewal_planner (LLM node)
│       ├── account.py               # acme_account_setup node
│       ├── order.py                 # order_initializer node
│       ├── challenge.py             # challenge_setup + challenge_verifier nodes
│       ├── csr.py                   # csr_generator node
│       ├── finalizer.py             # order_finalizer + cert_downloader nodes
│       ├── storage.py               # storage_manager node
│       ├── router.py                # domain_loop_router (conditional edge logic)
│       ├── error_handler.py         # error_handler (LLM node)
│       └── reporter.py              # summary_reporter (LLM node)
│
├── acme/
│   ├── __init__.py
│   ├── client.py                    # Low-level ACME RFC 8555 HTTP client
│   ├── crypto.py                    # Key gen, CSR creation (cryptography lib)
│   ├── jws.py                       # JWS/JWK signing for ACME requests
│   └── http_challenge.py            # Standalone HTTP-01 server (port 80)
│
├── storage/
│   ├── __init__.py
│   └── filesystem.py                # PEM read/write, directory management
│
└── certs/                           # Generated PEM files (gitignored)
    └── example.com/
        ├── cert.pem                 # End-entity certificate
        ├── chain.pem                # Intermediate CA chain
        ├── fullchain.pem            # cert + chain (nginx uses this)
        └── privkey.pem              # Private key (chmod 600)
```

---

## 5. Key Implementation Details

### 5.1 ACME Client (`acme/client.py`)

The ACME protocol uses **JWS (JSON Web Signatures)** for all requests. Every POST is signed with the account private key.

```python
# Class hierarchy — CA-specific details encapsulated in subclasses:
class AcmeClient:                            # Base — all RFC 8555 protocol logic
    def __init__(self, directory_url): ...
    def get_directory(self) -> dict          # GET /directory
    def get_nonce(self) -> str               # HEAD /newNonce
    def create_account(self, account_key, nonce, directory)  # POST /newAccount (plain)
    def create_order(self, domains: List[str]) -> dict       # POST /newOrder
    def get_authorization(self, auth_url: str) -> dict       # POST-as-GET /authz
    def respond_to_challenge(self, challenge_url: str)       # POST challenge URL
    def poll_authorization(self, auth_url: str) -> str       # poll until valid
    def finalize_order(self, finalize_url, csr_der) -> dict  # POST /finalize
    def poll_order_for_certificate(self, order_url) -> str   # poll until cert ready
    def download_certificate(self, cert_url: str) -> str     # POST-as-GET cert (PEM)

class DigiCertAcmeClient(AcmeClient):       # Overrides create_account → injects EAB
    DEFAULT_DIRECTORY_URL = "https://acme.digicert.com/v2/DV/directory"
    def __init__(self, eab_key_id, eab_hmac_key, directory_url=...): ...

class LetsEncryptAcmeClient(AcmeClient):    # Preset URLs; inherits plain create_account
    PRODUCTION_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
    STAGING_DIRECTORY_URL    = "https://acme-staging-v02.api.letsencrypt.org/directory"
    def __init__(self, staging=False): ...

def make_client() -> AcmeClient:            # Factory — reads CA_PROVIDER from settings
    ...
```

### 5.2 JWS Signing (`acme/jws.py`)

ACME requires **RS256** or **ES256** JWS signed requests. Libraries to use:
- `josepy` — Battle-tested JWS/JWK library from Certbot
- OR `cryptography` + `PyJWT` for more control

```python
# Key ACME crypto operations:
def generate_account_key() -> RSAPrivateKey           # 2048-bit RSA
def generate_domain_key() -> RSAPrivateKey            # For CSR
def create_csr(private_key, domain: str) -> bytes     # DER-encoded CSR
def sign_jws(payload, private_key, nonce, url) -> dict  # ACME-format JWS
def create_eab_jws(account_jwk, eab_kid, eab_hmac) -> dict  # EAB binding
def compute_key_authorization(token, account_key) -> str    # HTTP-01 answer
```

### 5.3 HTTP-01 Challenge Server (`acme/http_challenge.py`)

Two modes — choose based on environment:

```python
# Mode 1: Webroot (if nginx/apache already serving on port 80)
def write_webroot_challenge(webroot_path, token, key_auth):
    path = f"{webroot_path}/.well-known/acme-challenge/{token}"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(key_auth)

# Mode 2: Standalone server (spin up temporary HTTP server on port 80)
class StandaloneHttpChallenge:
    """Minimal HTTP server that serves ONLY the challenge token."""
    def start(self, token: str, key_authorization: str): ...
    def stop(self): ...
    # Uses threading + http.server or uvicorn on port 80
```

### 5.4 LLM Planner Node (`agent/nodes/planner.py`)

```python
PLANNER_PROMPT = """
You are a TLS Certificate Lifecycle Manager.

You have scanned the following domains and their certificate status:
{cert_summary}

Your job is to:
1. Identify which domains need IMMEDIATE renewal (< 7 days)
2. Identify which domains need ROUTINE renewal (< 30 days)
3. Decide the processing ORDER (most urgent first)
4. Flag any domains where renewal may be risky (e.g., recently failed)
5. Note any domains that don't need action

Write a concise renewal plan in JSON format:
{{
  "urgent": ["domain1.com"],
  "routine": ["domain2.com", "domain3.com"],
  "skip": [],
  "notes": "api.example.com expires in 3 days — process first"
}}
"""
```

### 5.5 LLM Error Handler (`agent/nodes/error_handler.py`)

```python
ERROR_HANDLER_PROMPT = """
You are diagnosing a TLS certificate renewal failure for domain: {domain}

Error encountered: {error}
Retry attempt: {retry_count} of {max_retries}
ACME order status: {order_status}

Decide the best course of action:
- "retry": Try the challenge again (if transient DNS/network issue)
- "skip": Skip this domain and continue with others (if domain unreachable)
- "abort": Stop all renewals (if credentials or CA issue)

Respond in JSON: {{"action": "retry|skip|abort", "reason": "..."}}
"""
```

### 5.6 PEM File Storage Layout

```
./certs/
└── api.example.com/
    ├── cert.pem        # Leaf certificate only
    ├── chain.pem       # Intermediate CA chain
    ├── fullchain.pem   # cert.pem + chain.pem (for nginx/apache)
    ├── privkey.pem     # RSA private key (chmod 600 — owner read only)
    └── metadata.json   # {issued_at, expires_at, acme_order_url, renewed_by}
```

---

## 6. Configuration (`config.py`)

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # CA selection
    CA_PROVIDER: Literal["digicert", "letsencrypt", "letsencrypt_staging", "custom"] = "digicert"
    ACME_DIRECTORY_URL: str = ""  # Auto-set from CA_PROVIDER; required only for "custom"

    # EAB credentials (DigiCert only; leave empty for Let's Encrypt)
    ACME_EAB_KEY_ID: str = ""     # From DigiCert console
    ACME_EAB_HMAC_KEY: str = ""   # Base64url-encoded HMAC key

    # Domain management
    MANAGED_DOMAINS: List[str]    # ["api.example.com", "shop.example.com"]
    RENEWAL_THRESHOLD_DAYS: int = 30

    # Storage
    CERT_STORE_PATH: str = "./certs"

    # HTTP-01 Challenge
    HTTP_CHALLENGE_MODE: str = "standalone"  # "standalone" or "webroot"
    WEBROOT_PATH: Optional[str] = None       # Path if using webroot mode

    # LLM
    ANTHROPIC_API_KEY: str        # For Claude (or OPENAI_API_KEY)
    LLM_MODEL: str = "claude-opus-4-5-20251101"

    class Config:
        env_file = ".env"
```

---

## 7. LangGraph Key Concepts You'll Learn

| Concept | Where Used in This Project |
|---------|---------------------------|
| `StateGraph` | Main graph builder in `agent/graph.py` |
| `TypedDict` State | `AgentState` — shared state passed between all nodes |
| Regular Nodes | Every tool node (scanner, challenge, storage etc.) |
| LLM Nodes | `renewal_planner`, `error_handler`, `summary_reporter` |
| `add_node()` | Registering each function as a graph node |
| `add_edge()` | Deterministic flow (scanner → planner → account → ...) |
| `add_conditional_edges()` | Loop router, error handler decisions |
| `compile()` | Produces the runnable `CompiledGraph` |
| `MemorySaver` | Optional checkpointing — resume after interruption |
| `interrupt_before` | Human-in-the-loop: pause before finalizing order |
| Streaming | Stream agent steps as events for live logging |

---

## 8. Implementation Phases

### Phase 1: ACME Protocol Core (Week 1)
1. `acme/jws.py` — Key generation, JWS signing, EAB
2. `acme/client.py` — Full ACME client (directory → order → finalize)
3. `acme/http_challenge.py` — Standalone HTTP-01 server
4. `storage/filesystem.py` — PEM read/write
5. **Unit test**: Full ACME flow against Let's Encrypt staging (free, safe)

### Phase 2: LangGraph Nodes (Week 2)
6. `agent/state.py` — Define `AgentState`, `CertRecord`, `AcmeOrder`
7. `agent/nodes/scanner.py` — Scan PEM files, parse expiry
8. `agent/nodes/planner.py` — LLM planner with structured output
9. `agent/nodes/account.py` — ACME account setup
10. `agent/nodes/order.py`, `challenge.py`, `finalizer.py` — ACME workflow nodes
11. `agent/nodes/storage.py` — Write cert PEMs
12. `agent/nodes/error_handler.py` — LLM error reasoning

### Phase 3: Graph Assembly & Testing (Week 3)
13. `agent/graph.py` — Wire all nodes, conditional edges, compile graph
14. `main.py` — CLI runner with scheduling
15. **Integration test**: Run full renewal against Let's Encrypt staging
16. **DigiCert test**: Validate against DigiCert staging (if available)

### Phase 4: Hardening & Observability (Week 4)
17. LangSmith tracing for LLM node visibility
18. Structured logging (structlog)
19. Alerting on renewal failure (email/webhook)
20. `MemorySaver` for checkpointing long-running multi-domain flows
21. Dockerfile for containerized deployment

---

## 9. Dependencies (`pyproject.toml`)

```
# LangGraph / LangChain
langgraph>=0.2.0
langchain>=0.3.0
langchain-anthropic>=0.3.0      # or langchain-openai

# ACME Protocol
josepy>=1.14.0                  # JWS/JWK signing (from Certbot)
cryptography>=42.0.0            # Key gen, CSR, cert parsing
requests>=2.31.0                # HTTP client for ACME calls
httpx>=0.27.0                   # Async HTTP (optional)

# Configuration & Settings
pydantic-settings>=2.0.0
python-dotenv>=1.0.0

# Storage & Utils
certifi>=2024.0.0               # CA bundle
schedule>=1.2.0                 # Job scheduling
structlog>=24.0.0               # Structured logging

# Dev / Testing
pytest>=8.0.0
pytest-asyncio>=0.23.0
responses>=0.25.0               # Mock HTTP for ACME client tests
```

---

## 10. Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| ACME library | `josepy` + manual client | Full control over EAB and CA-specific behaviour; Certbot's library is battle-tested |
| LLM model | `claude-opus-4-5-20251101` | Best reasoning for error analysis and renewal planning |
| Key algorithm | RSA-2048 (default) / EC P-256 (optional) | RSA for broadest CA compatibility; EC for performance |
| HTTP challenge | Standalone mode (default) | Most portable — doesn't require existing web server |
| State persistence | In-memory (start) → MemorySaver (later) | Walk before run; add checkpointing in Phase 4 |
| Scheduling | `schedule` lib (simple cron-like) | Lightweight; replace with APScheduler or Celery Beat if needed |

---

## 11. Security Considerations

- **Private key protection:** `chmod 600 privkey.pem` immediately after writing
- **EAB credentials:** Store in `.env` only — never commit to git
- **HTTP-01 server:** Bind to `0.0.0.0:80` only during challenge window; shut down immediately after
- **Account key:** Store encrypted or in OS keychain (Phase 4 hardening)
- **Port 80 requirement:** HTTP-01 challenge requires port 80 to be open. May need `authbind` on Linux to run as non-root.

---

## 12. Example: What the Agent Looks Like in Action

```
[2026-02-19 06:00:00] 🔍 Certificate Scanner starting...
[2026-02-19 06:00:01]   api.example.com     → expires 2026-02-24 (5 days)  ⚠️ URGENT
[2026-02-19 06:00:01]   shop.example.com    → expires 2026-03-15 (24 days) ✓ ROUTINE
[2026-02-19 06:00:01]   blog.example.com    → expires 2026-04-20 (60 days) ✅ OK

[2026-02-19 06:00:02] 🤖 Renewal Planner (LLM) reasoning...
  "api.example.com is critical — 5 days remaining. Process immediately.
   shop.example.com needs renewal within the week. Process second.
   blog.example.com is healthy — skip this cycle."

[2026-02-19 06:00:03] 🔑 ACME Account: Retrieved existing account
[2026-02-19 06:00:03] 📋 Creating ACME order for api.example.com...
[2026-02-19 06:00:04] ⚡ HTTP-01 Challenge: Starting standalone server on :80
[2026-02-19 06:00:04]   Serving: /.well-known/acme-challenge/abc123xyz...
[2026-02-19 06:00:07] ✅ Challenge VALID — CA verified api.example.com
[2026-02-19 06:00:07] 📝 Generating RSA-2048 private key and CSR...
[2026-02-19 06:00:08] 🎯 Finalizing order — submitting CSR...
[2026-02-19 06:00:12] 📜 Certificate issued — downloading chain...
[2026-02-19 06:00:12] 💾 Storing PEM files to ./certs/api.example.com/
[2026-02-19 06:00:12]   ✅ cert.pem, chain.pem, fullchain.pem, privkey.pem written

[2026-02-19 06:01:05] ✅ shop.example.com — renewed successfully

[2026-02-19 06:01:06] 📊 Summary Reporter (LLM):
  "Renewed 2 of 2 pending certificates. api.example.com renewed 5 days before
   expiry — cut it close. Consider lowering renewal_threshold_days to 45 for
   this domain. Next check: tomorrow at 06:00."
```

---

*Ready to implement? Phase 1 starts with the ACME JWS client — the cryptographic foundation everything else builds on.*
