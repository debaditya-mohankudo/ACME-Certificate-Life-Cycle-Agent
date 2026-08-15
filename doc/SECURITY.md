# Security Design of the ACME Certificate Lifecycle Agent

This document details every security decision baked into the agent — why it was made,
where in the code it lives, and what threat it addresses.

## When to use this page

- "Is this system secure?"
- "How are private keys protected?"
- "What are the security controls?"
- "Is checkpoint/trace data safe?"
- "How does LLM output validation work?"

## Canonicality

- **Canonical for**: Security design, key isolation, atomic writes, LLM validation, audit trails, container hardening
- **Not canonical for**: RFC compliance details (→ [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)), test coverage (→ [CI_TEST_COVERAGE.md](CI_TEST_COVERAGE.md)), configuration (→ [CONFIGURATION.md](CONFIGURATION.md))

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Security & quality hub: [WIKI_SECURITY_QUALITY.md](WIKI_SECURITY_QUALITY.md)
- RFC compliance mapping: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)
- Architecture constitution: [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md)

## Retrieval keywords

`security`, `private key`, `account key isolation`, `atomic writes`, `tls verification`, `ACME_INSECURE`, `credential handling`, `file permissions`, `container hardening`, `network exposure`, `retry safety`, `mcp security`, `core dump`, `RLIMIT_CORE`, `crash-time key exposure`
[negative keywords / not-this-doc]
async, concurrency, parallel, checkpoint, nonce, stateful, planner, LLM, CI, MCP, revoke, configuration, storage, atomic, filesystem, docker, container, test, coverage, audit, performance, optimization, operator

---

## Table of Contents

1. [Private Key Handling](#1-private-key-handling)
2. [LangSmith / Trace Leakage Prevention](#2-langsmith--trace-leakage-prevention)
3. [TLS Enforcement for ACME API Calls](#3-tls-enforcement-for-acme-api-calls)
4. [ACME Protocol Integrity](#4-acme-protocol-integrity)
5. [HTTP-01 Challenge Server](#5-http-01-challenge-server)
6. [LLM Output Validation](#6-llm-output-validation)
7. [API Key and Credential Handling](#7-api-key-and-credential-handling)
8. [File Permissions](#8-file-permissions)
9. [Docker and Container Security](#9-docker-and-container-security)
10. [Network Exposure](#10-network-exposure)
11. [Resilience and Retry Safety](#11-resilience-and-retry-safety)
12. [MCP Server Security Controls](#12-mcp-server-security-controls)
13. [Known Constraints and Hardening Recommendations](#13-known-constraints-and-hardening-recommendations)
14. [Summary Table](#14-summary-table)

---

## 1. Private Key Handling

### Account key — never stored in agent state

The ACME account private key is the most sensitive long-lived credential in the system.
A deliberate design rule, documented in [agent/state.py](../agent/state.py), keeps it
entirely out of `AgentState`:

```python
# agent/state.py
# acme_account_key is NOT stored in state (security: would leak into
# LangSmith traces).  The account key is loaded from disk by the account
# node and passed through a secure side-channel (the key path is in state).

account_key_path: str   # only the path travels through state
```

Only the *path* to the key file is in state. Every node that needs the key loads it
directly from disk at the moment of use ([agent/nodes/challenge.py](../agent/nodes/challenge.py)):

```python
account_key = jwslib.load_account_key(state["account_key_path"])
```

**Threat addressed:** If LangSmith tracing is enabled (`LANGCHAIN_TRACING_V2=true`),
the full `AgentState` dict is uploaded to LangSmith on every node transition. Keeping
the private key out of state ensures it can never appear in a trace, a log, or a
third-party telemetry service.

### Key generation — secure defaults

Both account and domain keys are generated with
[cryptography](https://cryptography.io)'s OS-level CSPRNG:

| Key type | Algorithm | Size / Curve | File |
|---|---|---|---|
| ACME account key | RSA | 2048-bit | [acme/jws.py](../acme/jws.py) |
| Domain certificate key | RSA (default) | 2048-bit | [acme/crypto.py](../acme/crypto.py) |
| Domain certificate key | EC (alternative) | P-256 (SECP256R1) | [acme/crypto.py](../acme/crypto.py) |

All use `public_exponent=65537` and the `default_backend()` which delegates to
OpenSSL's `RAND_bytes`.

### Key serialisation — PKCS8 / PKCS1, no password

Keys are serialised to PEM with `NoEncryption()`. This is a deliberate trade-off:
password-protecting keys would require interactive input or another secret, both of
which conflict with unattended automation. The compensating control is strict
**filesystem permissions** — see [§8](#8-file-permissions).

The account key is saved in PKCS8 format; domain keys in TraditionalOpenSSL
(PKCS1) format — both are standard PEM formats compatible with nginx, Apache,
and other consumers.

### CSR — only public material in state

The Certificate Signing Request carries only the domain name and the public key.
The corresponding private key never enters state. The CSR itself is hex-encoded
before being placed in the `AcmeOrder` dict so it can travel safely through
LangGraph's state serialisation without binary encoding issues
([agent/nodes/csr.py](../agent/nodes/csr.py)):

```python
order["csr_hex"] = csr_bytes.hex()   # private key stays in local scope
```

CSR signing uses **SHA-256** with the domain's RSA private key.

### Core dump suppression — crash-time key exposure

Domain and account private keys are held in process memory for the life of the
run. Absent any mitigation, a process crash (segfault, `abort()`, `SIGQUIT`) can
cause the OS to write a core dump containing that in-memory key material to disk
— a persistent, readable artifact with no expiry, distinct from a runtime read
bug like Heartbleed and fully within this codebase's control to close.

[main.py](../main.py) disables core dumps for its own process at the very start
of `main()`, before argument parsing and before any lazy import that could
generate key material:

```python
# main.py
def suppress_core_dumps() -> None:
    try:
        import resource
    except ImportError:
        return  # not available on Windows; no-op rather than fail the process
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError) as exc:
        log.warning("Could not disable core dumps: %s", exc)
```

This covers every CLI subcommand (`--once`, `--schedule`, `--revoke-cert`,
`--generate-test-cert`, `--tui`) since it runs once at process startup rather
than per-subcommand. It fails open (logs a warning, continues) rather than
crashing the CLI if the host's hard limit cannot be lowered — consistent with
[§13](#13-known-constraints-and-hardening-recommendations)'s general posture of
defense-in-depth controls that degrade gracefully rather than block operation.

**mcp_server.py is a separate long-lived process** with its own startup path and
does not yet call this helper — tracked as a follow-up (task:62845f14, not yet
implemented as of this writing).

**Threat addressed:** Post-crash forensic exposure of private key material via
an on-disk core dump, e.g. from an unhandled exception, OOM kill, or signal
during a renewal run.

---

## 2. LangSmith / Trace Leakage Prevention

When `LANGCHAIN_TRACING_V2=true`, every `AgentState` snapshot and every LLM
message is uploaded to LangSmith. The following items are explicitly kept out of
state to prevent them appearing in traces:

| Sensitive item | How it is kept out |
|---|---|
| ACME account private key | Only `account_key_path` (a string path) is in state |
| Domain private keys | Generated in-node local scope; only the hex-encoded CSR enters state |
| EAB HMAC key | Read from `config.settings` inside the node; never added to state |
| LLM API keys | Read from `config.settings`; never added to state |

The `messages` field in state does travel to LangSmith — it contains LLM prompts
and responses. These are carefully reviewed to ensure no private key material or
credential is ever included in a prompt template
([agent/prompts.py](../agent/prompts.py)).

---

## 3. TLS Enforcement for ACME API Calls

All HTTP communication with the CA's ACME API goes through a `requests.Session`
configured in [acme/client.py](../acme/client.py):

```python
# acme/client.py — AcmeClient.__init__
if insecure:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    self._session.verify = False
elif ca_bundle:
    self._session.verify = ca_bundle
# else: verify=True (requests default) — system CA bundle
```

The key defaults:

- `ACME_INSECURE=false` by default (`config.py`) — TLS verification is **on**.
- When `ACME_CA_BUNDLE` is set, that bundle is used (supports private/enterprise CAs).
- `ACME_INSECURE=true` suppresses only InsecureRequestWarning noise; it is
  documented as *never use in production* in both `config.py` and `CLAUDE.md`.

**Threat addressed:** Man-in-the-middle attacks on ACME API traffic. A compromised
CA response could cause the agent to install a certificate signed by an untrusted
authority. TLS verification ensures the agent only trusts the legitimate CA.

The LLM provider calls (Anthropic, OpenAI) are made by the vendor SDK, which also
enforces TLS by default.

---

## 4. ACME Protocol Integrity

### Nonce-based replay protection (RFC 8555 § 6.5)

Every ACME POST request includes a server-issued one-time nonce in the JWS
protected header. The agent:

1. Fetches a fresh nonce via `HEAD /newNonce` before each request
   ([acme/client.py](../acme/client.py)).
2. Validates the nonce is non-empty **before signing** — `sign_request()` raises
   `ValueError` immediately if `nonce` is empty or whitespace-only, surfacing the
   failure at the call site rather than letting the CA return `badNonce`
   ([acme/jws.py](../acme/jws.py)).
3. Includes the nonce in the signed header — it cannot be stripped without
   invalidating the signature.
4. On a `badNonce` error response, extracts the fresh nonce from the
   `Replay-Nonce` response header and retries (up to `_NONCE_RETRIES = 3`
   times) without an extra round-trip.
5. Threads `current_nonce` through `AgentState` so every node picks up the
   latest nonce automatically.

**Threat addressed:** Replay attacks — an attacker capturing a signed ACME request
cannot resubmit it because the nonce is single-use and server-validated.

### JWS signature — RS256 + URL binding (RFC 8555 § 6.2 and § 6.3)

All ACME requests are signed with **RS256** (RSA-SHA256, PKCS#1 v1.5 padding).
The signed protected header always includes both the nonce **and the target URL**
(required by RFC 8555 § 6.3 — the URL field binds each JWS to a specific endpoint):

```python
# acme/jws.py — sign_request
# Both nonce and url are validated non-empty before this point
header = {
    "alg": "RS256",
    "nonce": nonce,
    "url": url,       # URL is part of the signature
    ...
}
```

`sign_request()` validates that `url` is non-empty before building the header —
an empty URL would produce a JWS bound to no endpoint, which every ACME server
would reject. This guard mirrors the nonce pre-condition check.

Including the URL in the signature binds each request to a specific ACME endpoint.
A signed `newOrder` request cannot be replayed against `revokeCert`.

### EAB (External Account Binding) — HMAC-SHA256 (RFC 8739 § 2)

DigiCert, ZeroSSL, and Sectigo require EAB per RFC 8739 § 2. The outer EAB JWS is signed with
**HS256** (HMAC-SHA256) using the EAB HMAC key provided by DigiCert
([acme/jws.py](../acme/jws.py)):

```python
mac = hmac.new(hmac_key, signing_input, hashlib.sha256).digest()
```

The EAB payload contains **only the account public JWK** — the private key is never
transmitted.

---

## 5. HTTP-01 Challenge Server

The standalone HTTP server ([acme/http_challenge.py](../acme/http_challenge.py)) is
purpose-built to be as minimal as possible:

```python
class _ChallengeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        expected = f"/.well-known/acme-challenge/{self.token}"
        if self.path == expected:
            # serve key authorization
        else:
            self.send_response(404)
            self.end_headers()
```

Security properties:

| Property | Detail |
|---|---|
| **Exact path matching** | Only responds to `/.well-known/acme-challenge/<token>`. Everything else returns 404. |
| **No directory traversal** | Path is compared by exact string equality, not prefix matching. `/../etc/passwd` cannot match. |
| **Read-only** | Only `do_GET` is implemented. No POST, PUT, DELETE or other verbs. |
| **Single token served** | One token at a time (rotated per domain for multi-SAN). |
| **No access logging** | `log_message` is overridden to a no-op — the token is never written to stdout or a log file. |
| **Temporary binding** | Server starts just before challenge submission and stops immediately after validation. Port 80 is not held open during idle periods. |

For **webroot mode**, challenge files are written to
`<WEBROOT_PATH>/.well-known/acme-challenge/<token>` and removed after validation.
Path construction uses `pathlib.Path` concatenation — no user input is passed to
a shell or used in string interpolation that could enable traversal.

---

## 6. LLM Output Validation

The planner node receives structured JSON from the LLM. Because LLMs can hallucinate
domain names, every item in the planner's output is validated against the
authoritative `managed_domains` list before the agent acts on it
([agent/nodes/planner.py](../agent/nodes/planner.py)):

```python
for key in ("urgent", "routine", "skip"):
    original = plan.get(key, [])
    validated = [d for d in original if d in managed_domains]
    if len(validated) != len(original):
        removed = set(original) - set(validated)
        logger.warning("Planner hallucinated domains — removing: %s", removed)
    plan[key] = validated
```

Additional guarantees:

- **All domains accounted for:** Any managed domain not placed in a bucket is
  automatically added to `routine` with a warning — the LLM cannot silently skip
  a domain.
- **JSON parse failure is safe:** If the LLM returns malformed JSON, the fallback
  is to renew all managed domains (fail-safe, not fail-open).
- **Scope is closed:** The agent cannot be tricked into operating on domains outside
  `MANAGED_DOMAINS`, regardless of what the LLM returns.

**Threat addressed:** Prompt injection or LLM hallucination causing the agent to
request certificates for domains it doesn't own, or to skip renewal of domains it
should renew.

---

## 7. API Key and Credential Handling

### Storage

All credentials are environment-variable based, read by Pydantic Settings from
`.env` or the process environment. They are **never hardcoded** and **never
committed** (`.env` is in `.gitignore` and `.dockerignore`).

### Startup validation

[main.py](../main.py) validates required credentials before any graph node runs:

```python
_required_keys = {"anthropic": settings.ANTHROPIC_API_KEY,
                  "openai":    settings.OPENAI_API_KEY}
if settings.LLM_PROVIDER in _required_keys and not _required_keys[settings.LLM_PROVIDER]:
    log.error("%s_API_KEY is not set ...", ...)
    sys.exit(1)
```

The process exits immediately with a clear error message rather than attempting to
proceed and failing mid-renewal.

### Docker

In the Docker deployment, `.env` is passed to the container via `env_file:` in
`docker-compose.yml` — it is **not copied into the image layer** at build time.
The Dockerfile's `test-runner` stage uses a dummy `ANTHROPIC_API_KEY=dummy-build-key`
solely to satisfy the settings singleton during the build-time unit test run; this
value is not present in the production image.

### Logging level

Structlog is configured at `INFO` level by default. `DEBUG` log statements in
individual nodes may include order URLs and domain names, but no credential or
private key material is ever passed to a logger.

---

## 8. File Permissions

Every private key written to disk — both the ACME account key and per-domain
certificate keys — is immediately `chmod`'d to **0o600** (owner read/write only):

```python
# acme/jws.py — save_account_key
os.chmod(path, 0o600)

# storage/filesystem.py — write_cert_files
os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
```

The agent process must own the key files for this to be effective. In the Docker
deployment the container runs as **UID 1001** (`acme` system user — non-root).
`/data` is `chown`'d to UID 1001 at image build time so the volume mount is
writable without a privileged entrypoint. See
[DOCKER_NONROOT.md](DOCKER_NONROOT.md) for details.

Certificates (`cert.pem`, `chain.pem`, `fullchain.pem`, `metadata.json`) are not
secret and are written without additional permission restrictions so that web servers
can read them.

---

## 9. Docker and Container Security

### Multi-stage build gates on tests

The production image is only reachable after the `test-runner` stage completes
successfully. If any unit test fails, the `production` stage is never built:

```dockerfile
# Stage 2: test-runner — runs unit tests; build fails here if tests fail
FROM base AS test-runner
COPY . .
ENV ANTHROPIC_API_KEY=dummy-build-key
RUN pytest tests/test_unit_acme.py -v

# Stage 3: production — only reachable if test-runner succeeded
FROM base AS production
COPY --from=test-runner /app/agent   ./agent
...
```

This ensures no image with failing tests can be deployed.

### Minimal production image

The production stage uses selective `COPY --from=test-runner` to include only
application source modules. Test files, documentation, `.env`, key files, and
local certificate directories are excluded — both by the `COPY` statements and
by `.dockerignore`:

```
.env        # credentials never baked in
*.key       # no private keys in image
certs/      # no local certs in image
.git        # no git history in image
```

### Persistent data outside the image

Certificates and the ACME account key live in a named Docker volume (`acme_data`)
mounted at `/data/` inside the container. They are never part of the image layer
and survive container restarts and image rebuilds without being re-embedded:

```yaml
volumes:
  - acme_data:/data
```

`ENV CERT_STORE_PATH=/data/certs` and `ENV ACCOUNT_KEY_PATH=/data/account.key`
redirect the agent's default paths into this volume.

---

## 10. Network Exposure

The container declares a **single inbound port: 80**, and only for the transient
HTTP-01 challenge window during certificate renewal (seconds per domain).

All other traffic is **outbound-only**:

| Direction | Destination | Purpose |
|---|---|---|
| Outbound | CA ACME API (Let's Encrypt, DigiCert, …) | Certificate issuance |
| Outbound | LLM provider API (Anthropic, OpenAI, …) | Planner / reporter inference |
| Inbound | Port 80 (transient) | ACME HTTP-01 challenge response |

There is no inbound management interface, no SSH server, no metrics endpoint, and
no admin API. The attack surface is intentionally minimal.

**Webroot mode removes all inbound exposure.** When `HTTP_CHALLENGE_MODE=webroot`
is set, the agent writes challenge tokens to a directory served by an existing web
server (e.g. nginx) and binds no port whatsoever. This is recommended in any
environment where port 80 is already occupied or where firewall rules make inbound
connections difficult.

---

## 11. Resilience and Retry Safety

### Exponential backoff with scheduled retry timing

Retries are handled via a two-step process (Phase 3):

1. **error_handler** (LLM) analyzes the failure and decides action (retry/skip/abort).
   If retrying, it calculates the backoff delay and schedules a retry time:
   ```python
   # error_handler.py
   retry_not_before = now + new_delay
   updates["retry_not_before"] = retry_not_before
   ```
   The delay doubles each retry: `new_delay = min(retry_delay * 2, 300)` seconds.
   `MAX_RETRIES` (default 3) provides a hard ceiling. Maximum wait is capped at 300
   seconds (5 minutes) to prevent excessive delays.

2. **retry_scheduler** node applies the backoff before looping back to retry:
   ```python
   # retry_scheduler.py — synchronous version
   wait_time = retry_not_before - now
   if wait_time > 0:
       time.sleep(wait_time)  # blocking, or async version: await asyncio.sleep
   return {"retry_not_before": None}
   ```
   This separates concerns: the LLM decides the action; the scheduler enforces timing.
   An async version (`retry_scheduler_async`) is available for future conversion to
   non-blocking execution ([agent/nodes/retry_scheduler.py](../agent/nodes/retry_scheduler.py)).

**Threat addressed:** Rate limiting protection. By enforcing exponential backoff and a
hard ceiling (300 seconds), the agent cannot hammer the CA's API even if errors
persist, protecting against rate-limit bans.

### Isolated domain failures

Each domain is processed independently. A failure in one domain's ACME flow (e.g.
network timeout during order finalization) adds that domain to `failed_renewals`
and the agent continues with the next domain. One bad domain cannot block all
others.

### Deterministic planner fallback

If the planner LLM returns malformed JSON, the agent falls back to renewing all
managed domains — the safest default. The agent never silently does nothing in
response to an LLM failure.

---

## 12. MCP Server Security Controls

The MCP server in [mcp_server.py](../mcp_server.py) exposes operational tools for
renewal, revocation, status, and test certificate generation. Security controls are
enforced at MCP entrypoints before graph execution.

### Input validation and allowlisting

All CA-related MCP inputs are validated in `_resolve_ca_inputs()`:

| Control | Enforcement | Threat addressed |
|---|---|---|
| CA input mode restriction | `ca_input_mode` must be `config` or `custom` | Invalid modes and ambiguous execution paths |
| Provider allowlist | `ca_provider` must be one of known providers | Arbitrary provider injection |
| Directory URL scheme check | `acme_directory_url` must begin with `http://` or `https://` | Non-network URI abuse (e.g., `file://`) |

Revocation reasons are validated by `_validate_reason()` and restricted to
`0, 1, 4, 5`.

These controls are covered by
[tests/test_mcp_server_security.py](../tests/test_mcp_server_security.py).

### Path traversal prevention for test certificate generation

`generate_test_cert` validates the requested domain with
`_validate_domain_for_cert_generation()`:

- rejects empty values,
- rejects path separators (`/` and `\\`),
- rejects traversal patterns (`..`) and dot-prefixed names.

This prevents directory escape attacks when writing test certificate artifacts.

### Side-effect serialization policy

Mutating tools are serialized with a process-wide async lock via
`_operation_lock(required=True)`:

- `health`
- `renew_once`
- `revoke_cert`
- `generate_test_cert`

Read-only tools explicitly do not acquire serialization (`required=False`):

- `expiring_in_30_days`
- `domain_status`

This reduces race conditions around shared settings and filesystem state while
allowing concurrent read-only requests.

Lock behavior is validated in
[tests/test_mcp_server_locking.py](../tests/test_mcp_server_locking.py).

### Failure containment

Tool entrypoints catch exceptions and return structured failure payloads (for
example, `{"status": "failed", "error": "..."}`) instead of propagating
tracebacks to MCP clients.

---

## 13. Known Constraints and Hardening Recommendations

| Area | Current state | Recommended hardening |
|---|---|---|
| **Key encryption at rest** | Keys stored as unencrypted PEM (protected by 0o600 permissions) | Use an encrypted filesystem (LUKS) or a cloud KMS (AWS KMS, GCP Cloud KMS, HashiCorp Vault) to wrap keys at rest |
| **Secrets management** | Credentials read from `.env` / environment variables | In production, inject secrets via a dedicated secrets manager (AWS Secrets Manager, Vault Agent, Kubernetes Secrets with RBAC) rather than a flat `.env` file |
| **Container user** | Runs as UID 1001 (`acme`) — non-root; `NET_BIND_SERVICE` grants port-80 binding; all other capabilities dropped | ✅ Implemented — see [DOCKER_NONROOT.md](DOCKER_NONROOT.md) |
| **Port 80 access control** | Port 80 is mapped from host; no firewall rule restricts callers | Use firewall/security-group rules to allow inbound port 80 only from Let's Encrypt / DigiCert validation IP ranges during renewal windows, or switch to webroot mode |
| **ACME CA certificate pinning** | Standard TLS chain validation; no certificate pinning | Pin the CA's ACME API certificate fingerprint for defence-in-depth against CA compromise or BGP hijack |
| **Webroot file permissions** | Challenge files inherit the process umask | Explicitly `chmod 644` challenge files after writing, or verify the webroot directory's umask is set correctly |
| **EAB credentials rotation** | EAB HMAC key is long-lived; no rotation mechanism | Rotate EAB keys on a schedule via DigiCert's management API and update the `.env` / secret store |

---

## 14. Summary Table

| Security aspect | Mechanism | Location |
|---|---|---|
| Account key never in state | Excluded from `AgentState`; only path is stored | [agent/state.py](../agent/state.py) |
| Domain key never in state | Generated in-node local scope; only hex CSR in state | [agent/nodes/csr.py](../agent/nodes/csr.py) |
| Core dump suppression | `RLIMIT_CORE=0` at process startup; fails open, no-op on Windows | [main.py](../main.py) |
| Key file permissions | `os.chmod(path, 0o600)` after every write | [acme/jws.py](../acme/jws.py), [storage/filesystem.py](../storage/filesystem.py) |
| TLS verification | Enabled by default; `ACME_INSECURE=false` | [acme/client.py](../acme/client.py), [config.py](../config.py) |
| Nonce replay protection | Fresh nonce per request; `badNonce` retry logic | [acme/client.py](../acme/client.py), [acme/jws.py](../acme/jws.py) |
| URL binding in JWS | `url` field in every signed protected header | [acme/jws.py](../acme/jws.py) |
| Challenge server minimal surface | Exact path match; 404 for all other paths; no logging | [acme/http_challenge.py](../acme/http_challenge.py) |
| Challenge token cleanup | Server stopped / token file removed after validation | [agent/nodes/challenge.py](../agent/nodes/challenge.py) |
| LLM output validation | Domains filtered against `managed_domains`; JSON fallback | [agent/nodes/planner.py](../agent/nodes/planner.py) |
| API key startup check | `sys.exit(1)` if required key is missing | [main.py](../main.py) |
| Credentials not in image | `.env` and `*.key` excluded by `.dockerignore` | [.dockerignore](../.dockerignore) |
| Tests gate the build | `test-runner` stage must pass before `production` builds | [Dockerfile](../Dockerfile) |
| Persistent data outside image | Named volume `/data`; keys never in image layer | [docker-compose.yml](../docker-compose.yml) |
| Minimal inbound network surface | Port 80 only, transiently; all else is outbound | [docker-compose.yml](../docker-compose.yml) |
| Webroot zero-inbound option | No port binding when `HTTP_CHALLENGE_MODE=webroot` | [acme/http_challenge.py](../acme/http_challenge.py) |
| Exponential backoff scheduling | error_handler calculates `retry_not_before` timestamp; caps at 300 s | [agent/nodes/error_handler.py](../agent/nodes/error_handler.py) |
| Scheduled backoff enforcement | retry_scheduler node sleeps until `retry_not_before` arrives before retry | [agent/nodes/retry_scheduler.py](../agent/nodes/retry_scheduler.py) |
| Async backoff support | retry_scheduler_async (non-blocking) for future graph async conversion | [agent/nodes/retry_scheduler.py](../agent/nodes/retry_scheduler.py) |
| Domain failure isolation | One failed domain does not block others | [agent/graph.py](../agent/graph.py) |
| MCP CA input hardening | `ca_input_mode`/`ca_provider` allowlist + `http(s)` directory URL validation | [mcp_server.py](../mcp_server.py) |
| MCP path traversal protection | Test-cert domain validation blocks separators and traversal patterns | [mcp_server.py](../mcp_server.py), [tests/test_mcp_server_security.py](../tests/test_mcp_server_security.py) |
| MCP operation serialization | Process-wide async lock for mutating tools; read-only tools not serialized | [mcp_server.py](../mcp_server.py), [tests/test_mcp_server_locking.py](../tests/test_mcp_server_locking.py) |
| MCP tool failure containment | Exceptions mapped to structured `status=failed` responses | [mcp_server.py](../mcp_server.py), [tests/test_mcp_server_security.py](../tests/test_mcp_server_security.py) |
