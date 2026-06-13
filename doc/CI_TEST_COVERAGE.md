# CI Test Coverage

[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](#code-coverage)
[![Unit Tests](https://img.shields.io/badge/unit_tests-509_passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](#tests-currently-in-ci-509-total)
[![Integration Tests](https://img.shields.io/badge/integration_tests-9_pebble-blue?style=for-the-badge&logo=docker&logoColor=white)](#can-we-add-pebble-tests-to-ci)
[![CI Runtime](https://img.shields.io/badge/CI_runtime-~9s-blue?style=for-the-badge&logo=githubactions&logoColor=white)](#workflow-githubworkflowstestsyml)

This document describes what the GitHub Actions workflow runs on every push and
pull request to `main`, and analyses whether Pebble integration tests can be
added.

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Security & quality hub: [WIKI_SECURITY_QUALITY.md](WIKI_SECURITY_QUALITY.md)
- Checkpoint tests: [CHECKPOINT_TESTS.md](CHECKPOINT_TESTS.md)
- Planner validation tests: [PLANNER_VALIDATION_TESTS.md](PLANNER_VALIDATION_TESTS.md)

## Retrieval keywords

`ci`, `github actions`, `pytest`, `unit tests`, `integration tests`, `pebble`, `coverage`, `workflow`, `tests.yml`, `uv`, `quality gate`, `setup-python`, `caching`
[negative keywords / not-this-doc]
async, concurrency, parallel, checkpoint, nonce, stateful, planner, LLM, MCP, revoke, configuration, storage, atomic, filesystem, docker, container, audit, performance, optimization, operator

---

## Workflow: `.github/workflows/tests.yml`

Trigger: every push and PR targeting `main`, **except when only documentation files change**.
Paths ignored (workflow skipped entirely if all changed files match):
- `**/*.md` — any Markdown file
- `doc/**` — everything under `doc/`
- `.history` — architectural intent log

Runner: `ubuntu-latest` (no container — Docker image pull eliminated).
Python: `actions/setup-python@v5` with `python-version: '3.12'`; resolved from
the GitHub runner tool cache (near-instant on warm runners).
Toolchain: `uv` via `astral-sh/setup-uv` with `enable-cache: true` — virtual
environment and package layers are cached across runs keyed on `uv.lock`.

### Checkout note

The workflow uses `actions/checkout@v4` with:

```yaml
with:
  persist-credentials: false
```

Reason: this repo's CI workflow never runs `git push`, so persisted credentials
are unnecessary. Disabling them avoids any post-run credential cleanup side
effects.

Impact:

- No meaningful performance impact.
- No change to `uv` cache behavior or test caching.
- If future workflows need authenticated `git push`, credentials must be
  provided explicitly for that step.

### Command

```bash
uv run pytest -v -n auto -m "not integration"
```

**509 tests, 3 skips, no external services required.**

Parallel execution via xdist (8 concurrent workers on typical GitHub runners).
Unit tests are isolated and mocked — safe to parallelize.
Integration tests (Pebble) excluded from CI by marker.

---

## Tests Currently in CI (509 total)

### `tests/test_unit_acme.py` — 55 tests
Core ACME RFC 8555 protocol layer. All HTTP calls mocked with the `responses`
library; no network access needed.

| Group | Tests | What is verified |
|---|---|---|
| JWS signing — Case A | `test_sign_request_jwk_header` | protected header has `jwk`, no `kid`; payload round-trips via base64url |
| JWS signing — Case B | `test_sign_request_kid_header` | protected header has `kid`, no `jwk` |
| JWS signing — Case C | `test_sign_request_post_as_get_signature_is_valid` | `payload == ""` (RFC 8555 §6.3); RS256 signature cryptographically valid |
| JWS input guards | `test_sign_request_rejects_empty_nonce` / `_whitespace_nonce` | `ValueError` on empty / whitespace nonce |
| JWS input guards | `test_sign_request_rejects_empty_url` / `_whitespace_url` | `ValueError` on empty / whitespace URL |
| RFC 7638 thumbprint | `test_jwk_thumbprint_rfc7638_canonical_*` | canonical form is `{e,kty,n}` alphabetical, no padding |
| RFC 7638 thumbprint | `test_jwk_thumbprint_matches_independent_rfc7638_computation` | independent SHA-256 digest matches `compute_jwk_thumbprint()` |
| RFC 7638 thumbprint | `test_jwk_thumbprint_differs_when_extra_fields_included` | adding `alg` field changes digest |
| Key auth | `test_compute_key_authorization` | `token.thumbprint` format |
| Account key I/O | `test_save_and_load_account_key` | file mode `0o600`; thumbprint survives round-trip |
| Crypto | `test_rsa_key_generation`, `test_private_key_to_pem` | RSA-2048, PEM headers |
| CSR | `test_create_csr_single_domain`, `_multi_san` | SAN list correct |
| Directory / nonce | `test_get_directory`, `test_get_nonce` | mocked HTTP GET |
| POST-as-GET compliance | `test_post_as_get_*`, `test_post_with_payload_vs_post_as_get` | RFC 8555 §6.2 POST-as-GET |
| Account ops | `test_create_account_*`, `test_lookup_account_*` | 200 happy path + 404 miss + 400 error |
| Order / auth | `test_create_order`, `test_poll_authorization_*` | order creation, valid vs invalid auth |
| Error handling | `test_acme_error_on_non_2xx` | `AcmeError` raised |
| Revocation | `test_revoke_certificate`, `test_revoke_certificate_invalid_reason_*` | reason code validation (0–10 allowed) |
| CA hierarchy | `test_zerossl_*`, `test_sectigo_*`, `test_digicert_*`, `test_eab_subclass_*` | class URLs, EAB inheritance |
| Factory | `test_make_client_returns_zerossl`, `_sectigo` | `make_client()` dispatch |
| EAB account | `test_eab_create_account_injects_eab`, `_omits_eab_when_credentials_empty` | EAB injection logic |
| EAB JWS guards | `test_eab_jws_rejects_*`, `_succeeds_*`, `_minimum_*` | input validation, minimum 16-byte HMAC |
| Config EAB | `test_config_rejects_partial_*`, `_accepts_*` | Pydantic validator for partial EAB config |
| validate_eab_hmac_key | `test_jws_validate_eab_hmac_key.py` | positive and negative cases for EAB HMAC key validation |
| StandaloneHttpChallenge refactor | covered by integration and lifecycle tests | stateless handler, context manager idiom |

---

### `tests/test_unit_failure_scenarios.py` — 9 tests
Protocol error paths; all HTTP mocked.

| Test | What is verified |
|---|---|
| `test_challenge_failure_invalid_status` | `invalid` challenge status raises `AcmeError` |
| `test_invalid_csr_rejected_by_server` | 400 on finalize raises `AcmeError` |
| `test_bad_nonce_retries_and_succeeds` | `badNonce` triggers retry with fresh nonce |
| `test_bad_nonce_exhausts_retries` | retry cap raises `AcmeError` |
| `test_network_timeout_on_directory_fetch` | `ConnectionError` on directory |
| `test_invalid_directory_url_connection_error` | bad URL raises `ConnectionError` |
| `test_invalid_directory_url_returns_404` | 404 directory raises `AcmeError` |
| `test_finalize_order_malformed_json_response` | malformed body raises `AcmeError` |
| `test_rate_limit_429_with_retry_after` | 429 raises `AcmeError` |

---

### `tests/test_dns_challenge.py` — 51 tests
DNS-01 challenge provider layer; all cloud SDK calls mocked.

| Group | Tests | What is verified |
|---|---|---|
| TXT value computation | 8 tests | known RFC vector, no padding, determinism, base64url, 43-char fixed length |
| Provider factory | 7 tests | Cloudflare / Route53 / Google dispatch; unknown provider error; import-error hints |
| Cloudflare provider | 6 tests | create (explicit zone, auto-discover, idempotent), delete (found, error, missing) |
| Route53 provider | 5 tests | UPSERT with quotes, explicit zone, auto-discover, DELETE action, error swallowed |
| Google Cloud DNS | 6 tests | add+create, delete+create, error swallowed, idempotent same value, replace different value, no-existing |
| Order node (dns-01) | 5 tests | challenge type selection, `auth_domains`, `dns_txt_values` populated, http-01 leaves empty, missing challenge error |
| Challenge setup | 4 tests | `create_txt_record` called per domain, propagation sleep called/skipped |
| Challenge cleanup | 3 tests | `delete_txt_record` called per domain, continues on partial failure, safe with no provider |
| Config validation | 7 tests | `dns` mode accepted, invalid mode rejected, Cloudflare token required, Google project-id required, Route53 no mandatory fields, standalone/webroot unchanged |

---

### `tests/test_planner_validation.py` — 12 tests
LLM output validation; no LLM calls made (direct function tests + mocked LLM).

| Test | What is verified |
|---|---|
| `test_invalid_json_falls_back_to_renew_all` | malformed JSON → all domains queued |
| `test_hallucinated_domain_in_{urgent,routine,skip}_stripped` | invented domain stripped from every bucket |
| `test_mixed_real_and_hallucinated_preserves_real` | real domains pass through |
| `test_lookalike_domain_stripped` | `evil.example.com` stripped when only `example.com` is managed |
| `test_missing_domain_added_to_routine` | domain absent from LLM output added to routine queue |
| `test_all_missing_domains_added_to_routine` | all domains fall back to routine if LLM omits all |
| `test_all_hallucinated_triggers_missing_domain_fallback` | all-hallucinated response → managed domains queued |
| `test_planner_node_strips_hallucinated_from_pending_renewals` | full planner node integration |
| `test_planner_node_invalid_json_queues_all_domains` | node-level fallback |
| `test_planner_node_urgent_before_routine_in_pending` | urgent domains precede routine |

---

### `tests/test_revocation.py` — 33 tests
Revocation subgraph; no ACME server required (all mocked). Comprehensive observability coverage.

| Group | Tests | What is verified |
|---|---|---|
| **Core nodes** | 8 tests | |
| Router | 3 tests | picks next domain, handles last domain, handles empty target list |
| Loop router | 2 tests | routes to revoker when targets remain, to reporter when done |
| Revoker node | 3 tests | successful revocation, missing cert file, `AcmeError` handling |
| **Reporter** | 3 tests | LLM summary on success, summary with failures, LLM call failure graceful |
| **Graph topology** | 4 tests | graph compiles; single/multi-domain flows; partial failure tracking |
| **Nonce management** | 3 tests | nonce cleared between domains, multi-domain sequence, None handling |
| **RFC 5280 reason codes** | 2 tests | all valid codes (0–5) passed to ACME; invalid code error handling |
| **State integrity** | 4 tests | message accumulation across flow, no domain duplicates, field cleanup, error log preservation |
| **Checkpointing** | 2 tests | graph compiles with checkpointing, state resumption readiness |
| **Account setup** | 1 test | account creation failure handling |
| **Edge cases** | 3 tests | very long domain names, internationalized domains (IDN), duplicate domains in targets |
| **Reporter content** | 1 test | message structure includes revocation context |
| **Error handling** | 3 tests | consecutive failures tracked, error log format validation, multi-failure accumulation |

---

### `tests/test_checkpoint.py` — 10 tests
LangGraph `MemorySaver` checkpoint mechanics; all ACME nodes mocked.

| Group | Tests | What is verified |
|---|---|---|
| Basic | 2 tests | completed run creates checkpoint; checkpoint history non-empty |
| Interrupt / resume | 3 tests | interrupt before account setup; resume completes; interrupt before challenge verifier |
| State integrity | 3 tests | config fields preserved; completed renewals in final state; messages accumulate |
| Thread isolation | 1 test | two `thread_id` values produce independent state |
| Advanced | 1 test | `update_state` injects domain before resume |

---

### `tests/test_node_base.py` — 6 tests
Node callable contract and registry architectural constraints.

| Group | Tests | What is verified |
|---|---|---|
| Callable contract | 2 tests | callable node structural compatibility and exception propagation |
| Graph integration | 1 test | graph execution invokes registry-provided callable class nodes |
| Registry shape | 1 test | all `NODE_REGISTRY` entries are classes |
| Registry negative cases | 2 tests | `get_node()` rejects function entries and non-class callable objects (e.g., `MagicMock`) |

---

### `tests/test_atomic_writes.py` — 12 tests
`storage/atomic.py` — crash-safe PEM file writes.

| Group | Tests | What is verified |
|---|---|---|
| Text writes | 5 tests | creates file, overwrites, no temp file left, creates parent dirs, cleans up temp on error |
| Bytes writes | 4 tests | creates file, overwrites, no temp file left, large file (1 MB) |
| Integration | 3 tests | PEM round-trip, multiple writes same dir, concurrent writes different files |

---

### `tests/test_ca_detection.py` — 33 tests
CA detection from X.509 issuer fields; no network calls (synthetic certs built in-process).

| Group | Tests | What is verified |
|---|---|---|
| `detect_ca_from_cert()` — known CAs | 8 tests | Let's Encrypt, Let's Encrypt staging, DigiCert, ZeroSSL, Sectigo (no AIA), Sectigo (Sectigo OCSP), Sectigo (ZeroSSL OCSP), COMODO legacy with ZeroSSL OCSP |
| `detect_ca_from_cert()` — fallback | 3 tests | unknown issuer org returns `None`; invalid/empty PEM returns `None`; cert with no O field returns `None` |
| Internal helpers | 4 tests | `_get_issuer_org` present/absent; `_get_ocsp_url` present/absent |
| `detect_ca_for_domain()` | 4 tests | metadata `ca_provider` takes precedence; falls back to cert inspection; falls back when metadata lacks `ca_provider`; unknown CA returns `None` |
| `write_cert_files()` metadata | 2 tests | `ca_provider` written to `metadata.json`; defaults to empty string when omitted |
| `_warn_if_ca_mismatch()` | 6 tests | no warning when detected is `None`; no warning on match; letsencrypt/staging treated as equivalent (both directions); warning logged on real mismatch; domain name included in warning |
| Scanner integration | 5 tests | no cert → `detected_ca_provider` is `None`; named `CA_PROVIDER` skips detection (returns `None`); `CA_PROVIDER=custom` runs detection; mismatch warning emitted only for `custom`; no warning emitted for named providers |

---

### `tests/test_cli_overrides.py` — 12 tests
CLI argument parsing and runtime settings override validation.

| Test | What is verified |
|---|---|
| `test_apply_runtime_settings_overrides_custom` | Custom CA provider + directory URL override via CLI |
| `test_apply_runtime_settings_overrides_named_provider_uses_preset` | Named provider (e.g., digicert) applies preset URL |
| `test_list_domains_expiring_within_filters_and_sorts` | `--domain-status` command filters by expiry threshold |
| `test_list_domains_expiring_within_exits_when_no_domains_configured` | Graceful exit if no domains configured |
| `test_get_domain_statuses_classifies_domains` | Domains classified into valid / expiring / missing |
| `test_get_domain_statuses_exits_when_empty_domains` | Graceful exit on empty domain list |
| `test_cli_domain_status_prints_results` | CLI formatter outputs status table |
| `test_cli_expiring_in_30_days_uses_domains_override` | CLI respects `--domains` override |
| `test_cli_applies_runtime_overrides_before_action` | Overrides applied before main action executes |
| `test_cli_rejects_unknown_ca_provider` | Unknown CA provider rejected with error |
| `test_cli_domain_status_requires_domains` | `--domain-status` requires `--domains` |
| `test_cli_requires_action_flag` | CLI rejects commands without action flag |

---

### `tests/test_docker_config.py` — 11 tests
Dockerfile and docker-compose non-root user security + capability hardening.

| Group | Tests | What is verified |
|---|---|---|
| Dockerfile non-root | 5 tests | `useradd -S` creates system user; UID 1001; chown data dir; no root in final image |
| docker-compose capabilities | 6 tests | `NET_BIND_SERVICE` added (for port 80); all others dropped; `no-new-privileges` set; port 80 still mapped; data volume mounted |

---

### `tests/test_retry_scheduler.py` — 11 tests
Retry scheduling logic; exponential backoff timing and event integration.

| Group | Tests | What is verified |
|---|---|---|
| Sync scheduler | 5 tests | no scheduled retry passes through; past retry time doesn't wait; future retry time waits; clears retry if not before time limit; long backoff (300s cap) |
| Async scheduler | 4 tests | async variants pass through, wait, don't block, respect boundaries |
| Integration | 2 tests | retry scheduler with error handler state machine; multi-domain concurrent retries |

---

### `tests/test_mcp_server_locking.py` — 2 tests
MCP tool async lock serialization policy.

| Test | What is verified |
|---|---|
| `test_mutating_tools_always_request_operation_lock` | `health`, `renew_once`, `revoke_cert`, `generate_test_cert` all set `required=True` |
| `test_read_only_tools_are_not_serialized` | `expiring_in_30_days`, `domain_status` set `required=False` for concurrent execution |

---

### `tests/test_mcp_server_security.py` — 21 tests
MCP server input validation and exception handling.

| Group | Tests | What is verified |
|---|---|---|
| Path injection prevention | 8 tests | Forward slash, backslash, `..`, single `.`, double `.`, empty domain all rejected; valid domain generates cert |
| CA input validation | 7 tests | Unknown CA provider rejected with valid choices shown; `file://`, `ftp://` URLs rejected; valid `http(s)` URLs accepted; known providers accepted; config mode ignores custom inputs |
| Exception handling | 4 tests | `health`, `renew_once`, `revoke_cert`, `generate_test_cert` return `{"status": "failed", "error": str(...)}` on exception |
| Revocation reason validation | 2 tests | RFC 5280 reasons 0, 1, 4, 5 accepted; invalid reasons rejected with valid choices shown |

---

### `tests/test_llm_factory.py` — 9 tests
LLM factory provider registry and kwargs building.

| Test | What is verified |
|---|---|
| `test_anthropic_kwargs` | Anthropic provider returns `api_key` and `max_tokens` |
| `test_openai_kwargs` | OpenAI provider returns `api_key` and `max_tokens` |
| `test_ollama_kwargs` | Ollama provider returns `base_url` and `num_predict` (not `max_tokens`) |
| `test_ollama_ignores_api_key` | Ollama provider does not include API key even if provided |
| `test_unknown_provider_raises_error` | Unknown provider raises `ValueError` with available options listed |
| `test_case_sensitive_provider_names` | Provider names are case-sensitive (must be lowercase) |
| `test_max_tokens_respected` | Different max_tokens values pass through unchanged |
| `test_api_key_preserved_exactly` | API key strings preserved without modification |
| `test_base_url_preserved_exactly` | Base URL strings preserved without modification |

---

### `tests/test_router.py` — 25 tests
Pure routing functions in `agent/nodes/router.py`; no mocking needed.

| Group | Tests | What is verified |
|---|---|---|
| `pick_next_domain` / `PickNextDomainNode` | 5 tests | Pops first domain, resets per-domain state (order/nonce/retry), empty → `{}`, callable == run |
| `domain_loop_router` | 3 tests | Pending → "next_domain"; empty/missing → "all_done" |
| `challenge_router` | 4 tests | `invalid` status → "challenge_failed"; any other status/absent order → "challenge_ok" |
| `renewal_router` | 3 tests | Non-empty pending → "renewals_needed"; empty/missing → "no_renewals" |
| `error_action_router` | 10 tests | retry under limit, retry at/over limit → skip, abort, skip, unknown action, bad JSON, empty string, missing key, default max_retries |

---

### `tests/test_storage_manager.py` — 10 tests
`_split_pem_chain` (pure function) and `StorageManagerNode` guard + success paths.

| Group | Tests | What is verified |
|---|---|---|
| `_split_pem_chain` | 5 tests | Single cert, two certs, three certs (leaf/chain split), no PEM blocks, empty string |
| Guard paths | 3 tests | Missing `full_chain_pem` → failed_renewals; `None` order → failed_renewals; missing `privkey.pem` → failed_renewals |
| Success / error | 2 tests | Successful write adds to completed_renewals + cert_metadata; `OSError` from `write_cert_files` adds to failed_renewals |

---

### `tests/test_finalizer_guards.py` — 7 tests
Guard paths and error handling for `OrderFinalizerNode` and `CertDownloaderNode`.

| Group | Tests | What is verified |
|---|---|---|
| `OrderFinalizerNode` | 3 tests | Missing CSR → error_log, no ACME call made; `AcmeError` on finalize → order status "invalid" |
| `CertDownloaderNode` | 4 tests | Missing cert_url → error_log, no ACME call made; `AcmeError` → error_log; success → `full_chain_pem` in order |

---

### `tests/test_error_handler.py` — 8 tests
`ErrorHandlerNode` action paths with mocked LLM (no API key needed).

| Test | What is verified |
|---|---|
| `test_error_handler_retry_increments_retry_count` | retry action increments retry_count, sets retry_not_before |
| `test_error_handler_retry_uses_doubled_delay_when_suggested_zero` | Fallback delay = min(delay×2, 300) when suggested_delay is 0 |
| `test_error_handler_skip_adds_domain_to_failed_renewals` | skip action adds current domain to failed_renewals |
| `test_error_handler_skip_preserves_existing_failed_renewals` | Existing failed_renewals not overwritten on skip |
| `test_error_handler_abort_clears_pending_renewals` | abort drains pending_renewals into failed_renewals |
| `test_error_handler_malformed_json_falls_back_to_skip` | Non-JSON LLM response defaults to skip |
| `test_error_handler_stores_raw_llm_response_in_error_analysis` | Raw LLM content stored in error_analysis |
| `test_error_handler_appends_messages` | System + Human + AI messages accumulated in state |

---

### `tests/test_logger_singleton.py` — 8 tests
Decorator pattern implementation for logger with run_id tracking; all tests run without external dependencies.

| Group | Tests | What is verified |
|---|---|---|
| Singleton behavior | 2 tests | LoggerWithRunID singleton identity, underlying logger shared across instances |
| RunIDFilter | 1 test | RunIDFilter adds run_id attribute to LogRecord objects |
| LoggerDecorator | 3 tests | Wraps base logger, returns correct run_id, delegates all logging methods (info/warning/error/critical) |
| Integration | 2 tests | LoggerWithRunID delegates to LoggerDecorator, run_id appears in log output captured by caplog |

---

### `tests/test_config_llm_disabled.py` — 20 tests
Configuration validation for `LLM_DISABLED` feature flag; tests config validator with multiple input formats.

| Group | Tests | What is verified |
|---|---|---|
| Defaults | 1 test | `LLM_DISABLED` defaults to `False` |
| Boolean handling | 4 tests | Accepts `true`, `false`, case-insensitive environment variables |
| String aliases | 2 tests | Accepts `yes`/`no`, `on`/`off` (case-insensitive) |
| Integer values | 3 tests | Accepts `0`, `1`, with/without whitespace |
| Validation | 2 tests | Rejects invalid strings (`maybe`); error messages clear |
| File loading | 1 test | Can be set via `.env` file |
| Compatibility | 4 tests | Works with any CA provider (preset or custom); works with challenge modes (standalone, webroot) |
| Singleton mutation | 1 test | Config singleton can be mutated in tests with fixture restoration |
| Integration | 2 tests | Works alongside other LLM settings without conflict; singleton mutation preserved |

---

### `tests/test_planner_deterministic.py` — 15 tests
Deterministic renewal planner logic (when `LLM_DISABLED=true`); no LLM calls made.

| Group | Tests | What is verified |
|---|---|---|
| No-cert domains | 2 tests | Domains with no certificate always renewed; prioritized before expiring domains |
| Expiring domains | 3 tests | Domains within threshold renewed; domains beyond threshold skipped; boundary conditions |
| Sorting | 3 tests | Expiring domains sorted by `days_until_expiry` (ascending); ties broken by expiry date |
| Mixed scenarios | 3 tests | No-cert + expiring mixed correctly; empty records; all fresh certs skipped |
| Helper function | 1 test | `_renewal_planner_deterministic()` pure function works in isolation |
| Output | 3 tests | `renewal_plan` contains readable text; no LLM messages; summary documents decision |

---

### `tests/test_error_handler_deterministic.py` — 23 tests
Deterministic error handler logic (when `LLM_DISABLED=true`); exponential backoff, no LLM calls.

| Group | Tests | What is verified |
|---|---|---|
| Retry action | 4 tests | Retries while `retry_count < max_retries`; increments count; sets backoff timing |
| Exponential backoff | 5 tests | Formula: `delay = base * 2^(retry_count+1)` for each retry count; respects different base delays |
| Delay cap | 2 tests | Delay capped at 300 seconds regardless of exponent |
| Skip action | 3 tests | Skip when max retries exceeded; adds to failed_renewals; no retry fields set |
| No abort | 1 test | Deterministic mode never aborts (only retry/skip) |
| Error analysis | 4 tests | Plain text format (not JSON); includes domain, error, retry count, action |
| Output | 4 tests | No LLM messages in deterministic mode; helper function isolated |

---

### `tests/test_reporter_deterministic.py` — 20 tests
Deterministic summary reporter logic (when `LLM_DISABLED=true`); plain-text formatting, no LLM calls.

| Group | Tests | What is verified |
|---|---|---|
| Completed domains | 2 tests | All completed renewals reported; empty case shows `(none)` |
| Failed domains | 2 tests | All failed domains reported; empty case handled |
| Skipped domains | 3 tests | Correctly identifies domains not in completed or failed; handles boundary cases |
| Status field | 4 tests | SUCCESS (no failures), PARTIAL (mixed), FAILED (all failures), empty run |
| Error log | 2 tests | Error count reported; empty log handled |
| Formatting | 5 tests | Plain text (not JSON); box borders (═══); title included; colon-separated fields |
| Node integration | 2 tests | Reporter node returns empty messages; handles complex state |
| Edge cases | 2 tests | Duplicate domains in lists; empty error log |
| Helper function | 1 test | `_summary_reporter_deterministic()` pure function isolated |

---

## Code Coverage

### 100% Coverage
- `agent/nodes/router.py` — 100% ↑ (was 60%)
- `agent/nodes/planner.py` — 100%
- `agent/nodes/registry.py` — 100%
- `agent/nodes/revocation_router.py` — 100%
- `agent/state.py` — 100%
- `agent/graph.py` — 100%
- `agent/revocation_graph.py` — 100%
- `acme/crypto.py` — 100%

### High Coverage (95%+)
- `acme/http_challenge.py` — 98%
- `acme/jws.py` — 97%
- `acme/ca_detection.py` — 96%
- `config.py` — 97%
- `storage/filesystem.py` — 96%
- `agent/nodes/account.py` — 97%
- `agent/nodes/order.py` — 96%
- `agent/nodes/retry_scheduler.py` — 97%
- `agent/nodes/error_handler.py` — 99% ↑ (was 26%)
- `agent/nodes/storage.py` — 96% ↑ (was 23%)
- `agent/nodes/csr.py` — 95%
- `logger.py` — 98% ↑ (new: decorator pattern refactor with 6 new unit tests)
- `scripts/generate_test_cert.py` — 92%

### Medium Coverage (70–95%)
- `acme/client.py` — 78%
- `acme/dns_challenge.py` — 93%
- `llm/factory.py` — 80%
- `storage/atomic.py` — 76%
- `agent/nodes/reporter.py` — 89% ↑ (was 86%)
- `agent/nodes/scanner.py` — 93%
- `agent/nodes/finalizer.py` — 88% ↑ (was 22%)
- `agent/nodes/revoker.py` — 94%

### Low Coverage (< 70%, by design)
- `main.py` — 60% (CLI argument parsing mostly tested indirectly)
- `mcp_server.py` — 59% (MCP tools use partial coverage in unit tests; E2E coverage via integration)
- `agent/nodes/challenge.py` — 54% (standalone/webroot verifier loop covered by integration tests)
- `tests/conftest.py` — 39% (test fixtures and configuration helpers; not source code)
- `tests/test_dns_provider_registry.py` — 61% (optional SDK imports have conditional coverage)

---

| File | Count | Reason excluded |
|---|---|---|
| `tests/test_integration_pebble.py` | 4 | Requires Pebble ACME stub server |
| `tests/test_lifecycle_pebble.py` | 2 | Requires Pebble ACME stub server |
| `tests/test_revocation_pebble.py` | 3 | Requires Pebble ACME stub server |
**Pebble total: 9 integration tests.**

**Total test count: 518 tests (509 unit tests in CI + 9 Pebble integration tests excluded; 3 skipped)**

**Overall line coverage: 92%** (6,338 / 6,884 statements)

---

## Can We Add Pebble Tests to CI?

### What Pebble tests do

The 9 Pebble tests exercise the **complete agent end-to-end** against
[`ghcr.io/letsencrypt/pebble`](https://github.com/letsencrypt/pebble), a
lightweight ACME test server. With `PEBBLE_VA_ALWAYS_VALID=1` set, it
auto-approves all challenges — no real DNS or port-80 access needed.

Tests covered:

| Test | Scenario |
|---|---|
| `test_full_renewal_flow` | HTTP-01 happy path: all 11 agent nodes execute |
| `test_second_run_reuses_account` | Account key persisted; second run skips `newAccount` |
| `test_no_renewal_needed` | Scanner detects valid cert; planner skips renewal |
| `test_full_renewal_flow_dns01` | DNS-01 happy path with mocked Cloudflare provider |
| `test_certificate_lifecycle` | Issue → read cert → confirm SAN list |
| `test_revoke_original_cert_after_renewal` | Renew then revoke old cert |
| `test_revocation_graph_basic_against_pebble` | Revocation subgraph happy path |
| `test_revocation_reason_codes_against_pebble` | Reason codes 0, 1, 4, 5 accepted |
| `test_revocation_nonexistent_cert_against_pebble` | Revoke non-existent cert: graceful failure |

### Feasibility

**Yes — adding Pebble tests to CI is feasible.** GitHub Actions supports
Docker Compose service containers, which is exactly what Pebble requires.

### What needs to change

**1. Add a `services:` block to the workflow**

```yaml
services:
  pebble:
    image: ghcr.io/letsencrypt/pebble:latest
    ports:
      - 14000:14000
      - 15000:15000
    env:
      PEBBLE_VA_NOSLEEP: "1"
      PEBBLE_VA_ALWAYS_VALID: "1"
```

**2. Wait for Pebble to be ready**

Add a health-check step before running Pebble tests:

```yaml
- name: Wait for Pebble
  run: |
    for i in $(seq 1 15); do
      curl -sk https://localhost:14000/dir && break
      sleep 1
    done
```

**3. Run Pebble tests as a separate job (or separate step)**

Keep the existing `--ignore` flags for the unit-test step unchanged.
Add a second step (or second job) that includes the Pebble tests:

```yaml
- name: Run Pebble integration tests
  run: |
    uv run pytest tests/test_integration_pebble.py \
                  tests/test_lifecycle_pebble.py \
                  tests/test_revocation_pebble.py -v
  env:
    CA_PROVIDER: custom
    ACME_DIRECTORY_URL: https://localhost:14000/dir
    ACME_INSECURE: "true"
    MANAGED_DOMAINS: acme-test.localhost
    HTTP_CHALLENGE_MODE: webroot
    WEBROOT_PATH: /tmp/pebble-webroot
    CERT_STORE_PATH: /tmp/pebble-certs
    ACCOUNT_KEY_PATH: /tmp/pebble-account.key
    ANTHROPIC_API_KEY: dummy-key-for-testing
    MAX_RETRIES: "2"
```

**4. `ACME_INSECURE` on the runner**

Pebble uses a self-signed certificate. The `ACME_INSECURE=true` env var tells
`AcmeClient` to use `verify=False` on requests. This is already supported and
safe in a CI-only context.

### Residual risk / caveats

| Item | Detail |
|---|---|
| Pebble image availability | `ghcr.io/letsencrypt/pebble:latest` is public; no auth needed |
| TLS self-signed cert | Handled by `ACME_INSECURE=true`; not a concern in CI |
| `test_full_renewal_flow_dns01` | Uses mocked Cloudflare SDK — no real DNS; works without changes |
| Port conflicts | Pebble binds 14000 + 15000; standard GitHub runners have no conflicts |
| `requires_pebble` decorator | Automatically skips if port 14000 unreachable; safe to leave in place |
| Flakiness | Pebble with `PEBBLE_VA_ALWAYS_VALID=1` is deterministic; historically stable in CI |
| Docker networking for Pebble | GitHub `services:` containers require the job to run directly on the runner host (not inside a container job) for networking to resolve correctly. Both jobs use `ubuntu-latest` + `actions/setup-python`, so no container conflicts. |

### Recommended implementation

Add the Pebble block as a **second job** (`pebble-integration`) in the same
workflow file, with `needs: [test]` so it only runs when the unit tests pass.
This keeps the failure signal clean: unit-test failures surface immediately
without waiting for Pebble to start.

```yaml
pebble-integration:
  needs: [test]
  runs-on: ubuntu-latest
  # No container: block here — service containers (Pebble) require the job to
  # run directly on the runner host so Docker networking resolves correctly.

  services:
    pebble:
      image: ghcr.io/letsencrypt/pebble:latest
      ports:
        - 14000:14000
        - 15000:15000
      env:
        PEBBLE_VA_NOSLEEP: "1"
        PEBBLE_VA_ALWAYS_VALID: "1"

  steps:
    - uses: actions/checkout@v4

    - uses: actions/setup-python@v5
      with:
        python-version: '3.12'

    - name: Install uv
      uses: astral-sh/setup-uv@v5
      with:
        enable-cache: true

    - name: Install dependencies
      run: uv sync

    - name: Wait for Pebble
      run: |
        for i in $(seq 1 15); do
          curl -sk https://localhost:14000/dir && echo && break
          sleep 1
        done

    - name: Run Pebble integration tests
      env:
        CA_PROVIDER: custom
        ACME_DIRECTORY_URL: https://localhost:14000/dir
        ACME_INSECURE: "true"
        MANAGED_DOMAINS: acme-test.localhost
        HTTP_CHALLENGE_MODE: webroot
        WEBROOT_PATH: /tmp/pebble-webroot
        CERT_STORE_PATH: /tmp/pebble-certs
        ACCOUNT_KEY_PATH: /tmp/pebble-account.key
        ANTHROPIC_API_KEY: dummy-key-for-testing
        MAX_RETRIES: "2"
      run: |
        uv run pytest tests/test_integration_pebble.py \
                      tests/test_lifecycle_pebble.py \
                      tests/test_revocation_pebble.py -v
```

This adds **9 real end-to-end tests** to CI with no changes to the existing
unit-test job.

---

## Metadata

- **Owner**: QA / CI team
- **Status**: active (509 unit tests with xdist parallelization as of 2026-06-13)
- **Coverage**: 92% line coverage (6,338 / 6,884 statements); +4 new test files at 100%; router 60%→100%, storage 23%→96%, finalizer 22%→88%, error_handler 26%→99%
- **Last reviewed**: 2026-06-13
- **Last change**: Removed LLM entirely — deleted llm/factory.py and 4 LLM-only test files; 509 unit tests passing (527→509 after removing LLM-specific tests), 0 regressions
- **Next review due**: 2026-04-03 (monthly, or on significant test changes)
