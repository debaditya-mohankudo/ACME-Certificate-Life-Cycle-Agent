# ACME Certificate Lifecycle Agent

An intelligent, agentic TLS certificate manager built on **LangGraph** and **Claude**. It monitors certificate expiry across multiple domains, uses an LLM to plan and prioritize renewals, executes the full **ACME RFC 8555** flow against **any RFC 8555-compliant CA** (DigiCert, Let's Encrypt, or custom), and stores issued certificates as PEM files on the local filesystem — all on a configurable daily schedule.

**Deterministic mode** (`LLM_DISABLED=true`): No LLM API calls; fully auditable renewal logic for air-gapped installations and cost optimization.

Designed for the coming **47-day TLS mandate (2029)**, where automated renewal is not optional.

---

## Quality & Testing

[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](doc/CI_TEST_COVERAGE.md)
[![Unit Tests](https://img.shields.io/badge/unit_tests-566_passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](doc/CI_TEST_COVERAGE.md)
[![Integration Tests](https://img.shields.io/badge/integration_tests-9_pebble-blue?style=for-the-badge&logo=docker&logoColor=white)](doc/CI_TEST_COVERAGE.md)
[![CI Runtime](https://img.shields.io/badge/CI_runtime-~9s-blue?style=for-the-badge&logo=githubactions&logoColor=white)](doc/CI_TEST_COVERAGE.md)

| Metric | Value |
|---|---|
| Line coverage | **92%** — 6,338 / 6,884 statements *(not recomputed this pass — see [CI_TEST_COVERAGE.md](doc/CI_TEST_COVERAGE.md))* |
| Unit tests (CI) | 566 · parallel via `xdist` · ~9 s |
| Integration tests | 9 against Pebble ACME mock server |
| Total | 575 tests |
| Modules at 100% | `router` · `planner` · `registry` · `state` · `graph` · `crypto` · `prompts` · `revocation_graph` |

Coverage lifts from targeted tests: `router` 60%→**100%** · `storage` 23%→**96%** · `error_handler` 26%→**98%** · `finalizer` 22%→**88%**

See [CI_TEST_COVERAGE.md](doc/CI_TEST_COVERAGE.md) for the full per-file breakdown.

## Documentation

| Topic | Link |
|---|---|
| Docs wiki home | [WIKI_HOME.md](doc/WIKI_HOME.md) |
| How it works | [HOW_IT_WORKS.md](doc/HOW_IT_WORKS.md) |
| Project structure | [PROJECT_STRUCTURE.md](doc/PROJECT_STRUCTURE.md) |
| Setup (includes prerequisites) | [SETUP.md](doc/SETUP.md) |
| Running with Docker | [DOCKER.md](doc/DOCKER.md) |
| Usage | [USAGE.md](doc/USAGE.md) |
| MCP server usage | [MCP_SERVER.md](doc/MCP_SERVER.md) |
| Pebble testing server | [PEBBLE_TESTING_SERVER.md](doc/PEBBLE_TESTING_SERVER.md) |
| SPIFFE SVID extension (design + SPIRE test harness) | [DESIGN_SPIFFE_SVID_EXTENSION.md](doc/DESIGN_SPIFFE_SVID_EXTENSION.md) · [SPIRE_TESTING_SERVER.md](doc/SPIRE_TESTING_SERVER.md) |
| Configuration reference | [CONFIGURATION.md](doc/CONFIGURATION.md) |
| Certificate revocation | [REVOCATION_IMPLEMENTATION.md](doc/REVOCATION_IMPLEMENTATION.md) |
| Certificate storage layout | [CERTIFICATE_STORAGE.md](doc/CERTIFICATE_STORAGE.md) |
| HTTP-01 challenge modes | [HTTP_CHALLENGE_MODES.md](doc/HTTP_CHALLENGE_MODES.md) |
| HTTP-01 validation explained | [HTTP_01_VALIDATION_EXPLAINED.md](doc/HTTP_01_VALIDATION_EXPLAINED.md) |
| LLM nodes and provider support | [LLM_NODES.md](doc/LLM_NODES.md) |
| Let's Encrypt | [LETS_ENCRYPT.md](doc/LETS_ENCRYPT.md) |
| Observability | [OBSERVABILITY.md](doc/OBSERVABILITY.md) |
| Security considerations | [SECURITY.md](doc/SECURITY.md) |
| Dependencies | [DEPENDENCIES.md](doc/DEPENDENCIES.md) |

## Quick CLI examples

```bash
python main.py --once
python main.py --schedule
python main.py --expiring-in-30-days
python main.py --domain-status my.local api.example.com
python main.py --generate-test-cert example.com --days 90
python main.py --revoke-cert example.com --reason 4
# Deterministic mode (no LLM API calls)
LLM_DISABLED=true python main.py --once
python mcp_server.py
```


## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
