# ACME Certificate Lifecycle Agent

An intelligent, agentic TLS certificate manager built on **LangGraph** and **Claude**. It monitors certificate expiry across multiple domains, uses an LLM to plan and prioritize renewals, executes the full **ACME RFC 8555** flow against **any RFC 8555-compliant CA** (DigiCert, Let's Encrypt, or custom), and stores issued certificates as PEM files on the local filesystem — all on a configurable daily schedule.

The lifecycle logic (monitor → plan → issue → renew → revoke) is protocol-agnostic — ACME is one issuance backend. Set `CERT_ISSUANCE_MODE=spiffe` and the same agent issues **SPIFFE SVIDs** (workload identity certs) via a local **SPIRE** deployment instead — attestation-based auth, no HTTP-01/DNS-01 challenge, no public CA — for agentic and service-mesh environments. Strictly either/or per running instance; see [DESIGN_SPIFFE_SVID_EXTENSION.md](doc/DESIGN_SPIFFE_SVID_EXTENSION.md).

**Deterministic mode** (`LLM_DISABLED=true`): No LLM API calls; fully auditable renewal logic for air-gapped installations and cost optimization.

---

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

Non-technical users running this repo in Claude Code can instead say "enroll a certificate for my domain" to invoke the guided `enroll-cert` skill (`.claude/skills/enroll-cert/`), which collects the needed inputs in plain English and diagnoses challenge failures (DNS/HTTP checks) automatically.

## Terminal UI

```bash
uv sync --extra tui
python main.py --tui
```

A live dashboard over the same CLI: a Home screen with the active config, a
Domain Status screen (expiry countdown per managed domain), and Run/Revoke
screens that launch `main.py --once`/`--revoke-cert` as a subprocess and
stream its output live, with automatic plain-English diagnosis (DNS/HTTP
checks, same logic as the `enroll-cert` skill) if a run fails.

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
