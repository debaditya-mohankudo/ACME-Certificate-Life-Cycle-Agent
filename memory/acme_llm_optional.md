---
name: acme-llm-optional
description: LLM is fully optional — set LLM_DISABLED=true for zero-dependency deterministic mode
metadata:
  type: project
  domain: acme
  priority: 10
  tags: llm, deterministic, llm-disabled, planner, reporter, error-handler
---

Set `LLM_DISABLED=true` in `.env` to run the agent without any LLM provider or API key.

**Affected nodes:** `planner`, `reporter`, `error_handler` — each has a `_run_deterministic()` fallback.
- Planner: classifies domains by `days_until_expiry` vs `RENEWAL_THRESHOLD_DAYS` (urgent < 7d, routine ≤ threshold, skip otherwise).
- Reporter: emits a structured plain-text summary without LLM prose.
- Error handler: applies rule-based retry/abort logic without LLM classification.

**Why:** Enables CI, Docker, and air-gapped deployments where no LLM key is available. Also makes unit tests faster — no `mock_llm_nodes` fixture needed.

**How to apply:** Never assume an LLM is present. `config.settings.LLM_DISABLED` is the gate — check it before any `make_llm()` call. Install LLM extras with `uv sync --extra llm-anthropic` (or openai/ollama). Without an extra, LLM calls will ImportError — `LLM_DISABLED=true` avoids this entirely.
