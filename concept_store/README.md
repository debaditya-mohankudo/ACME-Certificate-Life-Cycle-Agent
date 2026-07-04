# concept_store

Architectural knowledge base for this repo — a JSON-backed store of high-level concepts (what each module does, what invariants it must uphold, what it promises callers) that agents can consult instead of re-reading the whole codebase from scratch.

## Contents

- **`concepts.json`** — the store itself: `{"meta": {...}, "concepts": {name: {...}}}`.

  `meta` is store-level bookkeeping, separate from individual concept records:

  | Field | Meaning |
  |---|---|
  | `commit` | git SHA of HEAD at the time of the last full extraction (empty string if unknown/never recorded) |
  | `extracted_at` | ISO timestamp of the last full extraction |

  Without this, there'd be no way to tell whether a concept is stale relative to *current* HEAD — only when it was last touched in wall-clock time. To check staleness: `git log --since=<extracted_at> --oneline -- <module>` for a given concept's module; non-empty output means code changed after the concepts were last extracted.

  `concepts` is keyed by a unique kebab-case `name` slug (e.g. `"planner-llm-vs-deterministic-dispatch"`). Each entry:

  | Field | Meaning |
  |---|---|
  | `name` | Unique slug identifying the concept |
  | `module` | Source file the concept describes (e.g. `agent/nodes/planner.py`) |
  | `description` | 1–3 sentences on what this module/concept does architecturally |
  | `invariants` | Constraints that must always hold |
  | `contracts` | What this module promises its callers |
  | `confidence` | Float 0.0–1.0 — how certain the extraction was |
  | `evidence` | `"file:line"` references backing the concept |
  | `last_validated` / `created_at` | ISO timestamps |

  `ConceptStore` transparently reads the older flat `{name: {...}}` format (no `meta`/`concepts` wrapping) for backward compatibility, but always writes the new nested shape on save.

- **`store.py`** — `ConceptStore`: thin JSON read/write wrapper (`upsert`, `delete`, `get`, `list`, `modules`). No caching, no schema validation beyond what `upsert` fills in — it's a dumb key-value store, not a database.

- **`extractor.py`** — one-shot extraction: reads a fixed list of source files (`_SOURCE_FILES`), shells out once to `claude -p --safe-mode --tools none` (no `ANTHROPIC_API_KEY` needed — reuses the caller's Claude Code OAuth login), asks for a JSON array of concepts, and upserts each into the store.

## Regenerating

```bash
uv run python scripts/extract_concepts.py
```

Re-running does a **full reseed** — every concept for every file in `extractor.py`'s `_SOURCE_FILES` list gets re-extracted and upserted (existing `created_at` is preserved via `upsert`'s merge logic; everything else is overwritten), and `meta.commit`/`meta.extracted_at` are updated to the current HEAD/timestamp. There is no incremental "update just this file" mode here — if only one module changed, prefer reconciling it directly via `store.upsert()` with a hand-written diff, or use the `/update-concept-store` skill if driving this from an agent session, rather than a full reseed.

## Consuming

Other tooling (task-grooming, deploy pipelines, `/update-concept-store`) reads `concepts.json` directly and matches entries by `module` against a list of changed files — see `ConceptStore.list(module=...)` for the lookup pattern. There's no MCP tool wrapping this store in this repo; it's read via plain `json.loads` + `Path.read_text()`.
