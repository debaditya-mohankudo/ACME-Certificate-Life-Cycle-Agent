---
name: acme-team-memory-poc
description: Three-layer team memory POC — SQLite memory, code graph, RAG — location and usage
metadata:
  type: project
  domain: acme
  priority: 10
  tags: team-memory, rag, code-graph, sqlite, tools, poc
---

Team memory POC lives on branch `feat/team-memory-poc`. Three layers implemented under `tools/`:

**Layer 2 — SQLite memory** (`tools/memory_sync.py`, `tools/memory_loader.py`):
- Seed files: `memory/*.md` (frontmatter: name, type, domain, priority, tags)
- Sync: `uv run python tools/memory_sync.py` → writes to `team_memory.sqlite`
- Query: `uv run python tools/memory_loader.py "your prompt" --top 5`

**Layer 3b — Code graph** (`tools/graph_extractor.py`, `tools/code_graph_query.py`):
- Extracts symbols/calls/imports from all `.py` files using stdlib `ast` (zero extra deps)
- Build: `uv run python tools/graph_extractor.py` → writes `code_graph.sqlite`
- Query: `uv run python tools/code_graph_query.py callers sign_request`
- GitHub Action: `.github/workflows/code-graph.yml` — triggers on every PR merge

**Layer 3a — RAG** (`tools/rag_indexer.py`, `tools/rag_query.py`):
- Indexes merged PR descriptions + `doc/` markdown via `sentence-transformers` + ChromaDB
- Install: `uv sync --extra team-memory`
- Build: `uv run python tools/rag_indexer.py` → writes `rag_index/` (5.3 MB, 186 chunks)
- Query: `uv run python tools/rag_query.py "how does JWS signing work" --top 3`
- GitHub Action: `.github/workflows/rag-index.yml` — nightly cron 01:00 UTC

**Note:** `rag_index/` is tracked on the POC branch only — restore `.gitignore` exclusion before merging to main.
