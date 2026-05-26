"""Unified 3-layer context query — merges SQLite memory, code graph, and RAG results.

This is the single entry point Claude should use to answer questions about the codebase.
Each layer contributes a different signal:

  Layer 2 — SQLite memory  : curated facts, gotchas, architectural decisions (keyword scoring)
  Layer 3b — Code graph    : structural facts — who calls what, where is X defined
  Layer 3a — RAG           : semantic search over doc/ markdown and merged PR descriptions

Usage:
    python tools/context_query.py "how does JWS signing work"
    python tools/context_query.py "who calls sign_request" --top 3
    python tools/context_query.py "storage atomic write" --layers memory rag
    python tools/context_query.py "RenewalPlannerNode" --layers graph
    python tools/context_query.py "nonce" --inject   # injection-ready format for Claude
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "tools"))


# ── helpers ──────────────────────────────────────────────────────────────────

def _section(title: str, body: str) -> str:
    bar = "─" * 60
    return f"\n{bar}\n## {title}\n{bar}\n{body.strip()}\n"


# ── Layer 2: SQLite memory ────────────────────────────────────────────────────

def _query_memory(prompt: str, top_n: int) -> str:
    try:
        from memory_loader import format_for_injection, query_memories
    except ImportError:
        return "memory_loader not available."

    results = query_memories(prompt, top_n=top_n)
    if not results:
        return "No matching memories."
    return format_for_injection(results)


# ── Layer 3b: Code graph ──────────────────────────────────────────────────────

def _extract_symbols(prompt: str) -> list[str]:
    """Heuristic: pull CamelCase words and snake_case identifiers from prompt."""
    camel = re.findall(r"\b[A-Z][a-zA-Z0-9]{2,}\b", prompt)
    snake = re.findall(r"\b[a-z][a-z0-9]{2,}(?:_[a-z0-9]+)+\b", prompt)
    return list(dict.fromkeys(camel + snake))  # deduplicate, preserve order


def _query_graph(prompt: str, top_n: int) -> str:
    try:
        from code_graph_query import callers, find
    except ImportError:
        return "code_graph_query not available."

    symbols = _extract_symbols(prompt)
    if not symbols:
        return "No identifiers detected in prompt — try including a function or class name."

    parts = []
    seen: set[str] = set()
    for sym in symbols[:3]:  # limit to first 3 symbols to keep output focused
        found = find(sym)
        if "No symbols" not in found and found not in seen:
            parts.append(found)
            seen.add(found)
        callers_result = callers(sym)
        if "No callers" not in callers_result and callers_result not in seen:
            parts.append(callers_result)
            seen.add(callers_result)

    return "\n\n".join(parts) if parts else f"No graph entries found for symbols: {symbols}"


# ── Layer 3a: RAG ─────────────────────────────────────────────────────────────

def _query_rag(prompt: str, top_k: int) -> str:
    try:
        from rag_query import query
    except ImportError:
        return "rag_query not available. Install with: uv sync --extra team-memory"

    return query(prompt, top_k=top_k)


# ── Unified query ─────────────────────────────────────────────────────────────

LAYER_NAMES = ("memory", "graph", "rag")


def context_query(
    prompt: str,
    top_n: int = 5,
    layers: list[str] | None = None,
    inject: bool = False,
) -> str:
    active = set(layers or LAYER_NAMES)
    sections: list[str] = []

    if "memory" in active:
        result = _query_memory(prompt, top_n)
        sections.append(_section("Layer 2 — SQLite Memory (curated facts)", result))

    if "graph" in active:
        result = _query_graph(prompt, top_n)
        sections.append(_section("Layer 3b — Code Graph (structural)", result))

    if "rag" in active:
        result = _query_rag(prompt, top_n)
        sections.append(_section("Layer 3a — RAG (semantic / docs + PRs)", result))

    output = "\n".join(sections)

    if inject:
        header = (
            "## Team Context (auto-injected)\n"
            f"Query: {prompt!r}\n"
            f"Layers: {', '.join(sorted(active))}\n"
        )
        return header + output

    return output


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified 3-layer context query")
    parser.add_argument("prompt", help="Natural language question or keyword")
    parser.add_argument("--top", type=int, default=5, help="Results per layer (default: 5)")
    parser.add_argument(
        "--layers",
        nargs="+",
        choices=list(LAYER_NAMES),
        default=list(LAYER_NAMES),
        help="Which layers to query (default: all)",
    )
    parser.add_argument("--inject", action="store_true", help="Output injection-ready format")
    args = parser.parse_args()

    print(context_query(args.prompt, top_n=args.top, layers=args.layers, inject=args.inject))
