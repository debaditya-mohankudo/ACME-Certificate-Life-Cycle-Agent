"""One-shot architectural concept extraction from the ACME Certificate Lifecycle Agent codebase.

Shells out to `claude -p` (reuses the caller's existing Claude Code OAuth
login) instead of calling the Anthropic SDK directly — no ANTHROPIC_API_KEY
required. Same adapter pattern as SeniorDevAgent's extraction/llm.py
ClaudeCLILLM: --safe-mode (skip CLAUDE.md/hooks/plugins for lower token
overhead), --tools none (plain completion, not agentic).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from concept_store.store import ConceptStore

_MODEL = os.environ.get("LLM_MODEL", "sonnet")

_SOURCE_FILES = [
    "config.py",
    "main.py",
    "mcp_server.py",
    "logger.py",
    "agent/graph.py",
    "agent/revocation_graph.py",
    "agent/state.py",
    "agent/prompts.py",
    "llm/factory.py",
    "agent/nodes/base.py",
    "agent/nodes/registry.py",
    "agent/nodes/router.py",
    "agent/nodes/scanner.py",
    "agent/nodes/planner.py",
    "agent/nodes/account.py",
    "agent/nodes/order.py",
    "agent/nodes/challenge.py",
    "agent/nodes/csr.py",
    "agent/nodes/finalizer.py",
    "agent/nodes/storage.py",
    "agent/nodes/error_handler.py",
    "agent/nodes/retry_scheduler.py",
    "agent/nodes/reporter.py",
    "agent/nodes/revocation_router.py",
    "agent/nodes/revoker.py",
]

_SYSTEM = (
    "You are an expert software architect performing a one-shot architectural analysis. "
    "Respond with a JSON array only. No prose, no markdown fences."
)

_INSTRUCTIONS = """
Analyze the codebase above and extract architectural concepts.

For each logical unit (file or coherent subsystem), return one JSON object with:
  - name: unique kebab-case slug (e.g. "planner-llm-vs-deterministic-dispatch")
  - module: source file path (e.g. "agent/nodes/planner.py")
  - description: what this module/concept does architecturally (1-3 sentences)
  - invariants: list of strings — constraints that must always hold
  - contracts: list of strings — what this module promises its callers
  - confidence: float 0.0–1.0 — how certain you are about this concept
  - evidence: list of "file:line" strings referencing where you saw this

Return a single top-level JSON array of these objects. Nothing else.
"""


def _read_sources(repo_root: Path) -> str:
    parts = []
    for rel in _SOURCE_FILES:
        path = repo_root / rel
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        parts.append(f"### {rel}\n{content}")
    return "\n\n".join(parts)


def _call_claude_cli(system: str, user: str, model: str, timeout: int = 600) -> str:
    claude_path = os.environ.get("CLAUDE_CLI_PATH") or shutil.which("claude")
    if not claude_path:
        raise RuntimeError("`claude` binary not found on PATH (set CLAUDE_CLI_PATH)")

    cmd = [
        claude_path, "-p",
        "--safe-mode",
        "--output-format", "json",
        "--tools", "none",
        "--model", model,
        "--append-system-prompt", system,
    ]

    proc = subprocess.run(
        cmd, input=user, capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude CLI exited {proc.returncode}: {proc.stderr[:500]}")

    data = json.loads(proc.stdout)
    if data.get("is_error"):
        raise RuntimeError(f"claude CLI reported an error: {data.get('result')}")
    return data["result"]


def extract(repo_root: Path, store: ConceptStore, model: str | None = None) -> list[dict]:
    """Read all source files, call Claude once, parse concepts, upsert into store."""
    source = _read_sources(repo_root)
    user_message = f"{source}\n\n{_INSTRUCTIONS}"

    raw = _call_claude_cli(_SYSTEM, user_message, model or _MODEL).strip()

    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]
        raw = raw.strip()

    try:
        concepts = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Claude returned unparseable JSON: {raw[:500]}") from exc

    if not isinstance(concepts, list):
        raise ValueError(f"Expected JSON array, got {type(concepts).__name__}: {raw[:200]}")

    for concept in concepts:
        store.upsert(concept)

    return concepts
