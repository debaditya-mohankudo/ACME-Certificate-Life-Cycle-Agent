"""Query team_memory.sqlite — score memories against a prompt, return top-N.

Part of the three-layer team memory POC. See memory/acme_team_memory_poc.md for
full setup, layer overview, and how to add new memories.

Usage:
    python tools/memory_loader.py "how does JWS signing work"
    python tools/memory_loader.py "storage" --top 3
"""
import argparse
import re
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "team_memory.sqlite"


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def query_memories(prompt: str, top_n: int = 5) -> list[dict]:
    """Score all memories against prompt via keyword overlap, return top-N."""
    if not DB_PATH.exists():
        return []

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT name, type, domain, priority, tags, body FROM memories ORDER BY priority"
    ).fetchall()
    con.close()

    prompt_tokens = _tokenize(prompt)
    scored = []
    for row in rows:
        mem = dict(row)
        mem_tokens = _tokenize(f"{mem['name']} {mem['tags']} {mem['body']}")
        overlap = len(prompt_tokens & mem_tokens)
        # priority 1 = always inject regardless of score
        score = overlap + (100 if mem["priority"] == 1 else 0)
        if score > 0:
            scored.append((score, mem))

    scored.sort(key=lambda x: -x[0])
    return [m for _, m in scored[:top_n]]


def format_for_injection(memories: list[dict]) -> str:
    if not memories:
        return ""
    parts = ["## Team Memory Context\n"]
    for m in memories:
        parts.append(f"### [{m['type']}] {m['name']}\n{m['body']}\n")
    return "\n".join(parts)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("prompt", help="Prompt to score memories against")
    parser.add_argument("--top", type=int, default=5)
    parser.add_argument("--inject", action="store_true", help="Print injection-ready format")
    args = parser.parse_args()

    results = query_memories(args.prompt, top_n=args.top)
    if args.inject:
        print(format_for_injection(results))
    else:
        for m in results:
            print(f"[{m['priority']}] {m['name']} ({m['type']}/{m['domain']})")
            print(f"  {m['body'][:120].strip()}...")
            print()
