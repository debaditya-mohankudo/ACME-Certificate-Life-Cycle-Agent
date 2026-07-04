"""Seed concept_store/concepts.json from a one-shot Claude analysis of the codebase.

Usage:
    uv run python scripts/extract_concepts.py
"""
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from concept_store.store import ConceptStore
from concept_store.extractor import extract

REPO_ROOT = Path(__file__).resolve().parents[1]
STORE_PATH = REPO_ROOT / "concept_store" / "concepts.json"


def _current_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], text=True,
        ).strip()
    except Exception:
        return ""


def main() -> None:
    store = ConceptStore(STORE_PATH)
    print(f"Extracting concepts → {STORE_PATH}")
    concepts = extract(REPO_ROOT, store)
    store.set_meta(commit=_current_commit(), extracted_at=datetime.now(timezone.utc).isoformat())
    print(f"Done — {len(concepts)} concepts written to {STORE_PATH}")


if __name__ == "__main__":
    main()
