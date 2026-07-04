"""ConceptStore — JSON-backed store for architectural concepts extracted from this repo."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_DEFAULT_FILENAME = "concepts.json"


class ConceptStore:
    """Stores architectural concepts as a JSON file keyed by concept name.

    Each concept:
        name        — unique slug (e.g. "planner-llm-vs-deterministic-dispatch")
        module      — source file (e.g. "agent/nodes/planner.py")
        description — what this module/concept does architecturally
        invariants  — list[str] of constraints that must always hold
        contracts   — list[str] of promises to callers
        confidence  — float 0.0–1.0
        evidence    — list[str] of "file:line" references
        last_validated — ISO timestamp
        created_at     — ISO timestamp

    On-disk shape is {"meta": {...}, "concepts": {name: {...}}}. `meta` holds
    store-level bookkeeping (e.g. the git commit the concepts were last
    extracted against) separate from the concept records themselves —
    without this, there's no way to tell whether a concept is stale relative
    to current HEAD, only when it was last touched in wall-clock time.

    Transparently reads the older flat {name: {...}} format (no wrapping
    "meta"/"concepts" keys) for backward compatibility; always writes the
    new nested shape on save().
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._data: dict[str, dict] = {}
        self._meta: dict = {}
        if self._path.exists():
            text = self._path.read_text(encoding="utf-8").strip()
            raw = json.loads(text) if text else {}
            if "concepts" in raw or "meta" in raw:
                self._data = raw.get("concepts", {})
                self._meta = raw.get("meta", {})
            else:
                self._data = raw  # legacy flat format

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def upsert(self, concept: dict) -> None:
        name = concept["name"]
        now = datetime.now(timezone.utc).isoformat()
        existing = self._data.get(name, {})
        self._data[name] = {
            "name":           name,
            "module":         concept.get("module", ""),
            "description":    concept.get("description", ""),
            "invariants":     concept.get("invariants", []),
            "contracts":      concept.get("contracts", []),
            "confidence":     concept.get("confidence", 0.0),
            "evidence":       concept.get("evidence", []),
            "last_validated": now,
            "created_at":     existing.get("created_at", now),
        }
        self.save()

    def delete(self, name: str) -> None:
        self._data.pop(name, None)
        self.save()

    def save(self) -> None:
        self._path.write_text(
            json.dumps({"meta": self._meta, "concepts": self._data}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def set_meta(self, **fields) -> None:
        """Merge fields into store-level metadata (e.g. commit=<sha>, extracted_at=<iso>) and persist."""
        self._meta.update(fields)
        self.save()

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_meta(self) -> dict:
        return dict(self._meta)

    def get(self, name: str) -> Optional[dict]:
        return self._data.get(name)

    def list(self, module: Optional[str] = None) -> list[dict]:
        concepts = list(self._data.values())
        if module is not None:
            concepts = [c for c in concepts if c.get("module") == module]
        return concepts

    def modules(self) -> list[str]:
        return sorted({c.get("module", "") for c in self._data.values() if c.get("module")})

    def __len__(self) -> int:
        return len(self._data)
