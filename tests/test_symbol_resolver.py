"""Tests for concept_store.symbol_resolver and the symbol-only evidence format
it exists to serve (see store.py's evidence field docs)."""
import re
from pathlib import Path

import pytest

from concept_store.store import ConceptStore
from concept_store.symbol_resolver import SymbolNotFoundError, parse_citation, resolve_symbol

REPO_ROOT = Path(__file__).resolve().parent.parent

# "file" or "file:symbol"/"file:Class.method" -- never a line number or range.
_CITATION_RE = re.compile(r"^[^\s:]+(:[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?)?$")


def test_parse_citation_splits_symbol():
    assert parse_citation("main.py:suppress_core_dumps") == ("main.py", "suppress_core_dumps")


def test_parse_citation_bare_file_has_no_symbol():
    assert parse_citation("logger.py") == ("logger.py", None)


def test_resolve_symbol_finds_top_level_function():
    start, end = resolve_symbol(REPO_ROOT, "main.py", "suppress_core_dumps")
    assert start < end


def test_resolve_symbol_finds_method_on_class():
    start, end = resolve_symbol(REPO_ROOT, "agent/nodes/csr.py", "CsrGeneratorNode.run")
    assert start < end


def test_resolve_symbol_raises_for_unknown_name():
    with pytest.raises(SymbolNotFoundError):
        resolve_symbol(REPO_ROOT, "main.py", "does_not_exist")


def test_resolve_symbol_raises_when_descending_into_non_class():
    with pytest.raises(SymbolNotFoundError):
        resolve_symbol(REPO_ROOT, "main.py", "suppress_core_dumps.nested")


def test_concepts_json_evidence_matches_symbol_only_format():
    """Every evidence string in the real store must be "file" or "file:symbol" --
    no line numbers or ranges, since those are exactly what goes stale."""
    store = ConceptStore(REPO_ROOT / "concept_store" / "concepts.json")
    for concept in store.list():
        for citation in concept["evidence"]:
            assert _CITATION_RE.match(citation), (
                f"{concept['name']!r} has a non-symbol-only citation: {citation!r}"
            )
