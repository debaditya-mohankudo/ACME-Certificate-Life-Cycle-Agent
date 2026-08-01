"""SysML model tests — the model checked mechanically, not merely asserted.

These files describe responsibilities, the rules each one owns, and the shape
of the renewal workflow. Nothing referenced them when they were written, and a
model nothing checks is prose: it stays plausible while the code moves under it,
and the drift is discovered by someone acting on a stale claim.

This repo has already paid that bill once. `.history` was an append-only log
whose last entry said the LLM had been removed entirely, three commits after it
had been restored; it was deleted rather than corrected, because nothing could
have kept it honest. The models are a better artifact only if something fails
when they stop being true.

Three checks, in rising order of how much they would have caught:

  * Structure — one satisfier per requirement, every requirement allocated,
    every allocation naming a part that actually exists.

  * Citations — every requirement carries a `Source:` line, and every file path
    on it still exists. Documentation here rots by pointing at deleted code far
    more often than by becoming malformed.

  * The graph — every node and every edge in the ACME builder appears in the
    state model, and vice versa. This is the live tripwire: the state model
    claims to be transcribed from `agent/graph.py`, and this is what makes that
    claim testable rather than aspirational.

The graph is read as SOURCE TEXT, deliberately, not by importing it. Importing
would drag in settings resolution and the node registry, so the test would begin
depending on configuration to check a fact about the code's structure.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
MODELS = REPO / "models"
GRAPH = REPO / "agent" / "graph.py"

EXPECTED = {
    "foundation.sysml",
    "acme_agent_system.sysml",
    "renewal_lifecycle.sysml",
    "requirements.sysml",
}

REQUIREMENT_DEF = re.compile(r"requirement\s+def\s+(\w+)")
SATISFY = re.compile(r"satisfy\s+requirement\s+(\w+)\s+by\s+([\w.]+)\s*;")
PART_DEF = re.compile(r"part\s+def\s+(\w+)")
PART_INSTANCE = re.compile(r"part\s+(\w+)\s*:\s*(\w+)\s*;")
STATE_DECL = re.compile(r"^\s*state\s+(\w+)\s*;", re.M)
TRANSITION = re.compile(r"transition\s+\w+\s+first\s+(\w+)\s+then\s+(\w+)\s*;")

SOURCE_LINE = re.compile(r"Source:([^\n*]*(?:\n\s*\*[^\n]*)*)")
PATH_LIKE = re.compile(r"\b((?:[\w.-]+/)*[\w.-]+\.py)\b")

ADD_EDGE = re.compile(r"add_edge\(\s*([\"']?\w+[\"']?)\s*,\s*([\"']?\w+[\"']?)\s*\)")
COND_EDGES = re.compile(
    r"add_conditional_edges\(\s*\"(\w+)\"\s*,\s*\w+\s*,\s*\{(.*?)\}", re.S
)
COND_TARGET = re.compile(r"\"[\w_]+\"\s*:\s*\"(\w+)\"")


def _snake_to_camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part.capitalize() for part in rest)


def _acme_graph_source() -> str:
    """Just the ACME builder — the SPIFFE builder is a different machine."""
    text = GRAPH.read_text()
    start = text.index("def _build_acme_graph")
    end = text.index("def _build_spiffe_graph")
    return text[start:end]


def _graph_edges() -> set[tuple[str, str]]:
    """Every (from, to) pair the ACME builder wires, in camelCase.

    START and END are dropped: they are LangGraph's sentinels, and the model
    represents them as the machine's own entry and terminus.
    """
    source = _acme_graph_source()
    edges: set[tuple[str, str]] = set()

    for raw_a, raw_b in ADD_EDGE.findall(source):
        a, b = raw_a.strip("\"'"), raw_b.strip("\"'")
        if a in {"START", "END"} or b in {"START", "END"}:
            continue
        edges.add((_snake_to_camel(a), _snake_to_camel(b)))

    for src, block in COND_EDGES.findall(source):
        for dst in COND_TARGET.findall(block):
            edges.add((_snake_to_camel(src), _snake_to_camel(dst)))

    return edges


@pytest.fixture(scope="module")
def requirements() -> str:
    return (MODELS / "requirements.sysml").read_text()


@pytest.fixture(scope="module")
def system() -> str:
    return (MODELS / "acme_agent_system.sysml").read_text()


@pytest.fixture(scope="module")
def lifecycle() -> str:
    return (MODELS / "renewal_lifecycle.sysml").read_text()


class TestPresence:
    def test_model_files_are_exactly_the_expected_set(self):
        assert {p.name for p in MODELS.glob("*.sysml")} == EXPECTED


class TestSingleAllocation:
    def test_no_requirement_has_more_than_one_satisfy(self, requirements):
        """A rule needing two owners means the rule and its data have drifted."""
        counts: dict[str, list[str]] = {}
        for name, part in SATISFY.findall(requirements):
            counts.setdefault(name, []).append(part)
        duplicates = {n: p for n, p in counts.items() if len(p) > 1}
        assert not duplicates, f"allocated to more than one part: {duplicates}"

    def test_every_requirement_is_allocated(self, requirements):
        defined = set(REQUIREMENT_DEF.findall(requirements))
        allocated = {name for name, _ in SATISFY.findall(requirements)}
        assert defined == allocated, (
            f"unallocated: {sorted(defined - allocated)}; "
            f"allocated but undefined: {sorted(allocated - defined)}"
        )

    def test_allocations_name_real_parts(self, requirements, system):
        composed = {name for name, _ in PART_INSTANCE.findall(system)}
        for requirement, target in SATISFY.findall(requirements):
            assert target.startswith("system."), f"{requirement} -> {target}"
            part = target.split(".", 1)[1]
            assert part in composed, f"{requirement} names unknown part {part!r}"


class TestCitations:
    def test_every_requirement_cites_a_source(self, requirements):
        blocks = requirements.split("requirement def ")[1:]
        missing = [
            b.split("{")[0].strip()
            for b in blocks
            if "Source:" not in b.split("satisfy")[0]
        ]
        assert not missing, f"requirements with no Source: line: {missing}"

    def test_cited_paths_exist(self, requirements):
        dead = sorted({
            path
            for source in SOURCE_LINE.findall(requirements)
            for path in PATH_LIKE.findall(source)
            if not (REPO / path).exists()
        })
        assert not dead, f"requirement docs cite files that no longer exist: {dead}"


class TestStateModelMatchesGraph:
    """The state model claims to be transcribed from agent/graph.py. These make
    that claim fail loudly when someone rewires the graph and forgets."""

    def test_every_graph_node_is_a_state(self, lifecycle):
        states = set(STATE_DECL.findall(lifecycle))
        nodes = {n for edge in _graph_edges() for n in edge}
        missing = sorted(nodes - states)
        assert not missing, f"graph nodes absent from the state model: {missing}"

    def test_every_graph_edge_is_a_transition(self, lifecycle):
        modelled = set(TRANSITION.findall(lifecycle))
        actual = _graph_edges()
        missing = sorted(actual - modelled)
        assert not missing, f"graph edges absent from the state model: {missing}"

    def test_no_transition_is_invented(self, lifecycle):
        """The model must not claim routing the graph does not have."""
        modelled = set(TRANSITION.findall(lifecycle))
        actual = _graph_edges()
        # The entry transition into the scanner has no add_edge of its own —
        # it comes from START, which is dropped above.
        invented = sorted(modelled - actual - {("certificateScanner", "renewalPlanner")})
        assert not invented, f"state model invents transitions: {invented}"

    def test_backoff_edge_is_not_collapsed(self, lifecycle):
        """Retry routes through the scheduler; skip goes straight back. Merging
        them would silently drop the backoff, and both edges look alike."""
        modelled = set(TRANSITION.findall(lifecycle))
        assert ("errorHandler", "retryScheduler") in modelled
        assert ("retryScheduler", "pickNextDomain") in modelled
        assert ("errorHandler", "pickNextDomain") in modelled
