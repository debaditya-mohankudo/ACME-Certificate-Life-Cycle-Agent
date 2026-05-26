"""Extract symbol/call/import graph from all .py files → code_graph.sqlite.

Uses stdlib ast only — zero extra dependencies.

Usage:
    python tools/graph_extractor.py
    python tools/graph_extractor.py --output /tmp/code_graph.sqlite
    python tools/graph_extractor.py --root /path/to/repo
    python tools/graph_extractor.py --exclude .venv --exclude build
"""
import ast
import argparse
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS symbols (
    id     INTEGER PRIMARY KEY,
    name   TEXT NOT NULL,
    kind   TEXT NOT NULL,   -- function | class | method
    file   TEXT NOT NULL,
    line   INTEGER,
    module TEXT
);

CREATE TABLE IF NOT EXISTS calls (
    id        INTEGER PRIMARY KEY,
    caller_id INTEGER REFERENCES symbols(id),
    callee    TEXT NOT NULL,   -- name as written in source (may be dotted)
    file      TEXT NOT NULL,
    line      INTEGER
);

CREATE TABLE IF NOT EXISTS imports (
    id        INTEGER PRIMARY KEY,
    from_file TEXT NOT NULL,
    module    TEXT NOT NULL,
    symbol    TEXT            -- specific name imported, NULL for plain import
);

CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_id);
CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee);
"""


class _Visitor(ast.NodeVisitor):
    def __init__(self, file: str, module: str, con: sqlite3.Connection):
        self.file = file
        self.module = module
        self.con = con
        self._scope_stack: list[int] = []  # symbol ids of enclosing functions/classes

    def _insert_symbol(self, name: str, kind: str, line: int) -> int:
        cur = self.con.execute(
            "INSERT INTO symbols (name, kind, file, line, module) VALUES (?,?,?,?,?)",
            (name, kind, self.file, line, self.module),
        )
        return cur.lastrowid

    def visit_FunctionDef(self, node: ast.FunctionDef):
        kind = "method" if self._scope_stack else "function"
        sym_id = self._insert_symbol(node.name, kind, node.lineno)
        self._scope_stack.append(sym_id)
        self.generic_visit(node)
        self._scope_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef):
        sym_id = self._insert_symbol(node.name, "class", node.lineno)
        self._scope_stack.append(sym_id)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_Call(self, node: ast.Call):
        caller_id = self._scope_stack[-1] if self._scope_stack else None
        callee = _call_name(node.func)
        if callee and caller_id is not None:
            self.con.execute(
                "INSERT INTO calls (caller_id, callee, file, line) VALUES (?,?,?,?)",
                (caller_id, callee, self.file, node.lineno),
            )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.con.execute(
                "INSERT INTO imports (from_file, module, symbol) VALUES (?,?,?)",
                (self.file, alias.name, None),
            )

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            self.con.execute(
                "INSERT INTO imports (from_file, module, symbol) VALUES (?,?,?)",
                (self.file, module, alias.name),
            )


def _call_name(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _module_name(root: Path, path: Path) -> str:
    rel = path.relative_to(root)
    return str(rel.with_suffix("")).replace("/", ".")


def extract(root: Path, db_path: Path, exclude: list[str] | None = None):
    exclude_dirs = set(exclude or []) | {"__pycache__"}
    con = sqlite3.connect(db_path)
    con.executescript("DROP TABLE IF EXISTS calls; DROP TABLE IF EXISTS imports; DROP TABLE IF EXISTS symbols;")
    con.executescript(SCHEMA)

    def _is_excluded(path: Path) -> bool:
        return any(part in exclude_dirs for part in path.relative_to(root).parts)

    py_files = [p for p in root.rglob("*.py") if not _is_excluded(p)]
    for path in sorted(py_files):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            print(f"  skip (syntax error): {path}")
            continue
        rel = str(path.relative_to(root))
        module = _module_name(root, path)
        visitor = _Visitor(rel, module, con)
        visitor.visit(tree)

    con.commit()
    con.execute("VACUUM")
    sym_count = con.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
    call_count = con.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
    imp_count = con.execute("SELECT COUNT(*) FROM imports").fetchone()[0]
    con.close()
    print(f"✓ {len(py_files)} files → {sym_count} symbols, {call_count} calls, {imp_count} imports → {db_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repo root (default: cwd)")
    parser.add_argument("--output", default="code_graph.sqlite")
    parser.add_argument("--exclude", action="append", default=[".venv", "venv", "env"],
                        help="Directory names to exclude (repeatable, default: .venv venv env)")
    args = parser.parse_args()
    extract(Path(args.root).resolve(), Path(args.output), exclude=args.exclude)
