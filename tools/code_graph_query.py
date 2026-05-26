"""Query code_graph.sqlite — Claude calls this to answer structural code questions.

Part of the three-layer team memory POC. See memory/acme_team_memory_poc.md for
full setup, layer overview, and how to rebuild the graph.

Usage:
    python tools/code_graph_query.py callers sign_request
    python tools/code_graph_query.py callees handle_challenge
    python tools/code_graph_query.py deps acme/client.py
    python tools/code_graph_query.py find JWSBuilder
    python tools/code_graph_query.py stats
"""
import argparse
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "code_graph.sqlite"


def _con() -> sqlite3.Connection:
    if not DB_PATH.exists():
        raise FileNotFoundError(f"code_graph.sqlite not found at {DB_PATH}. Run graph_extractor.py first.")
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def callers(symbol: str) -> str:
    """Who calls this function/method?"""
    con = _con()
    rows = con.execute(
        """SELECT s.file, s.name, s.kind, c.line
           FROM calls c
           JOIN symbols s ON c.caller_id = s.id
           WHERE c.callee = ? OR c.callee LIKE ?
           ORDER BY s.file, c.line""",
        (symbol, f"%.{symbol}"),
    ).fetchall()
    con.close()
    if not rows:
        return f"No callers found for: {symbol}"
    lines = [f"Callers of '{symbol}':"]
    for r in rows:
        lines.append(f"  {r['file']}:{r['line']}  {r['kind']} {r['name']}")
    return "\n".join(lines)


def callees(symbol: str) -> str:
    """What does this function call?"""
    con = _con()
    rows = con.execute(
        """SELECT c.callee, c.line
           FROM calls c
           JOIN symbols s ON c.caller_id = s.id
           WHERE s.name = ?
           ORDER BY c.line""",
        (symbol,),
    ).fetchall()
    con.close()
    if not rows:
        return f"No callees found for: {symbol}"
    lines = [f"'{symbol}' calls:"]
    for r in rows:
        lines.append(f"  line {r['line']:4d}  {r['callee']}")
    return "\n".join(lines)


def deps(file_path: str) -> str:
    """What modules does this file import?"""
    con = _con()
    rows = con.execute(
        "SELECT module, symbol FROM imports WHERE from_file = ? ORDER BY module",
        (file_path,),
    ).fetchall()
    con.close()
    if not rows:
        return f"No imports found for: {file_path}"
    lines = [f"Imports in '{file_path}':"]
    for r in rows:
        sym = f"  (symbol: {r['symbol']})" if r["symbol"] else ""
        lines.append(f"  {r['module']}{sym}")
    return "\n".join(lines)


def find(symbol: str) -> str:
    """Find all definitions of a symbol."""
    con = _con()
    rows = con.execute(
        "SELECT name, kind, file, line FROM symbols WHERE name LIKE ? ORDER BY file",
        (f"%{symbol}%",),
    ).fetchall()
    con.close()
    if not rows:
        return f"No symbols found matching: {symbol}"
    lines = [f"Symbols matching '{symbol}':"]
    for r in rows:
        lines.append(f"  {r['file']}:{r['line']}  {r['kind']} {r['name']}")
    return "\n".join(lines)


def stats() -> str:
    con = _con()
    sym = con.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
    calls = con.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
    imps = con.execute("SELECT COUNT(*) FROM imports").fetchone()[0]
    files = con.execute("SELECT COUNT(DISTINCT file) FROM symbols").fetchone()[0]
    con.close()
    return f"Code graph: {files} files, {sym} symbols, {calls} call edges, {imps} imports"


COMMANDS = {"callers": callers, "callees": callees, "deps": deps, "find": find, "stats": stats}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Query the code graph")
    parser.add_argument("command", choices=list(COMMANDS))
    parser.add_argument("arg", nargs="?", help="Symbol or file to query")
    args = parser.parse_args()

    fn = COMMANDS[args.command]
    if args.command == "stats":
        print(fn())
    elif args.arg:
        print(fn(args.arg))
    else:
        parser.error(f"'{args.command}' requires an argument")
