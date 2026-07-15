"""Shared subprocess-launch/JSONL-stream helper for RunScreen and
RevokeScreen — both shell out to a main.py CLI subcommand and need the same
launch/parse/forward loop. Extracted here rather than duplicated per the
epic's grooming note: two screens independently reimplementing the same
Popen/readline/json.loads loop is the "duplicate ownership" failure mode
task-grooming explicitly calls out to avoid.

Intentionally has no Textual imports — this module only knows about
subprocess/JSON, not widgets. Callers own translating parsed lines into
EventFeed writes via call_from_thread.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any, Callable

JsonRecord = dict[str, Any]
OnLine = Callable[[str, "JsonRecord | None"], None]
IsCancelled = Callable[[], bool]


def parse_jsonl_line(line: str) -> JsonRecord | None:
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def stream_subprocess(argv: list[str], on_line: OnLine, is_cancelled: IsCancelled) -> tuple[int, str | None]:
    """Runs argv, forwarding each stdout line (parsed as JSONL where
    possible) to on_line as it arrives. Returns (exit_code, last_error) where
    last_error is the message of the last ERROR/CRITICAL-level line seen, or
    None if none occurred.

    Must be called from a worker thread (not the event loop) — this blocks
    on subprocess I/O for the run's full duration.
    """
    last_error: str | None = None
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            if is_cancelled():
                proc.terminate()
                break
            record = parse_jsonl_line(line)
            on_line(line.rstrip("\n"), record)
            if record and record.get("level") in ("ERROR", "CRITICAL"):
                last_error = record.get("message", line)
        exit_code = proc.wait()
    except Exception:
        proc.kill()
        proc.wait()
        raise
    return exit_code, last_error
