"""Shared Textual building blocks, vendored from the house TUI style used
by crew-bug-hunter/crew_bug_hunter/tui_widgets.py, bee-bug-hunter/bee_bug_hunter/tui_widgets.py,
and docker_log_analyzer/tui_widgets.py.

Vendored rather than imported cross-repo: this repo has no shared dependency
on those packages. Keep this file's bordered()/EventFeed/step_prefix() contents
identical to the other repos' copies when updating any of them.

FeedLogHandler differs from the other repos' copies: those forward structured
logs keyed by short event-name messages (e.g. "flow_run_started") via an
explicit _KIND_BY_MESSAGE lookup. This repo's nodes (agent/nodes/*.py) log
free-form printf-style sentences via logger.py's LoggerWithRunID/JSONLFormatter
instead, so there is no fixed event-name vocabulary to key off of. FeedLogHandler
here maps by logging *level* instead: INFO -> context_log, WARNING -> tool_call,
ERROR/CRITICAL -> tool_crashed. This is coarser than the other repos' per-event
icons but requires no changes to any node's existing logger.info/.warning/.error
call sites.
"""
import logging
from typing import Any

from rich.markup import escape as escape_markup
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import RichLog, Static

from logger import logger as _agent_logger


def bordered(widget: Widget, title: str) -> Widget:
    """Set `widget.border_title` and return it, so every bordered picker/
    content box in every screen gets its purpose labeled the same way,
    inline in a `yield` or `with` statement instead of a separate
    query_one(...).border_title = ... follow-up line."""
    widget.border_title = title
    return widget


def breadcrumb_bar(labels: list[str], active_index: int) -> Horizontal:
    """Chip-style breadcrumb — "Home › Run" rendered as bordered, colored
    chip widgets (active chip highlighted) rather than plain text, adapted
    from docker_log_analyzer/tui.py's breadcrumb_bar(). That version is a
    fixed linear stepper (Connect > Window > Menu > Result) for a wizard
    flow; this app's navigation is hub-and-spoke (Home, plus whichever
    screen was pushed from it), so callers pass exactly ["Home", <current
    screen label>] with active_index=1, or ["Home"] with active_index=0 for
    HomeScreen itself — same chip visuals, no fixed step count assumed.

    Yield at the top of every screen's compose(), above the screen's own
    content, mirroring the vendored pattern's placement.
    """
    chips: list[Widget] = []
    for i, label in enumerate(labels):
        classes = "breadcrumb-chip active" if i == active_index else "breadcrumb-chip"
        chips.append(Static(label, classes=classes))
        if i < len(labels) - 1:
            chips.append(Static("›", classes="breadcrumb-sep"))
    return Horizontal(*chips, classes="breadcrumb-bar")


def status_chip(text: str, kind: str = "neutral") -> Static:
    """Small bordered pill indicator — e.g. "acme mode", "deterministic",
    "✗ run failed". `kind` selects the CSS class (neutral/success/warning/
    error) driving the chip's border/text color via AcmeTuiApp's theme-
    variable CSS rules (.status-chip.success/.warning/.error)."""
    classes = "status-chip" if kind == "neutral" else f"status-chip {kind}"
    return Static(text, classes=classes)


def stat_tile(label: str, value: str) -> Widget:
    """Bordered label/value box for a row of summary numbers (e.g. domain
    count, days until soonest expiry) — reads better at a glance than the
    same numbers embedded in a paragraph of text."""
    return Vertical(
        Static(value, classes="stat-tile-value"),
        Static(label, classes="stat-tile-label"),
        classes="stat-tile",
    )


def step_prefix(index: int, total: int) -> str:
    """"[2/6] " style progress counter for a multi-step intake flow."""
    return f"[{index + 1}/{total}] "


# Event-kind -> (icon, rich markup color) for EventFeed.write_event.
_EVENT_STYLES: dict[str, tuple[str, str]] = {
    "tool_call": ("▶", "bold amber1"),
    "tool_done": ("✓", "green"),
    "tool_crashed": ("✗", "bold red"),
    "context_log": ("", "dim"),
}

# logging level -> EventFeed kind, for FeedLogHandler's level-based mapping
# (see module docstring for why this repo can't key off event-name messages
# the way the other vendored copies of this file do).
_LEVEL_TO_KIND: dict[int, str] = {
    logging.DEBUG: "context_log",
    logging.INFO: "context_log",
    logging.WARNING: "tool_call",
    logging.ERROR: "tool_crashed",
    logging.CRITICAL: "tool_crashed",
}


class EventFeed(RichLog):
    """RichLog specialized for a live progress-event feed — color/icon-codes
    each event kind so a run can be scanned at a glance, and escapes every
    interpolated field via rich.markup.escape first.

    Caller supplies already-formatted, already-escaped text per event; kind
    controls the icon/color prefix. Falls back to plain text for an
    unrecognized kind rather than raising.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("highlight", False)
        kwargs.setdefault("markup", True)
        kwargs.setdefault("wrap", True)
        super().__init__(*args, **kwargs)

    @staticmethod
    def escape(text: str) -> str:
        return escape_markup(text)

    def write_event(self, kind: str, text: str) -> None:
        icon, color = _EVENT_STYLES.get(kind, ("", ""))
        prefix = f"[{color}]{icon}[/] " if icon else (f"[{color}]" if color else "")
        suffix = "[/]" if color and not icon else ""
        self.write(f"{prefix}{text}{suffix}")


class FeedLogHandler(logging.Handler):
    """Forwards this repo's structured logger (logger.py's LoggerWithRunID,
    the same one every agent/nodes/*.py module already calls) into an
    EventFeed, so the TUI's live view is driven by the exact same log
    records that already flow to JSONL stdout — no parallel logging path.

    Attach directly to the underlying stdlib logger, not the LoggerWithRunID
    facade:

        from logger import logger as agent_logger
        handler = FeedLogHandler(event_feed)
        agent_logger.logger.addHandler(handler)
        ...
        agent_logger.logger.removeHandler(handler)  # when the screen is torn down
    """

    def __init__(self, feed: EventFeed) -> None:
        super().__init__()
        self._feed = feed

    def emit(self, record: logging.LogRecord) -> None:
        kind = _LEVEL_TO_KIND.get(record.levelno, "context_log")
        text = EventFeed.escape(self.format(record) if self.formatter else record.getMessage())
        self._feed.write_event(kind, text)


def log_ui(event: str, **fields: Any) -> None:
    """Every screen change / button click / key interaction in the TUI goes
    through this, so the app's own interaction trail lands in the same JSONL
    stream as node-level events (logger.py's LoggerWithRunID/JSONLFormatter)
    instead of being invisible outside the terminal session — mirrors
    crew-bug-hunter's log_ui() helper.

    Calls the LoggerWithRunID facade directly (not a child logger) so the
    existing RunIDFilter — attached via logger.addFilter on this exact
    logger instance — actually applies; a `logging.getLogger("agent.tui")`
    child would propagate to the same handler but skip that filter, since
    Logger-level filters only run for records handled by the logger they
    were attached to, not for records merely propagated through it.

    Call sites (screens/app, added when they're built):
        on_mount / on_screen_resume -> log_ui("screen_shown", screen="HomeScreen")
        on_button_pressed            -> log_ui("button_pressed", button=event.button.id)
    """
    _agent_logger.info(event, extra={"ui_event": True, **fields})
