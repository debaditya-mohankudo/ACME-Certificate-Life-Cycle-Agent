import json
import logging
import uuid
from typing import Any

# Attributes every LogRecord carries that are not "extra" fields — anything
# else attached to the record (via logging's extra= kwarg, or a filter like
# RunIDFilter) is treated as caller-supplied structured data and included
# verbatim in the JSON line.
_STANDARD_RECORD_ATTRS = frozenset(logging.LogRecord(
    name="", level=0, pathname="", lineno=0, msg="", args=(), exc_info=None,
).__dict__.keys()) | {"message", "asctime"}


class JSONLFormatter(logging.Formatter):
    """Formats each LogRecord as a single JSON line (JSONL).

    Always includes: timestamp, level, run_id, logger, message. Any extra
    fields attached to the record (via logging's extra= kwarg, or a custom
    filter) are merged in verbatim. Exceptions are JSON-encoded as a single
    "exc_info" string field rather than the raw traceback newlines, so the
    output stays valid JSON — one object per line.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%d %H:%M:%S"),
            "level": record.levelname,
            "run_id": getattr(record, "run_id", None),
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key, value in record.__dict__.items():
            if key in _STANDARD_RECORD_ATTRS or key == "run_id":
                continue
            payload[key] = value

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


class RunIDFilter(logging.Filter):
    """Filter that injects run_id into log records."""

    def __init__(self, run_id: str):
        super().__init__()
        self.run_id = run_id

    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = self.run_id
        return True


class LoggerDecorator:
    """
    Decorator that wraps a standard logger with run_id tracking.
    
    Uses the decorator pattern to extend logging.Logger behavior
    without inheritance, maintaining loose coupling.
    """
    
    def __init__(self, logger: logging.Logger, run_id: str):
        self._logger = logger
        self.run_id = run_id
        self._configure()
    
    def _configure(self) -> None:
        """Configure the wrapped logger with run_id filter and formatter."""
        self._logger.setLevel(logging.INFO)
        
        # Add run_id filter
        run_id_filter = RunIDFilter(self.run_id)
        self._logger.addFilter(run_id_filter)
        
        # Configure handler with JSONL output (one JSON object per log line)
        handler = logging.StreamHandler()
        handler.setFormatter(JSONLFormatter())
        self._logger.addHandler(handler)
    
    # Delegate logging methods to wrapped logger
    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.info(msg, *args, **kwargs)
    
    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.error(msg, *args, **kwargs)
    
    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.warning(msg, *args, **kwargs)
    
    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.debug(msg, *args, **kwargs)
    
    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.exception(msg, *args, **kwargs)
    
    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.critical(msg, *args, **kwargs)
    
    def get_run_id(self) -> str:
        return self.run_id


class LoggerWithRunID:
    """
    Singleton facade for LoggerDecorator.
    
    Ensures single run_id across the application lifecycle.
    """
    _instance: "LoggerWithRunID | None" = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, name: str = "agent"):
        if not hasattr(self, "initialized"):
            run_id = str(uuid.uuid4())
            self.logger = logging.getLogger(name)  # Exposed for backward compatibility
            self._decorator = LoggerDecorator(self.logger, run_id)
            self.initialized = True
    
    # Delegate all methods to the decorator
    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._decorator.info(msg, *args, **kwargs)
    
    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._decorator.error(msg, *args, **kwargs)
    
    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._decorator.warning(msg, *args, **kwargs)
    
    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._decorator.debug(msg, *args, **kwargs)
    
    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._decorator.exception(msg, *args, **kwargs)
    
    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._decorator.critical(msg, *args, **kwargs)
    
    def get_run_id(self) -> str:
        return self._decorator.get_run_id()

__all__ = ["LoggerWithRunID", "logger"]

# Module-level singleton instance to avoid callers instantiating during import,
# which can cause race conditions when many modules create their own instances.
logger = LoggerWithRunID()
