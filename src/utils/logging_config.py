"""JSON logging setup so log output is machine-parseable."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

# Attributes that are part of the standard LogRecord and should not be re-emitted
# as "extra" fields.
_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module",
    "exc_info", "exc_text", "stack_info", "lineno", "funcName", "created", "msecs",
    "relativeCreated", "thread", "threadName", "processName", "process", "taskName",
    "message", "asctime",
}


class JsonFormatter(logging.Formatter):
    """Render each record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(level: str = "INFO") -> None:
    """Configure the root logger once, idempotently.

    Safe to call from CLI entrypoints; subsequent calls only adjust the level.
    """
    root = logging.getLogger()
    root.setLevel(level.upper())

    # Avoid stacking duplicate handlers if called more than once.
    if not any(isinstance(h, logging.StreamHandler) and getattr(h, "_cve_analysis", False) for h in root.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        handler._cve_analysis = True  # type: ignore[attr-defined]
        root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger (root handler config applied via setup_logging)."""
    return logging.getLogger(name)


def set_level(level: Optional[str]) -> None:
    """Adjust the root logger level without re-adding handlers."""
    if level:
        logging.getLogger().setLevel(level.upper())
