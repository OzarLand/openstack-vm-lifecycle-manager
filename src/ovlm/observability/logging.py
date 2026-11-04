"""Structured JSON logging to stdout."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, TextIO

from ovlm.observability.context import current_context
from ovlm.observability.redaction import RedactionFilter, redact_text, redact_value

_STANDARD = set(vars(logging.LogRecord("x", 0, "", 0, "", (), None))) | {
    "message",
    "asctime",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    def __init__(self, process: str) -> None:
        super().__init__()
        self.process = process

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "process": self.process,
            "logger": record.name,
            "event": record.getMessage(),
        }
        payload.update(current_context())
        for key, value in vars(record).items():
            if key not in _STANDARD and key not in payload:
                payload[key] = redact_value(value, key)
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            payload["exception"] = record.exc_text
        # Final pass over the serialized line: the backstop of the backstop.
        return redact_text(json.dumps(payload, default=str, ensure_ascii=False))


def configure_logging(process: str, level: str = "INFO", stream: TextIO | None = None) -> None:
    """Replace root handlers with one JSON handler on ``stream`` (default stdout)."""
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter(process))
    handler.addFilter(RedactionFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # uvicorn installs its own handlers; route everything through ours.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True
