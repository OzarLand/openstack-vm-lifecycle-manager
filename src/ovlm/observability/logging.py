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


#: Loggers of the OpenStack SDK stack and the HTTP clients under it. At DEBUG, keystoneauth logs every request as a
#: curl line with its body and every response body: ``user_data`` with the bootstrap host key (ADR-0006),
#: ``adminPass``, credentials (security-model.md 4.5, SEC-C-2). Their children inherit the pinned level.
SDK_HTTP_LOGGERS = (
    "keystoneauth",
    "keystoneauth1",
    "openstack",
    "openstacksdk",
    "os_client_config",
    "urllib3",
    "requests",
    "httpx",
    "httpcore",
)
SDK_HTTP_MIN_LEVEL = logging.WARNING


def _is_sdk_http(name: str) -> bool:
    return any(name == p or name.startswith(p + ".") for p in SDK_HTTP_LOGGERS)


class SdkHttpLevelFilter(logging.Filter):
    """Drop records below WARNING from the SDK/HTTP loggers at the handler, whatever level those loggers were
    given later (``openstack.enable_logging(debug=True)``, a library resetting its own level, ...)."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= SDK_HTTP_MIN_LEVEL or not _is_sdk_http(record.name)


def configure_logging(
    process: str,
    level: str = "INFO",
    stream: TextIO | None = None,
    *,
    openstack_http_debug: bool = False,
) -> None:
    """Replace root handlers with one JSON handler on ``stream`` (default stdout).

    The SDK/HTTP loggers (:data:`SDK_HTTP_LOGGERS`) are held at WARNING whatever ``level`` is, unless
    ``openstack_http_debug`` (``log.openstack_http_debug``, refused by the settings outside development mode)."""
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter(process))
    handler.addFilter(RedactionFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for name in SDK_HTTP_LOGGERS:
        logging.getLogger(name).setLevel(logging.NOTSET if openstack_http_debug else SDK_HTTP_MIN_LEVEL)
    if openstack_http_debug:
        logging.getLogger("ovlm.observability").warning(
            "log.openstack_http_debug is on: OpenStack request and response bodies are logged "
            "(development only; server creation is still sent without logging)"
        )
    else:
        handler.addFilter(SdkHttpLevelFilter())
    # uvicorn installs its own handlers; route everything through ours.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True
