"""Redaction backstop for logs (security-model.md section 5.2).

Primary defence: secrets are never passed to the logger. This filter is the backstop: it removes
known secret values (every value read by ``ovlm.config.secrets.read_secret_file``), values of
sensitive-looking field names, ``user:password@`` URL userinfo and ``Bearer`` tokens, in the message, its
arguments, exception text and extra fields.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from ovlm.config.secrets import known_secrets

REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|authorization|credential|private[_-]?key|cookie)",
    re.I,
)
_URL_USERINFO = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^/\s:@]*):(?P<pw>[^/\s@]+)@"
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_KEY_VALUE = re.compile(
    r"(?i)\b(?P<k>[\w.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key)[\w.-]*)(?P<sep>\s*[=:]\s*)(?P<v>[^\s,;&\"']+)"
)
_STANDARD = set(vars(logging.LogRecord("x", 0, "", 0, "", (), None))) | {
    "message",
    "asctime",
    "taskName",
}


def _variants(secret: str) -> set[str]:
    """Forms a secret may take in output: raw, JSON-escaped, repr-escaped."""
    return {secret, json.dumps(secret)[1:-1], repr(secret)[1:-1]}


def redact_text(text: str) -> str:
    for secret in sorted(known_secrets(), key=len, reverse=True):
        for form in _variants(secret):
            if form:
                text = text.replace(form, REDACTED)
    text = _URL_USERINFO.sub(lambda m: f"{m['scheme']}{m['user']}:{REDACTED}@", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    return _KEY_VALUE.sub(lambda m: f"{m['k']}{m['sep']}{REDACTED}", text)


def redact_value(value: Any, key: str | None = None) -> Any:
    if key is not None and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(k): redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [redact_value(v) for v in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    return redact_text(str(value))


class RedactionFilter(logging.Filter):
    """Scrub a record in place. Attach to the handler so it also covers records from libraries."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a bad format string must not break logging
            message = str(record.msg)
        record.msg = redact_text(message)
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_text(record.stack_info)
        for key in list(vars(record)):
            if key not in _STANDARD:
                setattr(record, key, redact_value(getattr(record, key), key))
        return True
