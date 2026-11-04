"""Reading secrets from files.

Secrets never come from the command line or from plain environment values. A setting such as
``db.password_file`` names a file (Docker secret); the value is read here and registered so that the
logging redaction backstop (``ovlm.observability.redaction``) knows it.
"""

from __future__ import annotations

import threading
from pathlib import Path

_lock = threading.Lock()
_known: set[str] = set()


class SecretFileError(RuntimeError):
    """A secret file is missing, unreadable or empty. The message never contains the secret."""


def register_secret(value: str) -> None:
    """Remember a secret value so log output can be scrubbed of it."""
    if value:
        with _lock:
            _known.add(value)


def known_secrets() -> frozenset[str]:
    with _lock:
        return frozenset(_known)


def clear_known_secrets() -> None:
    """Test helper."""
    with _lock:
        _known.clear()


def read_secret_file(path: str | Path) -> str:
    """Return the stripped content of a secret file and register it for redaction."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SecretFileError(
            f"cannot read secret file {p}: {exc.strerror or type(exc).__name__}"
        ) from None
    value = raw.strip("\r\n")
    if not value:
        raise SecretFileError(f"secret file {p} is empty")
    register_secret(value)
    return value
