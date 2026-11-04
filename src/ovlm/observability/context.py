"""Correlation context for log lines (run_id, step_id, request_id, ...)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any

#: Context fields (architecture.md section 6). Values are None when unset and then omitted from log lines.
FIELDS: tuple[str, ...] = (
    "request_id",
    "actor",
    "run_id",
    "step_id",
    "step_key",
    "attempt",
    "fencing_token",
    "project_id",
    "openstack_request_id",
)

_vars: dict[str, ContextVar[Any]] = {
    name: ContextVar(f"ovlm_{name}", default=None) for name in FIELDS
}


def current_context() -> dict[str, Any]:
    return {name: var.get() for name, var in _vars.items() if var.get() is not None}


@contextmanager
def bind_context(**fields: Any) -> Iterator[None]:
    """Bind correlation fields for the duration of the block (asyncio- and thread-safe)."""
    unknown = set(fields) - set(FIELDS)
    if unknown:
        raise ValueError(f"unknown context field(s): {sorted(unknown)}")
    tokens: list[tuple[ContextVar[Any], Token[Any]]] = []
    try:
        for name, value in fields.items():
            var = _vars[name]
            tokens.append((var, var.set(value)))
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)
