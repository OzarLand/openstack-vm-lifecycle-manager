"""Per-entity allowlist of fields that may appear in audit ``before``/``after`` (security-model.md 5.2, 8).

Allowlist, never blocklist: a field is recorded only if its entity registered it. Secret fields are never
recorded, only their names in a ``changed_fields`` marker. Registering a field whose name looks sensitive is refused, so a
careless registration cannot put a secret into the append-only log, where it could never be removed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any
from uuid import UUID

_SENSITIVE_NAME = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|credential|private|cookie|hash|totp|otp|cipher|seed)",
    re.I,
)
_JSON_SCALARS = (str, int, float, bool, type(None))


class AllowlistError(ValueError):
    pass


_ENTITIES: dict[str, tuple[frozenset[str], frozenset[str]]] = {}


def register_entity(
    entity: str, fields: Iterable[str], *, secret_fields: Iterable[str] = ()
) -> None:
    """Declare which fields of ``entity`` may be recorded; ``secret_fields`` only yield ``<f>_changed`` markers.

    Re-registering with a different set is refused (modules register once, at import).
    """
    allowed = frozenset(fields)
    secret = frozenset(secret_fields)
    bad = sorted(f for f in allowed if _SENSITIVE_NAME.search(f))
    if bad:
        raise AllowlistError(
            f"{entity}: refusing to allowlist sensitive-looking field(s) {bad}; "
            "declare them in secret_fields (only their names are recorded when they change)"
        )
    if allowed & secret:
        raise AllowlistError(
            f"{entity}: field(s) {sorted(allowed & secret)} are both allowed and secret"
        )
    existing = _ENTITIES.get(entity)
    if existing is not None and existing != (allowed, secret):
        raise AllowlistError(f"{entity}: already registered with a different field set")
    _ENTITIES[entity] = (allowed, secret)


def registered_entities() -> dict[str, frozenset[str]]:
    return {name: fields for name, (fields, _) in _ENTITIES.items()}


def _jsonable(value: Any) -> Any:
    if isinstance(value, _JSON_SCALARS):
        return value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, list | tuple | set | frozenset):
        items = sorted(value, key=str) if isinstance(value, set | frozenset) else value
        return [_jsonable(v) for v in items]
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return str(value)


def _entity(entity: str) -> tuple[frozenset[str], frozenset[str]]:
    try:
        return _ENTITIES[entity]
    except KeyError:
        raise AllowlistError(
            f"no audit allowlist registered for entity {entity!r}; call register_entity() first"
        ) from None


def snapshot(entity: str, values: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Allowlisted view of ``values``. Fields that are not allowlisted are dropped silently, by design."""
    if values is None:
        return None
    allowed, _ = _entity(entity)
    return {k: _jsonable(v) for k, v in values.items() if k in allowed}


def snapshot_pair(
    entity: str, before: Mapping[str, Any] | None, after: Mapping[str, Any] | None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Before/after snapshots; ``after["changed_fields"]`` lists secret fields whose value changed.

    The marker key is deliberately neutral (no ``secret``/``password`` in its name) so the log redaction backstop
    does not mask it and the mirrored log line stays identical to the database row.
    """
    _, secret = _entity(entity)
    b, a = snapshot(entity, before), snapshot(entity, after)
    if a is not None and secret and after is not None:
        changed = [f for f in sorted(secret) if f in after and (before or {}).get(f) != after[f]]
        if changed:
            a["changed_fields"] = changed
    return b, a
