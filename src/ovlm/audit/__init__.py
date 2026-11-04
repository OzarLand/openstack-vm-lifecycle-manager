"""Audit module (architecture.md section 3): append-only ``audit_event`` log.

Public API: :func:`record` (insert in the caller's transaction, mirror to the log after commit),
:func:`register_entity` (per-entity allowlist of fields that may appear in before/after) and :func:`list_events`.
May depend on ``db`` and ``observability``; it never updates or deletes rows (the database refuses it too).
"""

from ovlm.audit.allowlist import (
    AllowlistError,
    register_entity,
    registered_entities,
    snapshot,
    snapshot_pair,
)
from ovlm.audit.service import AuditRow, PrincipalType, Result, list_events, record

__all__ = [
    "AllowlistError",
    "AuditRow",
    "PrincipalType",
    "Result",
    "list_events",
    "record",
    "register_entity",
    "registered_entities",
    "snapshot",
    "snapshot_pair",
]
