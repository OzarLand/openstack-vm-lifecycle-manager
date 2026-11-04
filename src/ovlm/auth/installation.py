"""Installation settings with history (data-model.md section 8, ``installation_setting``).

Insert-only: a change is a new row, the current value is the newest row. Reading the value *as of* a time is what
approval re-validation needs ("was operator+approver allowed at ``decided_at``", renewal-workflow.md 3.1).
Only ``allow_operator_approver`` exists today (M9, default false).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

ALLOW_OPERATOR_APPROVER = "allow_operator_approver"
DEFAULTS: dict[str, Any] = {ALLOW_OPERATOR_APPROVER: False}


def get_setting(db: Session, key: str, *, at: datetime | None = None) -> Any:
    """The value in effect now, or at ``at`` (the newest change made at or before it); the default otherwise."""
    if key not in DEFAULTS:
        raise KeyError(key)
    row = db.execute(
        text(
            """
            SELECT value FROM installation_setting
            WHERE key = :k AND (CAST(:at AS timestamptz) IS NULL OR changed_at <= :at)
            ORDER BY changed_at DESC, id DESC LIMIT 1
            """
        ),
        {"k": key, "at": at},
    ).first()
    return DEFAULTS[key] if row is None else row.value


def allow_operator_approver(db: Session, *, at: datetime | None = None) -> bool:
    return get_setting(db, ALLOW_OPERATOR_APPROVER, at=at) is True


def set_setting(
    db: Session,
    key: str,
    value: Any,
    *,
    changed_by: UUID,
    stepup_id: UUID | None,
    reason: str = "",
) -> datetime:
    """Append a change (the caller audits it in the same transaction and commits). Returns ``changed_at``."""
    if key not in DEFAULTS:
        raise KeyError(key)
    if not isinstance(value, type(DEFAULTS[key])):
        raise TypeError(f"{key} takes a {type(DEFAULTS[key]).__name__}")
    changed_at: datetime = db.execute(
        text(
            """
            INSERT INTO installation_setting (key, value, changed_by, stepup_id, reason)
            VALUES (:k, CAST(:v AS jsonb), :by, :s, :r) RETURNING changed_at
            """
        ),
        {
            "k": key,
            "v": json.dumps(value),
            "by": changed_by,
            "s": stepup_id,
            "r": reason[:500],
        },
    ).scalar_one()
    return changed_at


def setting_history(db: Session, key: str, *, limit: int = 50) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            """
            SELECT s.value, s.changed_by, u.username, s.changed_at, s.reason
            FROM installation_setting s JOIN app_user u ON u.id = s.changed_by
            WHERE s.key = :k ORDER BY s.changed_at DESC, s.id DESC LIMIT :n
            """
        ),
        {"k": key, "n": limit},
    ).all()
    return [
        {
            "value": r.value,
            "changed_by": str(r.changed_by),
            "changed_by_username": r.username,
            "changed_at": r.changed_at.isoformat(),
            "reason": r.reason,
        }
        for r in rows
    ]
