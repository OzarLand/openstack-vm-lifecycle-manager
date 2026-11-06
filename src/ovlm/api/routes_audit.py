"""``GET /api/v1/audit`` (api-design.md 3.8): the audit log, scoped like the inventory and filtered by role.

Viewer role; an API token with the ``read`` scope may call it. What the caller sees is decided by
``ovlm.audit.view.visible_events`` (project scope, SEC-R-31 admin-only actions); an invisible project is never
leaked. ``run=`` returns a run's whole trail (the run, its steps' targets and its approvals).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ovlm.api.routes_common import ProblemRoute
from ovlm.audit import view
from ovlm.auth.authz import Action
from ovlm.auth.deps import get_db, require_action
from ovlm.auth.principal import Principal
from ovlm.registry.errors import DomainError

VIEWER = Depends(require_action(Action.AUDIT_VIEW))
DB = Annotated[Session, Depends(get_db)]

router = APIRouter(prefix="/api/v1", route_class=ProblemRoute)


def _utc(value: datetime | None) -> datetime | None:
    return value if value is None or value.tzinfo else value.replace(tzinfo=UTC)


@router.get("/audit")
def list_audit(
    session: DB,
    actor: UUID | None = None,
    target: Annotated[str | None, Query(max_length=200)] = None,
    run: UUID | None = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    limit: Annotated[int | None, Query(ge=1, le=view.MAX_PAGE)] = None,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    who: Principal = VIEWER,
) -> dict[str, Any]:
    """Newest first. ``actor``: user id. ``target``: the target id. ``from`` (inclusive) and ``to`` (exclusive):
    timestamps; without a UTC offset, UTC is assumed."""
    try:
        page = view.visible_events(
            session, who, actor_id=actor, target_id=target or None, run_id=run,
            since=_utc(from_), until=_utc(to), limit=limit, cursor=cursor,
        )  # fmt: skip
    except view.InvalidCursorError:
        raise DomainError(400, "invalid-cursor", "Invalid cursor", "The cursor is malformed.",
                          "Restart from the first page.") from None  # fmt: skip
    return {"items": [view.event_dict(r) for r in page.items], "next_cursor": page.next_cursor}
