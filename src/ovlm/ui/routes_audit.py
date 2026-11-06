"""The audit page (E6-4): a filterable table of the events the caller may see.

It calls ``ovlm.audit.view.visible_events``, the function behind ``GET /api/v1/audit``, so it applies the same
project scoping and the same admin-only action rule (SEC-R-31). HTMX swaps only the results; the page works without
JavaScript (a plain GET form and a "next page" link).
"""

from __future__ import annotations

from typing import Annotated, Any
from urllib.parse import urlencode
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ovlm.audit import view
from ovlm.auth.authz import Action
from ovlm.auth.deps import get_db, require_action
from ovlm.auth.principal import Principal
from ovlm.ui.support import UiRoute, parse_ts, render

router = APIRouter(route_class=UiRoute, include_in_schema=False)
Db = Annotated[Session, Depends(get_db)]
VIEWER = Depends(require_action(Action.AUDIT_VIEW))
PAGE_SIZE = 50


def _uuid(value: str) -> UUID | None:
    try:
        return UUID(value.strip())
    except ValueError:
        return None


@router.get("/audit", response_class=HTMLResponse)
def audit_view(
    request: Request, db: Db, actor: str = "", target: str = "", run: str = "",
    from_: Annotated[str, Query(alias="from")] = "", to: str = "", cursor: str = "",
    who: Principal = VIEWER,
) -> HTMLResponse:  # fmt: skip
    problems: list[str] = []
    actor_id = run_id = None
    if actor.strip():
        actor_id = _uuid(actor)
        if actor_id is None:
            problems.append("The actor filter must be a user id (a UUID).")
    if run.strip():
        run_id = _uuid(run)
        if run_id is None:
            problems.append("The run filter must be a run id (a UUID).")
    since, until = parse_ts(from_), parse_ts(to)
    if from_.strip() and since is None:
        problems.append("The from filter must be a date such as 2026-11-06 or 2026-11-06T09:30.")
    if to.strip() and until is None:
        problems.append("The to filter must be a date such as 2026-11-06 or 2026-11-06T09:30.")
    page = view.AuditPage([], None)
    if not problems:
        try:
            page = view.visible_events(
                db, who, actor_id=actor_id, target_id=target.strip() or None, run_id=run_id,
                since=since, until=until, limit=PAGE_SIZE, cursor=cursor or None,
            )  # fmt: skip
        except view.InvalidCursorError:
            problems.append("The page link is not valid. Showing the first page.")
            page = view.visible_events(
                db, who, actor_id=actor_id, target_id=target.strip() or None, run_id=run_id,
                since=since, until=until, limit=PAGE_SIZE,
            )  # fmt: skip
    filters: dict[str, Any] = {
        "actor": actor,
        "target": target,
        "run": run,
        "from": from_,
        "to": to,
    }
    return render(
        request, "audit/list.html", 422 if problems and not page.items else 200, active="audit",
        events=[view.event_dict(r) for r in page.items], next_cursor=page.next_cursor,
        problems=problems, filters=filters,
        next_query=urlencode({**{k: v for k, v in filters.items() if v}, "cursor": page.next_cursor})
        if page.next_cursor else "",
    )  # fmt: skip
