"""What a caller may see of the audit log (api-design.md 3.8, security-model.md section 8, SEC-R-31).

One function serves ``GET /api/v1/audit`` and the ``/audit`` page, so both apply the same rules:

* **Project scope.** The caller sees rows of the projects they may view (like the inventory routes). A caller with a
  global binding sees every row. A row of another project is simply absent: no 403, no count, no hint.
* **Action allowlist per role.** Authentication, token and user/role-management events are for a global admin only
  (:data:`ADMIN_ONLY_PREFIXES`). Everyone else, tokens included, never receives them, whatever the filters say.
* Rows are returned exactly as recorded (the fields were allowlisted when written; nothing is added or decoded).
* Cursor pagination, newest first; the cursor is the id of the last row of the previous page.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from ovlm.audit.service import AuditRow, list_events
from ovlm.auth.authz import Action, authorize, project_scope_of, visible_projects
from ovlm.auth.principal import GLOBAL, Principal

DEFAULT_PAGE = 50
MAX_PAGE = 200

#: Action prefixes only a global admin may read (SEC-R-31): login and step-up events, denials, API tokens, users and
#: their enrolment links, role bindings.
ADMIN_ONLY_PREFIXES: tuple[str, ...] = (
    "auth.",
    "authz.",
    "token.",
    "user.",
    "role_binding.",
    "role.",
)


class InvalidCursorError(ValueError):
    pass


@dataclass(frozen=True)
class AuditPage:
    items: list[AuditRow]
    next_cursor: str | None


def encode_cursor(last_id: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"id": last_id}).encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> int:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw)["id"]
    except (ValueError, TypeError, KeyError, binascii.Error):
        raise InvalidCursorError("malformed cursor") from None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise InvalidCursorError("malformed cursor")
    return value


def sees_admin_only(who: Principal) -> bool:
    """Only a human global admin reads the admin-only actions; project-scoped admins and tokens do not."""
    return who.is_human and authorize(who, "admin", GLOBAL)


def visible_events(
    session: Session,
    who: Principal,
    *,
    actor_id: UUID | None = None,
    target_id: str | None = None,
    run_id: UUID | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> AuditPage:
    """One page of the events ``who`` may see. Raises :class:`InvalidCursorError` for a bad cursor."""
    size = max(1, min(limit or DEFAULT_PAGE, MAX_PAGE))
    before_id = decode_cursor(cursor) if cursor else None
    projects = visible_projects(who, Action.AUDIT_VIEW)
    scopes = None if projects is None else [project_scope_of(p) for p in sorted(projects, key=str)]
    rows = list_events(
        session,
        actor_id=actor_id,
        target_id=target_id,
        run_trail=run_id,
        since=since,
        until=until,
        before_id=before_id,
        limit=size + 1,
        scopes=scopes,
        exclude_action_prefixes=() if sees_admin_only(who) else ADMIN_ONLY_PREFIXES,
    )
    more = len(rows) > size
    rows = rows[:size]
    return AuditPage(rows, encode_cursor(rows[-1].id) if more else None)


def event_dict(row: AuditRow) -> dict[str, Any]:
    """The JSON shape of one event: every recorded column, as recorded."""
    return {
        "id": row.id,
        "ts": row.ts.isoformat(),
        "actor_id": str(row.actor_id) if row.actor_id else None,
        "principal_type": row.principal_type,
        "auth_method": row.auth_method,
        "source_ip": row.source_ip,
        "project_scope": row.project_scope,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "before": row.before,
        "after": row.after,
        "result": row.result,
        "run_id": str(row.run_id) if row.run_id else None,
        "step_id": str(row.step_id) if row.step_id else None,
        "request_id": row.request_id,
        "authority_ref": row.authority_ref,
    }
