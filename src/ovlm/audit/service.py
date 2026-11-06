"""``audit.record()``: insert in the caller's transaction, mirror to the log stream after commit.

The row is written in the same transaction as the change it records (a failed audit insert rolls the change back).
After the transaction commits, each row is emitted as an ``event=audit`` JSON log line so that a rewrite by a
database administrator is detectable against the log collector (security-model.md section 8, SEC-R-21). A rolled
back transaction emits nothing. Do not wrap ``record()`` in a SAVEPOINT that you may roll back alone: lines are
queued per Session and flushed on its commit.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import event, text
from sqlalchemy.orm import Session

from ovlm.audit.allowlist import snapshot_pair
from ovlm.observability.context import current_context

log = logging.getLogger("ovlm.audit")

PrincipalType = Literal["human", "token", "system", "worker"]
Result = Literal["success", "failure", "denied"]

_PENDING = "ovlm.audit.pending"
_COLUMNS = (
    "id, ts, actor_id, principal_type, auth_method, source_ip, project_scope, action, target_type, "
    "target_id, before, after, result, run_id, step_id, request_id, authority_ref"
)


@dataclass(frozen=True)
class AuditRow:
    id: int
    ts: datetime
    actor_id: UUID | None
    principal_type: str
    auth_method: str
    source_ip: str | None
    project_scope: str | None
    action: str
    target_type: str
    target_id: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    result: str
    run_id: UUID | None
    step_id: UUID | None
    request_id: str | None
    authority_ref: str | None


def _uuid_or_none(value: Any) -> UUID | None:
    if value is None:
        return None
    try:
        return value if isinstance(value, UUID) else UUID(str(value))
    except ValueError:
        return None


def record(
    session: Session,
    *,
    action: str,
    target_type: str,
    target_id: str | None = None,
    result: Result = "success",
    actor_id: UUID | None = None,
    principal_type: PrincipalType = "human",
    auth_method: str,
    source_ip: str | None = None,
    project_scope: str | None = None,
    before: Mapping[str, Any] | None = None,
    after: Mapping[str, Any] | None = None,
    run_id: UUID | None = None,
    step_id: UUID | None = None,
    request_id: str | None = None,
    authority_ref: str | None = None,
) -> int:
    """Append one audit row in ``session``'s transaction and return its id.

    ``before``/``after`` are filtered through the allowlist registered for ``target_type`` (an unregistered
    ``target_type`` with values raises). Correlation ids default to the current log context.
    """
    ctx = current_context()
    request_id = request_id or ctx.get("request_id")
    run_id = run_id or _uuid_or_none(ctx.get("run_id"))
    step_id = step_id or _uuid_or_none(ctx.get("step_id"))
    if before is not None or after is not None:
        before_f, after_f = snapshot_pair(target_type, before, after)
    else:
        before_f = after_f = None
    params = {
        "actor_id": actor_id,
        "principal_type": principal_type,
        "auth_method": auth_method,
        "source_ip": source_ip,
        "project_scope": project_scope,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "before": json.dumps(before_f) if before_f is not None else None,
        "after": json.dumps(after_f) if after_f is not None else None,
        "result": result,
        "run_id": run_id,
        "step_id": step_id,
        "request_id": request_id,
        "authority_ref": authority_ref,
    }
    row = session.execute(
        text(
            """
            INSERT INTO audit_event (actor_id, principal_type, auth_method, source_ip, project_scope, action,
                                     target_type, target_id, before, after, result, run_id, step_id,
                                     request_id, authority_ref)
            VALUES (:actor_id, :principal_type, :auth_method, :source_ip, :project_scope, :action,
                    :target_type, :target_id, CAST(:before AS jsonb), CAST(:after AS jsonb), :result,
                    :run_id, :step_id, :request_id, :authority_ref)
            RETURNING id, ts
            """
        ),
        params,
    ).one()
    mirror: dict[str, Any] = {
        "audit_id": row.id,
        "audit_ts": row.ts.isoformat(),
        "actor_id": str(actor_id) if actor_id else None,
        "principal_type": principal_type,
        "auth_method": auth_method,
        "source_ip": source_ip,
        "project_scope": project_scope,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "before": before_f,
        "after": after_f,
        "result": result,
        "run_id": str(run_id) if run_id else None,
        "step_id": str(step_id) if step_id else None,
        "authority_ref": authority_ref,
    }
    if request_id and "request_id" not in ctx:
        mirror["request_id"] = request_id
    session.info.setdefault(_PENDING, []).append(mirror)
    return int(row.id)


@event.listens_for(Session, "after_commit")
def _emit_after_commit(session: Session) -> None:
    for line in session.info.pop(_PENDING, []):
        log.info("audit", extra=line)


@event.listens_for(Session, "after_rollback")
def _drop_on_rollback(session: Session) -> None:
    session.info.pop(_PENDING, None)


_RUN_TRAIL = """(
    run_id = :trail_run
    OR step_id IN (SELECT id FROM workflow_step WHERE run_id = :trail_run)
    OR (target_type IN ('renewal_run', 'workflow_run') AND target_id = :trail_run_text)
    OR (target_type = 'workflow_step'
        AND target_id IN (SELECT CAST(id AS text) FROM workflow_step WHERE run_id = :trail_run))
    OR (target_type = 'approval'
        AND target_id IN (SELECT CAST(id AS text) FROM approval WHERE run_id = :trail_run))
)"""

# Rows the worker writes carry a run id but no project scope; the run's plan says which project they belong to.
_IN_SCOPES = """(
    project_scope = ANY(CAST(:scopes AS text[]))
    OR (project_scope IS NULL AND run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM workflow_run r JOIN renewal_plan p ON p.id = r.renewal_plan_id
        WHERE r.id = audit_event.run_id AND p.resolved ->> 'scope' = ANY(CAST(:scopes AS text[]))))
)"""


def list_events(
    session: Session,
    *,
    actor_id: UUID | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    run_id: UUID | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    actions: Sequence[str] | None = None,
    before_id: int | None = None,
    limit: int = 100,
    run_trail: UUID | None = None,
    scopes: Collection[str] | None = None,
    exclude_action_prefixes: Sequence[str] = (),
) -> list[AuditRow]:
    """Newest first. Which roles see which actions is decided by the caller (``ovlm.audit.view``), which passes:

    * ``run_trail``: a run's whole trail: rows of the run, of its steps, and of the objects that are its steps'
      targets or its approvals (see ``_RUN_TRAIL``).
    * ``scopes``: ``None`` = every row; otherwise only rows whose ``project_scope`` is in ``scopes``, plus rows
      without a scope that belong to a run whose plan is in one of ``scopes`` (the worker records those).
    * ``exclude_action_prefixes``: actions starting with any of these are left out.
    """
    clauses = ["TRUE"]
    params: dict[str, Any] = {"limit": max(1, min(limit, 1000))}
    for col, val in (
        ("actor_id", actor_id),
        ("target_type", target_type),
        ("target_id", target_id),
        ("run_id", run_id),
    ):
        if val is not None:
            clauses.append(f"{col} = :{col}")
            params[col] = val
    if since is not None:
        clauses.append("ts >= :since")
        params["since"] = since
    if until is not None:
        clauses.append("ts < :until")
        params["until"] = until
    if actions:
        clauses.append("action = ANY(:actions)")
        params["actions"] = list(actions)
    if before_id is not None:
        clauses.append("id < :before_id")
        params["before_id"] = before_id
    if run_trail is not None:
        clauses.append(_RUN_TRAIL)
        params["trail_run"] = run_trail
        params["trail_run_text"] = str(run_trail)
    if scopes is not None:
        clauses.append(_IN_SCOPES)
        params["scopes"] = list(scopes)
    if exclude_action_prefixes:
        clauses.append(
            "NOT EXISTS (SELECT 1 FROM unnest(CAST(:xprefixes AS text[])) AS p(v) "
            "WHERE starts_with(audit_event.action, p.v))"
        )
        params["xprefixes"] = list(exclude_action_prefixes)
    rows = session.execute(
        text(
            f"SELECT {_COLUMNS} FROM audit_event WHERE {' AND '.join(clauses)} "  # noqa: S608
            "ORDER BY id DESC LIMIT :limit"
        ),
        params,
    ).all()
    return [AuditRow(**r._mapping) for r in rows]
