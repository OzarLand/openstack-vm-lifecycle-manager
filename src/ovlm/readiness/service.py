"""Readiness for the api: request an assessment, read results, the check catalogue (api-design.md section 3.5).

The api never runs a check and never calls OpenStack: requesting an assessment inserts a ``workflow_run`` in
``requested`` (the one workflow write ``ovlm_api`` has) and the worker's ``readiness`` definition does the rest.
Transactions belong to the caller.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import and_, bindparam, or_, select, text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.inventory.service import Page, clamp_limit, decode_cursor, encode_cursor
from ovlm.readiness.checks import catalogue as check_catalogue
from ovlm.readiness.tables import check_result, readiness_assessment
from ovlm.workflow.requests import request_run

# The request is audited by what was asked, never by the assessment's contents. Registered here because the REST
# route and the UI page both record it.
audit.register_entity(
    "readiness_request", ["managed_vm_id", "run_id", "already_pending", "run_repo_code_on_live_vm"]
)

KIND = "readiness"
STRATEGY = "readiness"
STRATEGY_VERSION = "1"
_TERMINAL = ("rejected", "cancelled", "failed", "completed", "rolled_back")


def catalogue() -> list[dict[str, Any]]:
    return check_catalogue()


def pending_run(session: Session, managed_vm_id: UUID) -> dict[str, Any] | None:
    """The newest non-terminal ``readiness`` run for this VM, if any."""
    row = session.execute(
        text(
            "SELECT id, state, started_at FROM workflow_run WHERE kind = :kind "
            "AND subject->>'managed_vm_id' = :vm AND state NOT IN :terminal "
            "ORDER BY started_at DESC, id DESC LIMIT 1"
        ).bindparams(bindparam("terminal", expanding=True)),
        {"kind": KIND, "vm": str(managed_vm_id), "terminal": list(_TERMINAL)},
    ).first()
    return _run_dict(row) if row else None


def _run_dict(r: Any) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "state": r.state,
        "requested_at": r.started_at.isoformat() if r.started_at else None,
    }


def runs_of(session: Session, managed_vm_id: UUID, *, limit: int = 5) -> list[dict[str, Any]]:
    """Recent runs, newest first, so a caller can show "requested", "running" or why one did not finish."""
    rows = session.execute(
        text(
            "SELECT id, state, started_at FROM workflow_run WHERE kind = :kind "
            "AND subject->>'managed_vm_id' = :vm ORDER BY started_at DESC, id DESC LIMIT :n"
        ),
        {"kind": KIND, "vm": str(managed_vm_id), "n": limit},
    ).all()
    return [_run_dict(r) for r in rows]


def request_assessment(
    session: Session, managed_vm: dict[str, Any], *, requested_by: UUID | None
) -> tuple[dict[str, Any], bool]:
    """Ask the worker for an assessment. Returns ``(run, created)``: while a run for this VM is still waiting or
    running, that run is returned (``created`` false) instead of piling up another one."""
    vm_id = UUID(managed_vm["id"])
    # Serialise concurrent requests for the same VM so two clicks cannot both create a run.
    session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"readiness:{vm_id}"})
    existing = pending_run(session, vm_id)
    if existing:
        return existing, False
    run_id = request_run(
        session.connection(), kind=KIND, strategy=STRATEGY, strategy_version=STRATEGY_VERSION,
        subject={"managed_vm_id": str(vm_id), "run_repo_code_on_live_vm": False},
        service_id=managed_vm["service_id"], started_by=str(requested_by) if requested_by else None,
    )  # fmt: skip
    row = session.execute(
        text("SELECT id, state, started_at FROM workflow_run WHERE id = :id"), {"id": run_id}
    ).one()
    return _run_dict(row), True


def _assessment_dict(r: Any) -> dict[str, Any]:
    return {
        "id": str(r.id), "managed_vm_id": str(r.managed_vm_id),
        "profile_version_id": str(r.profile_version_id) if r.profile_version_id else None,
        "observed_server_revision_id": str(r.observed_server_revision_id) if r.observed_server_revision_id else None,
        "level": r.level, "summary": r.summary,
        "requested_by": str(r.requested_by) if r.requested_by else None,
        "workflow_run_id": str(r.workflow_run_id), "live_code_run": r.live_code_run,
        "created_at": r.created_at.isoformat(),
    }  # fmt: skip


def _check_dict(r: Any) -> dict[str, Any]:
    return {
        "key": r.check_key, "version": r.check_version, "category": r.category, "result": r.result,
        "severity": r.severity, "evidence": r.evidence, "recommendation": r.recommendation,
    }  # fmt: skip


def get_assessment(session: Session, assessment_id: UUID) -> dict[str, Any] | None:
    row = session.execute(
        select(readiness_assessment).where(readiness_assessment.c.id == assessment_id)
    ).first()
    if row is None:
        return None
    checks = [
        _check_dict(c)
        for c in session.execute(
            select(check_result)
            .where(check_result.c.assessment_id == assessment_id)
            .order_by(check_result.c.seq)
        )
    ]
    out = _assessment_dict(row)
    out["input_snapshot"] = row.input_snapshot
    out["checks"] = checks
    out["blockers"] = [
        c for c in checks if c["severity"] == "blocker" and c["result"] in ("fail", "unknown")
    ]
    out["recommendations"] = [
        {"check": c["key"], "severity": c["severity"], "text": c["recommendation"]}
        for c in checks
        if c["recommendation"] and c["result"] in ("fail", "unknown")
    ]
    return out


def latest_assessment(session: Session, managed_vm_id: UUID) -> dict[str, Any] | None:
    ra = readiness_assessment
    row = session.execute(
        select(ra.c.id)
        .where(ra.c.managed_vm_id == managed_vm_id)
        .order_by(ra.c.created_at.desc(), ra.c.id.desc())
        .limit(1)
    ).first()
    return get_assessment(session, row.id) if row else None


def list_assessments(
    session: Session, managed_vm_id: UUID, *, limit: int | None = None, cursor: str | None = None
) -> Page:
    """Newest first, without checks or snapshot (``GET /assessments/{id}`` has them)."""
    ra = readiness_assessment
    n = clamp_limit(limit)
    stmt = select(ra).where(ra.c.managed_vm_id == managed_vm_id)
    if cursor:
        ts, rid = decode_cursor(cursor)
        stmt = stmt.where(or_(ra.c.created_at < ts, and_(ra.c.created_at == ts, ra.c.id < rid)))
    rows = list(session.execute(stmt.order_by(ra.c.created_at.desc(), ra.c.id.desc()).limit(n + 1)))
    more = len(rows) > n
    rows = rows[:n]
    return Page(
        [_assessment_dict(r) for r in rows],
        encode_cursor(rows[-1].created_at, rows[-1].id) if more else None,
    )
