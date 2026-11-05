"""Inventory sync requests: the api's side (api-design.md 3.2) and the periodic scheduler's.

Asking for a sync inserts a ``workflow_run`` of kind ``inventory_sync`` in ``requested`` (the one workflow write the
``ovlm_api`` role has, SEC-R-1); the worker's definition (:mod:`ovlm.inventory.job`) does the sync with the project's
read credential. Nothing here imports OpenStack or the credential store: the api process may import this module.

**One sync per project connection at a time.** While a sync run of a connection is ``requested`` or ``running``,
no other one is created: the api answers 409 with the existing run, the periodic job skips the connection. Both
serialise on the same transaction-scoped advisory lock, so a click and the scheduler cannot both create one.
Transactions belong to the caller.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import Connection, bindparam, text

from ovlm.workflow.requests import request_run

KIND = "inventory_sync"
STRATEGY = "inventory_sync"
STRATEGY_VERSION = "1"
#: The periodic job that enqueues one sync per eligible connection (a single-step run of its own).
SCHEDULE_KIND = "inventory_sync_schedule"
SCHEDULE_STRATEGY = "inventory_sync_schedule"
TERMINAL = ("rejected", "cancelled", "failed", "completed", "rolled_back")


def _lock(conn: Connection, project_connection_id: UUID | str) -> None:
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
        {"k": f"inventory_sync:{UUID(str(project_connection_id))}"},
    )


def _run_dict(r: Any) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "state": r.state,
        "requested_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "end_reason": r.end_reason,
        "origin": (r.subject or {}).get("origin"),
    }


#: Why a run ended: the engine's ``end_reason``, else the failing step's recorded reason (a fatal step failure).
_COLS = (
    "id, state, started_at, finished_at, subject, COALESCE(end_reason, (SELECT s.error->>'reason' FROM "
    "workflow_step s WHERE s.run_id = workflow_run.id AND s.error IS NOT NULL ORDER BY s.seq DESC LIMIT 1)) "
    "AS end_reason"
)


def pending_run(conn: Connection, project_connection_id: UUID | str) -> dict[str, Any] | None:
    """The non-terminal sync run of this connection (``requested`` or ``running``), if any."""
    row = conn.execute(
        text(
            f"SELECT {_COLS} FROM workflow_run WHERE kind = :k "  # noqa: S608 - fixed column list
            "AND subject->>'project_connection_id' = :p AND state NOT IN :t "
            "ORDER BY started_at DESC, id DESC LIMIT 1"
        ).bindparams(bindparam("t", expanding=True)),
        {"k": KIND, "p": str(UUID(str(project_connection_id))), "t": list(TERMINAL)},
    ).first()
    return _run_dict(row) if row else None


def recent_runs(
    conn: Connection, project_connection_id: UUID | str, *, limit: int = 10
) -> list[dict[str, Any]]:
    """Newest first: what is queued or running, and why a recent run ended (credential refused, ...)."""
    rows = conn.execute(
        text(
            f"SELECT {_COLS} FROM workflow_run WHERE kind = :k "  # noqa: S608 - fixed column list
            "AND subject->>'project_connection_id' = :p ORDER BY started_at DESC, id DESC LIMIT :n"
        ),
        {"k": KIND, "p": str(UUID(str(project_connection_id))), "n": limit},
    ).all()
    return [_run_dict(r) for r in rows]


def request_sync(
    conn: Connection,
    project_connection_id: UUID | str,
    *,
    requested_by: UUID | str | None,
    origin: str = "api",
) -> tuple[dict[str, Any], bool]:
    """Queue a sync of one connection. Returns ``(run, created)``; ``created`` is false when a sync of this
    connection is already queued or running (that run is returned)."""
    pc = str(UUID(str(project_connection_id)))
    _lock(conn, pc)
    existing = pending_run(conn, pc)
    if existing:
        return existing, False
    run_id = request_run(
        conn, kind=KIND, strategy=STRATEGY, strategy_version=STRATEGY_VERSION,
        subject={"project_connection_id": pc, "origin": origin},
        started_by=str(requested_by) if requested_by else None,
    )  # fmt: skip
    row = conn.execute(
        text(f"SELECT {_COLS} FROM workflow_run WHERE id = :i"),  # noqa: S608 - fixed column list
        {"i": run_id},
    ).one()
    return _run_dict(row), True


def eligible_connections(conn: Connection) -> list[str]:
    """Enabled connections whose active read credential passed its last validation (the periodic job's set).
    Expiry and endpoint binding are checked again by the worker when the sync runs."""
    rows = conn.execute(
        text(
            "SELECT p.id FROM project_connection p JOIN credential_ref r ON r.project_connection_id = p.id "
            "WHERE p.enabled AND r.kind = 'os_read' AND r.state = 'active' "
            "AND COALESCE((r.validation_result->>'ok')::boolean, false) "
            "AND LEAST(r.expires_at, r.verified_expires_at) > now() "  # LEAST ignores NULL
            "ORDER BY p.id"
        )
    ).all()
    return [str(r.id) for r in rows]
