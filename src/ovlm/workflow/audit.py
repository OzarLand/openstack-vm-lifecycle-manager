"""Audit hook of the engine.

The ``audit`` module (E3-4) owns ``audit_event`` and ``audit.record()``. Until it is merged, the engine writes
through this small protocol, **inside the same transaction** as the change it records (data-model.md section 10).
The default sink only logs (``event=workflow_audit``), and only **after the transaction commits** (SRE-C-6): a
rolled-back effect (lock conflict at admission, a signal left pending, a crash before COMMIT) emits nothing. The
worker wires the real sink once E3-4 lands (reported as an open item). Tests use a recording sink to check "one audit event per effect".
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

from sqlalchemy import Connection, text
from sqlalchemy import event as sa_event

from ovlm.audit.allowlist import register_entity, snapshot

log = logging.getLogger("ovlm.workflow.audit")


@dataclass(frozen=True)
class AuditEvent:
    action: str
    target_type: str
    target_id: str
    run_id: str | None = None
    step_id: str | None = None
    actor_id: str | None = None
    principal_type: str = "system"
    result: str = "ok"
    after: dict[str, Any] = field(default_factory=dict)


class AuditSink(Protocol):
    def record(self, conn: Connection, event: AuditEvent) -> None: ...


class LogAuditSink:
    def record(self, conn: Connection, event: AuditEvent) -> None:
        """Emit the log line when ``conn``'s transaction commits; never for a rollback."""

        def _on_commit(_conn: Connection) -> None:
            self._emit(event)

        sa_event.listen(conn, "commit", _on_commit, once=True)

    @staticmethod
    def _emit(event: AuditEvent) -> None:
        log.info(
            "workflow audit",
            extra={
                "event": "workflow_audit",
                "action": event.action,
                "target_type": event.target_type,
                "target_id": event.target_id,
                "run_id": event.run_id,
                "step_id": event.step_id,
                "result": event.result,
            },
        )


# Fields the engine's events may carry into the append-only table (allowlist, never blocklist). The fencing token is
# deliberately absent: it authorises writes, so it stays out of an immutable log.
_ENGINE_FIELDS = [
    "step_key", "attempt", "state", "error_class", "worker_id", "previous_owner", "lock", "holder_run_id",
    "locks", "first_step", "locks_released", "reason", "signal_id", "outcome", "engine_result",
]  # fmt: skip
register_entity("workflow_step", _ENGINE_FIELDS)
register_entity("workflow_run", _ENGINE_FIELDS)

_AUDIT_LOG = logging.getLogger("ovlm.audit")

_RESULT = {"ok": "success", "succeeded": "success", "waiting": "success", "refused": "denied"}


class DbAuditSink:
    """Insert each engine event into ``audit_event`` in the engine's own transaction (AU-1).

    One row per effect: a claim, an outcome, a park, a run transition, a signal. Heartbeats and polling never call
    the sink, so the volume is a few rows per step attempt. ``after`` goes through the allowlist of its target type.
    After the transaction commits the row is also mirrored as ``event=audit`` (like ``ovlm.audit.record``) and as
    the ``workflow_audit`` line.
    """

    def __init__(self) -> None:
        self._log = LogAuditSink()

    def record(self, conn: Connection, event: AuditEvent) -> None:
        after = snapshot(event.target_type, {**event.after, "engine_result": event.result}) or {}
        result = _RESULT.get(event.result, "failure")
        actor = event.actor_id
        human = actor is not None
        row = conn.execute(
            text(
                "INSERT INTO audit_event (actor_id, principal_type, auth_method, action, target_type, target_id, "
                "after, result, run_id, step_id) VALUES (:actor, :ptype, :method, :action, :ttype, :tid, "
                "CAST(:after AS jsonb), :result, :run, :step) RETURNING id, ts"
            ),
            {
                "actor": actor,
                "ptype": "human" if human else "worker",
                "method": "signal" if human else "worker",
                "action": event.action,
                "ttype": event.target_type,
                "tid": event.target_id,
                "after": json.dumps(after),
                "result": result,
                "run": event.run_id,
                "step": event.step_id,
            },
        ).one()
        line = {
            "audit_id": row.id,
            "audit_ts": row.ts.isoformat(),
            "actor_id": str(actor) if actor else None,
            "principal_type": "human" if human else "worker",
            "auth_method": "signal" if human else "worker",
            "action": event.action,
            "target_type": event.target_type,
            "target_id": event.target_id,
            "after": after,
            "result": result,
            "run_id": event.run_id,
            "step_id": event.step_id,
        }

        def _on_commit(_conn: Connection) -> None:
            _AUDIT_LOG.info("audit", extra=line)

        sa_event.listen(conn, "commit", _on_commit, once=True)
        self._log.record(conn, event)
