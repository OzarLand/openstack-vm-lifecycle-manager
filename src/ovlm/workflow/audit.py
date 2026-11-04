"""Audit hook of the engine.

The ``audit`` module (E3-4) owns ``audit_event`` and ``audit.record()``. Until it is merged, the engine writes
through this small protocol, **inside the same transaction** as the change it records (data-model.md section 10).
The default sink only logs (``event=workflow_audit``); the worker wires the real sink once E3-4 lands (reported as
an open item). Tests use a recording sink to check "one audit event per effect".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

from sqlalchemy import Connection

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
