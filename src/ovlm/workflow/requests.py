"""Inserts the api (and the planning module) may make: a run in ``requested`` and a ``run_signal``.

These are the only workflow writes the ``ovlm_api`` role is granted (data-model.md section 12, SEC-R-1). They do
not import the engine and are safe to call from the api process.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from sqlalchemy import Connection, text

from ovlm.workflow.ids import new_id

SIGNAL_KINDS = frozenset(
    {"admit", "abort", "rollback", "revert", "retry_step", "mark_resolved", "probe", "discard"}
)


def request_run(
    conn: Connection,
    *,
    kind: str,
    strategy: str,
    strategy_version: str,
    subject: Mapping[str, Any] | None = None,
    service_id: str | None = None,
    renewal_plan_id: str | None = None,
    started_by: str | None = None,
) -> str:
    run_id = new_id()
    conn.execute(
        text(
            "INSERT INTO workflow_run (id, kind, strategy, strategy_version, state, subject, service_id, "
            "renewal_plan_id, started_by, started_at) VALUES (:id, :kind, :strategy, :version, 'requested', "
            "CAST(:subject AS jsonb), :service_id, :plan_id, :started_by, now())"
        ),
        {
            "id": run_id,
            "kind": kind,
            "strategy": strategy,
            "version": strategy_version,
            "subject": json.dumps(dict(subject or {})),
            "service_id": service_id,
            "plan_id": renewal_plan_id,
            "started_by": started_by,
        },
    )
    return run_id


def send_signal(
    conn: Connection,
    run_id: str,
    kind: str,
    *,
    actor_id: str | None = None,
    approval_id: str | None = None,
    payload: Mapping[str, Any] | None = None,
) -> str:
    if kind not in SIGNAL_KINDS:
        raise ValueError(f"unknown signal kind {kind!r}")
    sig_id = new_id()
    conn.execute(
        text(
            "INSERT INTO run_signal (id, run_id, kind, actor_id, approval_id, payload) "
            "VALUES (:id, :run_id, :kind, :actor_id, :approval_id, CAST(:payload AS jsonb))"
        ),
        {
            "id": sig_id,
            "run_id": run_id,
            "kind": kind,
            "actor_id": actor_id,
            "approval_id": approval_id,
            "payload": json.dumps(dict(payload or {})),
        },
    )
    return sig_id
