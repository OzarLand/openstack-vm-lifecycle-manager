"""Ownership ledger (``owned_resource``, ADR-0005), the DB-backed ownership registry, fenced strategy writes.

:class:`DbOwnershipRegistry` answers the ownership guard from the database on **every** call (no cache): blue, the
data volume and the FIP from the plan (``preexisting``), green from this run's ledger (``created``). ``deletable`` is
true only while the run's open step is the one allowed to delete: ``discard_green`` for green (operator rollback,
abort or discard, all with TC), ``retire_old`` for blue (G3). A registration removed mid-run takes effect at the next
call.

:func:`fenced_write` is how a step writes strategy rows **during** an attempt (the ledger ``intended`` row before
create, ``downtime_started_at`` and the window interval in the W1 claim transaction, the restore interval before S2's
quiesce play): local fence check first, then, in one transaction, a
row lock on the step guarded by ``attempt`` and ``state='running'`` (a takeover increments ``attempt``, so a stale
attempt matches nothing), then the write.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Connection, Engine, RowMapping, text

from ovlm.openstack.ownership import Registration, ResourceKind
from ovlm.workflow.contract import StepContext
from ovlm.workflow.fence import FencedCommitRejected
from ovlm.workflow.ids import new_id


def plan_resolved(conn: Connection, run_id: str) -> Mapping[str, Any]:
    row = conn.execute(
        text(
            "SELECT p.resolved FROM workflow_run r JOIN renewal_plan p ON p.id = r.renewal_plan_id WHERE r.id = :r"
        ),
        {"r": run_id},
    ).first()
    if row is None:
        raise LookupError(f"run {run_id} has no renewal plan")
    resolved: Mapping[str, Any] = row[0]
    return resolved


def green_row(conn: Connection, run_id: str) -> RowMapping | None:
    """The live (``intended``/``present``) green ledger row of the run, else the latest one."""
    return (
        conn.execute(
            text(
                "SELECT * FROM owned_resource WHERE run_id = :r AND role = 'green' "
                "ORDER BY (state IN ('intended', 'present')) DESC, created_at DESC LIMIT 1"
            ),
            {"r": run_id},
        )
        .mappings()
        .first()
    )


def snapshot_row(conn: Connection, run_id: str) -> RowMapping | None:
    return (
        conn.execute(
            text(
                "SELECT * FROM owned_resource WHERE run_id = :r AND role = 'snapshot' "
                "ORDER BY created_at DESC LIMIT 1"
            ),
            {"r": run_id},
        )
        .mappings()
        .first()
    )


def open_step_key(conn: Connection, run_id: str) -> str | None:
    return conn.execute(
        text(
            "SELECT step_key FROM workflow_step WHERE run_id = :r "
            "AND state IN ('ready', 'running', 'waiting', 'needs_human')"
        ),
        {"r": run_id},
    ).scalar()


class DbOwnershipRegistry:
    def __init__(self, engine: Engine, run_id: str) -> None:
        self._engine = engine
        self._run_id = run_id

    @property
    def run_id(self) -> str:
        return self._run_id

    def lookup(self, kind: ResourceKind, openstack_id: str) -> Registration | None:
        with self._engine.connect() as c:
            resolved = plan_resolved(c, self._run_id)
            step = open_step_key(c, self._run_id)
            if kind is ResourceKind.SERVER:
                if openstack_id == resolved["blue"]["server_id"]:
                    return Registration(
                        kind, openstack_id, "preexisting", deletable=step == "retire_old"
                    )
                g = green_row(c, self._run_id)
                if (
                    g is not None
                    and g["openstack_id"] == openstack_id
                    and g["state"] in ("intended", "present")
                ):
                    return Registration(
                        kind, openstack_id, "created", deletable=step == "discard_green"
                    )
                return None
            if kind is ResourceKind.VOLUME:
                dv = resolved.get("data_volume") or {}
                return (
                    Registration(kind, openstack_id, "preexisting")
                    if dv.get("volume_id") == openstack_id
                    else None
                )
            if kind is ResourceKind.FLOATING_IP and resolved["floating_ip"]["id"] == openstack_id:
                return Registration(kind, openstack_id, "preexisting")
            return None

    def is_intended_server_name(self, name: str) -> bool:
        with self._engine.connect() as c:
            g = green_row(c, self._run_id)
        return (
            g is not None and g["state"] in ("intended", "present") and g["intended_name"] == name
        )


@contextmanager
def fenced_tx(engine: Engine, ctx: StepContext) -> Iterator[Connection]:
    """One transaction guarded by the attempt (see the module docstring): several strategy writes that must commit
    together (W1: ``downtime_started_at`` and the window interval)."""
    ctx.gate("commit:strategy")
    with engine.begin() as c:
        owned = c.execute(
            text(
                "SELECT 1 FROM workflow_step WHERE id = :s AND attempt = :a AND state = 'running' FOR UPDATE"
            ),
            {"s": ctx.step.id, "a": ctx.attempt},
        ).first()
        if owned is None:
            raise FencedCommitRejected(
                f"strategy write of step {ctx.step.id} attempt {ctx.attempt}: not the owner"
            )
        yield c


def fenced_write(engine: Engine, ctx: StepContext, sql: str, params: Mapping[str, Any]) -> int:
    """Write strategy rows during an attempt, guarded by the attempt (see the module docstring)."""
    with fenced_tx(engine, ctx) as c:
        return int(c.execute(text(sql), dict(params)).rowcount)


def ledger_intend(engine: Engine, ctx: StepContext, *, role: str, rtype: str, name: str) -> None:
    """Commit the ``intended`` row before the create (ADR-0005). Idempotent per (run, role) while live."""
    fenced_write(
        engine,
        ctx,
        "INSERT INTO owned_resource (id, run_id, resource_type, role, intended_name, state) "
        "SELECT :id, :r, :t, :role, :n, 'intended' WHERE NOT EXISTS (SELECT 1 FROM owned_resource "
        "WHERE run_id = :r AND role = :role AND state IN ('intended', 'present'))",
        {"id": new_id(), "r": ctx.run.id, "t": rtype, "role": role, "n": name},
    )


def ledger_present(
    engine: Engine,
    ctx: StepContext,
    *,
    role: str,
    openstack_id: str,
    detail: Mapping[str, Any] | None = None,
) -> None:
    fenced_write(
        engine,
        ctx,
        "UPDATE owned_resource SET openstack_id = :o, state = 'present', updated_at = now(), "
        "detail = detail || CAST(:d AS jsonb) WHERE run_id = :r AND role = :role AND state IN ('intended', 'present')",
        {"o": openstack_id, "r": ctx.run.id, "role": role, "d": json.dumps(dict(detail or {}))},
    )


def ledger_detail(
    engine: Engine, ctx: StepContext, *, role: str, detail: Mapping[str, Any]
) -> None:
    fenced_write(
        engine,
        ctx,
        "UPDATE owned_resource SET detail = detail || CAST(:d AS jsonb), updated_at = now() "
        "WHERE run_id = :r AND role = :role AND state IN ('intended', 'present')",
        {"r": ctx.run.id, "role": role, "d": json.dumps(dict(detail))},
    )


def ledger_state(engine: Engine, ctx: StepContext, *, role: str, state: str) -> None:
    fenced_write(
        engine,
        ctx,
        "UPDATE owned_resource SET state = :s, updated_at = now() WHERE run_id = :r AND role = :role "
        "AND state IN ('intended', 'present')",
        {"s": state, "r": ctx.run.id, "role": role},
    )
