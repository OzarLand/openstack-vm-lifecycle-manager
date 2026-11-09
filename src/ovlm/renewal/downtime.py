"""Downtime intervals of a renewal run (``run_downtime``, renewal-workflow.md 3 "Downtime", roadmap P0-3).

A run can take the service down more than once: the window (W1 claim to W10 success, or to S9 when the window ends in
a restore) and, after a cutover, a revert (S2 to S9). Every interval is a row; the run's downtime is their sum.

* **Open** (:func:`open_interval`): only when no interval of the run is open, so a retry, a takeover or a W1 re-claim
  never opens a second one. ``window`` is opened in W1's fenced claim transaction, before the quiesce play. ``restore``
  is opened by S2: in its fenced transaction before the quiesce play on green, or, when S2 is skipped (the volume is
  not on an ACTIVE green: stateless profile, green already stopped), in S2's success commit, before S3 stops green.
  In an in-window restore the window interval is still open, so S2 opens nothing and the window interval runs on.
* **Close** (:func:`close_open`): in the fenced success commit of W10 (``verify_external``) and S9
  (``verify_external_old``). ``UPDATE ... WHERE ended_at IS NULL``: a commit replayed by a new attempt closes nothing
  twice.
* An interval left open (a parked run) is **ongoing**; a read never invents an end.

Each open/close writes an audit row in the same transaction and each close observes ``ovlm_renewal_downtime_seconds``
with the interval kind.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.renewal import metrics
from ovlm.workflow.ids import new_id

WINDOW = "window"
RESTORE = "restore"


def open_interval(c: Connection, run_id: str, *, kind: str, step_key: str) -> bool:
    """Open an interval unless one of the run is already open. Returns whether a row was inserted."""
    row = c.execute(
        text("INSERT INTO run_downtime (id, run_id, kind, started_at, started_by_step) "
             "SELECT :id, :r, :k, now(), :s WHERE NOT EXISTS "
             "(SELECT 1 FROM run_downtime WHERE run_id = :r AND ended_at IS NULL) "
             "ON CONFLICT (run_id) WHERE ended_at IS NULL DO NOTHING RETURNING id"),
        {"id": new_id(), "r": run_id, "k": kind, "s": step_key},
    ).first()  # fmt: skip
    if row is None:
        return False
    with Session(bind=c) as s:
        audit.record(
            s, action="renewal.downtime.started", target_type="renewal_run", target_id=run_id,
            principal_type="system", auth_method="none", run_id=UUID(run_id),
            after={"interval_kind": kind, "step_key": step_key},
        )  # fmt: skip
    return True


def close_open(c: Connection, run_id: str, *, step_key: str) -> list[tuple[str, float]]:
    """Close the run's open interval (if any): ``[(kind, seconds)]`` of what this call closed."""
    rows = c.execute(
        text("UPDATE run_downtime SET ended_at = now(), ended_by_step = :s WHERE run_id = :r AND ended_at IS NULL "
             "RETURNING kind, EXTRACT(EPOCH FROM ended_at - started_at)"),
        {"r": run_id, "s": step_key},
    ).all()  # fmt: skip
    closed = [(str(k), float(sec)) for k, sec in rows]
    for kind, seconds in closed:
        with Session(bind=c) as s:
            audit.record(
                s, action="renewal.downtime.ended", target_type="renewal_run", target_id=run_id,
                principal_type="system", auth_method="none", run_id=UUID(run_id),
                after={"interval_kind": kind, "step_key": step_key, "seconds": round(seconds, 3)},
            )  # fmt: skip
        metrics.DOWNTIME.labels(kind).observe(seconds)
    return closed


def intervals(c: Any, run_id: str) -> list[dict[str, Any]]:
    """The run's intervals, oldest first. ``seconds`` is the measured length of a closed interval and the elapsed
    time (DB clock) of the open one. ``c`` is a Connection or a Session."""
    rows = c.execute(
        text("SELECT kind, started_at, started_by_step, ended_at, ended_by_step, "
             "EXTRACT(EPOCH FROM COALESCE(ended_at, now()) - started_at) AS seconds "
             "FROM run_downtime WHERE run_id = :r ORDER BY started_at, id"),
        {"r": run_id},
    ).mappings().all()  # fmt: skip
    return [
        {
            "kind": r["kind"],
            "started_at": r["started_at"],
            "started_by_step": r["started_by_step"],
            "ended_at": r["ended_at"],
            "ended_by_step": r["ended_by_step"],
            "ongoing": r["ended_at"] is None,
            "seconds": float(r["seconds"]),
        }
        for r in rows
    ]


def from_run_columns(run: Mapping[str, Any], now: datetime) -> list[dict[str, Any]]:
    """Compatibility: a run whose first interval exists only in ``workflow_run.downtime_*`` (written before
    ``renewal_0003`` without a backfill, or by a hand-made row). Read as one ``window`` interval."""
    start, end = run.get("downtime_started_at"), run.get("downtime_ended_at")
    if start is None:
        return []
    return [{"kind": WINDOW, "started_at": start, "started_by_step": "quiesce_old", "ended_at": end,
             "ended_by_step": None, "ongoing": end is None,
             "seconds": max(0.0, ((end or now) - start).total_seconds())}]  # fmt: skip


def summary(items: Sequence[Mapping[str, Any]], *, terminal: bool) -> dict[str, Any]:
    """The run representation's ``downtime`` object (api-design.md). ``measured`` is false when no interval was
    recorded; ``total_seconds`` is then ``None`` (never 0). An open interval of a terminal run cannot be ongoing:
    its end was not measured, so it is excluded from the total and flagged ``end_measured: false``."""
    out: list[dict[str, Any]] = []
    total = 0.0
    ongoing = False
    unmeasured = False
    for it in items:
        row = dict(it)
        open_ = row["ended_at"] is None
        row["ongoing"] = open_ and not terminal
        row["end_measured"] = not open_ or not terminal
        if open_ and terminal:
            row["seconds"] = None
            unmeasured = True
        else:
            total += float(row["seconds"])
        ongoing = ongoing or row["ongoing"]
        out.append(row)
    return {
        "measured": bool(out),
        "intervals": out,
        "total_seconds": round(total, 3) if out else None,
        "ongoing": ongoing,
        "complete": bool(out) and not unmeasured,
    }
