"""Worker liveness from ``worker_heartbeat`` (SRE-C-10).

Every worker upserts its row each loop iteration (``WorkflowEngine.beat_worker``) and sweeps rows not seen for
``SWEEP_AFTER_BEATS`` intervals (``WorkflowEngine.sweep_worker_rows``). Liveness is defined on *recent* rows only:
"at least one row younger than ``LIVE_WORKER_BEATS`` x ``worker.heartbeat_interval``". Never use ``max()`` over all
rows or the mere existence of a row: a dead worker's row would satisfy it until swept.
"""

from __future__ import annotations

from sqlalchemy import Connection, text

#: A worker is live if its row was updated within this many heartbeat intervals.
LIVE_WORKER_BEATS = 3
#: Rows older than this many heartbeat intervals are deleted by the sweeper.
SWEEP_AFTER_BEATS = 20


def count_live_workers(conn: Connection, max_age: float, *, include_draining: bool = False) -> int:
    """Workers seen within ``max_age`` seconds (DB clock). Draining workers are excluded by default."""
    return int(
        conn.execute(
            text(
                "SELECT count(*) FROM worker_heartbeat "
                "WHERE last_seen_at >= now() - make_interval(secs => :age) AND (:drain OR NOT draining)"
            ),
            {"age": max_age, "drain": include_draining},
        ).scalar_one()
    )
