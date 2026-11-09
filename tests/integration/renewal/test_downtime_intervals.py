"""Every downtime interval of a run (roadmap P0-3, lab finding AC, Felcloud 2026-11-08).

Before ``renewal_0003`` a run recorded only its first outage (``workflow_run.downtime_started_at`` / ``_ended_at``):
a revert after the cutover took the service down again (S2 quiesces green, S9 proves blue serves through the FIP)
and OVLM recorded nothing; only the external probe measured it. Here:

* cutover then revert before G3: two intervals, ``window`` (W1 -> W10) and ``restore`` (S2 -> S9);
* W1 parked then rollback: one ``window`` interval, W1 -> S9 (the restore does not open a second one);
* a worker crash or takeover inside an interval neither duplicates nor loses it; a parked restore shows it ongoing;
* the api run representation carries the intervals and their total; the table is append-only (close once).
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from ovlm.renewal import service
from ovlm.workflow import crashpoint
from ovlm.workflow.crashpoint import CrashPlan
from tests.integration.renewal.conftest import World, explain, to_cutover
from tests.integration.renewal.test_failures import parked, restored


def intervals(w: World) -> list[Any]:
    return w.q("SELECT * FROM run_downtime WHERE run_id = :r ORDER BY started_at, id", r=w.run_id)


def api_downtime(w: World) -> dict[str, Any]:
    with Session(bind=w.api) as s:
        body: dict[str, Any] = service.run_body(s, w.run_id)["downtime"]
    return body


def step_window(w: World, key: str) -> tuple[Any, Any]:
    """(created_at of the first attempt, finished_at) of a step: the interval must lie inside its steps."""
    rows = w.q(
        "SELECT min(a.started_at) AS s, max(st.finished_at) AS f FROM workflow_step st "
        "JOIN workflow_step_attempt a ON a.step_id = st.id WHERE st.run_id = :r AND st.step_key = :k",
        r=w.run_id,
        k=key,
    )
    return rows[0]["s"], rows[0]["f"]


def test_cutover_then_revert_before_g3_records_two_intervals(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    first = intervals(w)
    assert [(i["kind"], i["started_by_step"], i["ended_by_step"]) for i in first] == [
        ("window", "quiesce_old", "verify_external")
    ], first
    run = w.run()
    # the run columns stay the first interval (budget, REN-1 seal, retention timer)
    assert first[0]["started_at"] == run["downtime_started_at"]
    assert first[0]["ended_at"] == run["downtime_ended_at"]

    w.signal("revert", tc=w.blue_tc())
    w.drive()
    restored(w)
    rows = intervals(w)
    assert [(i["kind"], i["started_by_step"], i["ended_by_step"]) for i in rows] == [
        ("window", "quiesce_old", "verify_external"),
        ("restore", "quiesce_green", "verify_external_old"),
    ], rows
    window, restore = rows
    assert window == first[0]  # closing the second never touches the first
    assert (
        restore["started_at"] >= window["ended_at"] and restore["ended_at"] >= restore["started_at"]
    )
    # the restore interval starts before S2's quiesce play on green and ends in S9's success commit
    s2_start, _ = step_window(w, "quiesce_green")
    _, s9_end = step_window(w, "verify_external_old")
    assert s2_start <= restore["started_at"] and restore["ended_at"] <= s9_end
    # run columns unchanged by the revert
    assert w.run()["downtime_ended_at"] == window["ended_at"]

    body = api_downtime(w)
    assert body["measured"] and body["complete"] and not body["ongoing"]
    assert [i["kind"] for i in body["intervals"]] == ["window", "restore"]
    expected = sum((i["ended_at"] - i["started_at"]).total_seconds() for i in rows)
    assert body["total_seconds"] == pytest.approx(expected, abs=0.002)
    assert body["total_seconds"] > body["intervals"][0]["seconds"]
    acts = w.audit_actions()
    assert acts.count("renewal.downtime.started") == 2 and acts.count("renewal.downtime.ended") == 2


def test_w1_park_then_rollback_is_one_window_interval_ended_by_s9(world: World) -> None:
    w = world
    w.guest.failures["quiesce"] = ["retryable"]
    to_cutover(w)
    w.drive()
    parked(w, "quiesce_old_failed")
    rows = intervals(w)
    assert len(rows) == 1 and rows[0]["kind"] == "window" and rows[0]["ended_at"] is None
    body = api_downtime(w)
    assert body["ongoing"] and body["intervals"][0]["ongoing"] and body["total_seconds"] >= 0

    w.signal("rollback", tc=w.blue_tc())
    w.drive()
    restored(w)
    rows = intervals(w)
    assert [(i["kind"], i["started_by_step"], i["ended_by_step"]) for i in rows] == [
        ("window", "quiesce_old", "verify_external_old")
    ], rows
    assert rows[0]["ended_at"] == w.run()["downtime_ended_at"]
    body = api_downtime(w)
    assert not body["ongoing"] and len(body["intervals"]) == 1


def test_restore_crash_inside_the_interval_neither_duplicates_nor_loses_it(world: World) -> None:
    """The worker dies right after S2's quiesce play on green (restore interval open). The takeover parks the data
    phase; the interval stays open and reads as ongoing. retry-step re-runs S2 (its open is a no-op) and S9 closes the
    same interval once."""
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    crashpoint.install(CrashPlan(target="quiesce_green.after_act", mode="raise"))
    w.signal("revert", tc=w.blue_tc())
    w.drive()
    assert w.crashes == 1
    parked(w, "data_phase_interrupted")
    rows = intervals(w)
    assert [(i["kind"], i["ended_at"]) for i in rows][1:] == [("restore", None)], rows
    opened = rows[1]["started_at"]
    body = api_downtime(w)
    assert (
        body["ongoing"] and body["intervals"][1]["ongoing"] and body["intervals"][1]["seconds"] >= 0
    )

    w.signal("retry_step", tc=w.blue_tc())
    w.drive()
    restored(w)
    rows = intervals(w)
    assert [i["kind"] for i in rows] == ["window", "restore"], rows
    assert rows[1]["started_at"] == opened and rows[1]["ended_by_step"] == "verify_external_old"


@pytest.mark.parametrize(
    ("step", "point"),
    [
        ("verify_external", "after_verify_before_commit"),
        ("verify_external_old", "after_verify_before_commit"),
        ("stop_green", "after_act"),
        ("quiesce_old", "after_commit"),
    ],
)
def test_crash_at_an_interval_boundary_keeps_exactly_one_row_per_interval(
    world: World, step: str, point: str
) -> None:
    w = world
    to_cutover(w)
    if step in ("verify_external", "quiesce_old"):
        crashpoint.install(CrashPlan(target=f"{step}.{point}", mode="raise"))
    w.drive(until="await_retirement")
    if step not in ("verify_external", "quiesce_old"):
        crashpoint.install(CrashPlan(target=f"{step}.{point}", mode="raise"))
    w.signal("revert", tc=w.blue_tc())
    w.drive()
    assert w.crashes == 1, explain(w)
    restored(w)
    rows = intervals(w)
    assert [(i["kind"], i["ended_by_step"]) for i in rows] == [
        ("window", "verify_external"),
        ("restore", "verify_external_old"),
    ], rows


def test_stateless_revert_opens_the_restore_interval_when_s2_is_skipped(
    world_factory: Any,
) -> None:
    """No data volume: S2 has nothing to quiesce and is skipped, so the restore interval opens in S2's success
    commit, before S3 stops green (the service is still up on green until then)."""
    w = world_factory()
    w.x("UPDATE renewal_plan SET resolved = jsonb_set(jsonb_set(resolved, '{data_volume}', 'null'), '{stateless}', "
        "'true')")  # fmt: skip
    from ovlm.renewal.plans import load_facts

    with w.admin.connect() as c:
        h = load_facts(c, w.ids["plan"]).recomputed_hash
    w.x("UPDATE renewal_plan SET plan_hash = :h", h=h)
    w.x("UPDATE approval SET bound_hash = :h", h=h)
    w.guest.volume_id = None
    to_cutover(w)
    w.drive(until="await_retirement")
    w.signal("revert", tc=w.blue_tc())
    w.drive()
    s2 = next(s for s in w.steps() if s["step_key"] == "quiesce_green")
    assert s2["state"] == "succeeded" and "skipped" in s2["evidence"], explain(w)
    rows = intervals(w)
    assert [(i["kind"], i["started_by_step"], i["ended_by_step"]) for i in rows] == [
        ("window", "quiesce_old", "verify_external"),
        ("restore", "quiesce_green", "verify_external_old"),
    ], rows
    s3_start, _ = step_window(w, "stop_green")
    assert rows[1]["started_at"] <= s3_start


def test_run_downtime_is_close_once_and_never_deleted(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    rid = intervals(w)[0]["id"]
    # the worker may not rewrite a closed interval
    with w.worker.begin() as c, pytest.raises(DBAPIError):
        c.execute(text("UPDATE run_downtime SET ended_at = now() WHERE id = :i"), {"i": rid})
    with w.worker.begin() as c, pytest.raises(DBAPIError):
        c.execute(text("DELETE FROM run_downtime WHERE id = :i"), {"i": rid})
    with w.admin.begin() as c, pytest.raises(DBAPIError):  # not even the owner
        c.execute(text("DELETE FROM run_downtime WHERE id = :i"), {"i": rid})
    with w.api.begin() as c, pytest.raises(DBAPIError):  # the api only reads
        c.execute(
            text(
                "INSERT INTO run_downtime (id, run_id, kind, started_at, started_by_step) "
                "VALUES (gen_random_uuid(), :r, 'restore', now(), 'x')"
            ),
            {"r": w.run_id},
        )
    assert len(intervals(w)) == 1
