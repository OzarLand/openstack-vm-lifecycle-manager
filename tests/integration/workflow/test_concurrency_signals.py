"""Concurrency, resource locks, signals and abort (WF-10, WF-11, WF-16, SRE-R-24), metrics, scheduler and the
worker main loop, against a real PostgreSQL."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import pytest

from ovlm.config import Settings
from ovlm.worker.main import Worker
from ovlm.workflow import crashpoint
from ovlm.workflow import metrics as m
from ovlm.workflow.crashpoint import CrashPlan, SimulatedCrash
from ovlm.workflow.engine import EngineConfig
from ovlm.workflow.registry import PeriodicJob
from tests.integration.workflow.conftest import TEST_CONFIG, RecordingAudit, WfDb, drive
from tests.integration.workflow.dummy import BLOCKERS, plan_step


def _race(n: int, fn: Callable[[int], Any]) -> list[Any]:
    barrier = threading.Barrier(n)
    results: list[Any] = [None] * n
    errors: list[BaseException] = []

    def run(i: int) -> None:
        barrier.wait()
        try:
            results[i] = fn(i)
        except BaseException as exc:  # noqa: BLE001 - collected and re-raised below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    if errors:
        raise errors[0]
    return results


# ---- WF-10 duplicate delivery -------------------------------------------------------------------------------


def test_wf10_two_workers_racing_for_one_step_one_claimant(wf: WfDb) -> None:
    engines = [wf.make_engine() for _ in range(4)]
    for round_ in range(10):
        run_id = wf.request([plan_step("human", res=f"h{round_}")])
        engines[0].admit_pending()
        claims = _race(4, lambda i: engines[i].claim(5))
        assert sum(len(c) for c in claims) == 1, claims
        (winner,) = [c for c in claims if c]
        assert winner[0].run.id == run_id
        engines[0].execute(winner[0])  # parks waiting-for-signal: frees the slot for the next round


def test_wf10_duplicate_abort_has_one_effect_and_one_audit_event(wf: WfDb) -> None:
    audit = RecordingAudit()
    eng = wf.make_engine(audit=audit)
    run_id = wf.request([plan_step("block", res="k", value="K", name="dup")])
    eng.admit_pending()
    (claim,) = eng.claim(1)
    wf.signal(run_id, "abort")
    wf.signal(run_id, "abort")
    eng.process_signals()
    outcomes = [
        s["outcome"] for s in wf.q("SELECT outcome FROM run_signal ORDER BY created_at, id")
    ]
    assert outcomes == [
        "abort requested; applies at the step boundary",
        "duplicate: abort already requested",
    ]
    assert audit.actions().count("signal.abort") == 1
    BLOCKERS.setdefault("dup", threading.Event()).set()
    eng.execute(claim)
    r = wf.run(run_id)
    assert r["state"] == "cancelled"  # honoured at the step boundary (default on_abort)
    assert wf.steps(run_id)[0]["state"] == "succeeded"  # the running step finished first


# ---- WF-11 resource locks -----------------------------------------------------------------------------------


def test_wf11_second_run_on_a_locked_resource_gets_a_clear_conflict(wf: WfDb) -> None:
    eng = wf.make_engine()
    first = wf.request([plan_step("human", res="h")], locks=[["service", "s1"], ["server", "blue"]])
    second = wf.request([plan_step("human", res="h")], locks=[["server", "blue"], ["volume", "v9"]])
    eng.admit_pending()
    assert wf.run(first)["state"] == "running"
    r2 = wf.run(second)
    assert r2["state"] == "rejected"
    assert r2["end_reason"] == f"resource locked: server/blue is held by run {first}"
    assert wf.locks(second) == []  # all-or-nothing: v9 not left behind


def test_wf11_crossed_lock_sets_never_deadlock(wf: WfDb) -> None:
    engines = [wf.make_engine(), wf.make_engine()]
    for i in range(8):
        a, b = f"x{i}", f"y{i}"
        runs = [
            wf.request([plan_step("human", res="h")], locks=[["volume", a], ["volume", b]]),
            wf.request([plan_step("human", res="h")], locks=[["volume", b], ["volume", a]]),
        ]
        _race(2, lambda j: engines[j].admit_pending())
        states = sorted(wf.run(r)["state"] for r in runs)
        assert states == ["rejected", "running"]


def test_wf11_locks_survive_crash_and_needs_human_and_are_released_only_at_the_end(
    wf: WfDb,
) -> None:
    locks = [["floating_ip", "fip-1"], ["service", "s1"]]
    run_id = wf.request(
        [
            plan_step("set", res="a", value="A"),
            plan_step("fail", cls="needs_human", reason="ambiguous_state"),
        ],
        locks=locks,
    )
    crashpoint.install(CrashPlan("set.after_act", 1, "raise"))
    with pytest.raises(SimulatedCrash):
        drive(wf.make_engine(), run_id, wf)
    crashpoint.install(None)
    assert sorted(map(list, wf.locks(run_id))) == sorted(locks)
    wf.expire_leases()
    eng = wf.make_engine()
    assert drive(eng, run_id, wf)["state"] == "needs_human"
    assert sorted(map(list, wf.locks(run_id))) == sorted(locks)
    wf.signal(run_id, "rollback")
    eng.process_signals()
    assert wf.run(run_id)["state"] == "rolled_back"
    assert wf.locks() == []


def test_wf11_lock_acquired_in_a_transition_conflict_parks_the_run(wf: WfDb) -> None:
    eng = wf.make_engine()
    holder = wf.request([plan_step("human", res="h")], locks=[["port", "green-port"]])
    run_id = wf.request(
        [
            plan_step("set", res="a", value="A"),
            plan_step(
                "set",
                res="b",
                value="B",
                acquire_locks=[["port", "green-port"], ["server", "green"]],
            ),
        ],
        locks=[["service", "s2"]],
    )
    r = drive(eng, run_id, wf)
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "lock_conflict"
    assert wf.locks(run_id) == [("service", "s2")]  # nothing partial
    wf.signal(holder, "abort")
    eng.process_signals()
    wf.signal(run_id, "retry_step")
    r = drive(eng, run_id, wf)
    assert r["state"] == "completed"
    assert [s["state"] for s in wf.steps(run_id)] == ["succeeded", "succeeded"]


# ---- signals (SRE-R-24) and abort (WF-16, generic part) -----------------------------------------------------


def test_signal_effect_and_consumption_commit_together(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("human", res="h")], locks=[["service", "s1"]])
    eng.run_once()
    wf.signal(run_id, "abort")
    crashpoint.install(CrashPlan("signal.apply", 1, "raise"))
    with pytest.raises(SimulatedCrash):
        eng.process_signals()
    crashpoint.install(None)
    sig = wf.one("SELECT consumed_at, outcome FROM run_signal")
    assert sig["consumed_at"] is None  # not consumed ...
    r = wf.run(run_id)
    assert r["state"] == "running" and r["abort_requested"] is False  # ... and no effect
    assert wf.make_engine().process_signals() == 1  # re-applied by another worker
    assert wf.run(run_id)["state"] == "cancelled"
    assert wf.one("SELECT outcome FROM run_signal")["outcome"] == "aborted at boundary"
    assert wf.locks() == []


def test_boundary_signal_waits_while_a_step_runs(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request(
        [plan_step("block", res="k", value="K", name="rb"), plan_step("set", res="z", value="Z")]
    )
    eng.admit_pending()
    (claim,) = eng.claim(1)
    wf.signal(run_id, "rollback")
    assert eng.process_signals() == 0  # left pending: a step is running
    assert wf.one("SELECT consumed_at FROM run_signal")["consumed_at"] is None
    BLOCKERS.setdefault("rb", threading.Event()).set()
    eng.execute(claim)
    assert eng.process_signals() == 1
    assert wf.run(run_id)["state"] == "rolled_back"
    assert [s["state"] for s in wf.steps(run_id)] == ["succeeded", "cancelled"]
    assert wf.effects("z") == []


def test_signal_refused_by_validator_is_consumed_without_effect(wf: WfDb) -> None:
    audit = RecordingAudit()
    eng = wf.make_engine(audit=audit)
    run_id = wf.request([plan_step("human", res="h")])
    eng.run_once()
    wf.signal(run_id, "abort", deny=True)
    eng.process_signals()
    assert wf.one("SELECT outcome FROM run_signal")["outcome"].startswith("refused: denied")
    assert wf.run(run_id)["state"] == "running" and not wf.run(run_id)["abort_requested"]
    (ev,) = [e for e in audit.events if e.action == "signal.abort"]
    assert ev.result == "refused"


def test_abort_variants(wf: WfDb) -> None:
    eng = wf.make_engine()
    requested = wf.request([plan_step("human", res="h")], defer=True)
    waiting = wf.request([plan_step("human", res="h")])
    rolls_back = wf.request([plan_step("human", res="h")], abort_rolls_back=True)
    drive(eng, waiting, wf)
    drive(eng, rolls_back, wf)
    for r in (requested, waiting, rolls_back):
        wf.signal(r, "abort")
    eng.process_signals()
    assert wf.run(requested)["state"] == "cancelled"
    assert wf.run(requested)["end_reason"] == "aborted before admission"
    assert wf.run(waiting)["state"] == "cancelled"
    assert wf.steps(waiting)[0]["state"] == "cancelled"
    assert wf.run(rolls_back)["state"] == "rolled_back"
    wf.signal(waiting, "abort")
    eng.process_signals()
    assert wf.q("SELECT outcome FROM run_signal ORDER BY created_at DESC LIMIT 1")[0][
        "outcome"
    ] == ("ignored: run is cancelled")


def test_wait_until_signal_and_wake(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("human", res="gate")])
    drive(eng, run_id, wf)
    (s,) = wf.steps(run_id)
    assert s["state"] == "waiting" and s["not_before"] is None  # no timer
    assert eng.claim(5) == []
    wf.x("INSERT INTO fake_resource (key, value) VALUES ('gate', 'approved')")
    wf.signal(run_id, "admit")
    eng.process_signals()
    assert wf.one("SELECT outcome FROM run_signal")["outcome"] == "step human woken"
    assert drive(eng, run_id, wf)["state"] == "completed"


def test_probe_signal_is_a_string_outcome_and_unsupported_kinds_are_reported(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("human", res="h")])
    drive(eng, run_id, wf)
    wf.signal(run_id, "probe")
    wf.signal(run_id, "revert")
    eng.process_signals()
    outcomes = [
        r["outcome"] for r in wf.q("SELECT outcome FROM run_signal ORDER BY created_at, id")
    ]
    assert outcomes == ["probe recorded", "unsupported signal revert for this strategy"]


def test_retry_step_rejected_when_nothing_needs_a_human(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("human", res="h")])
    drive(eng, run_id, wf)
    wf.signal(run_id, "retry_step")
    eng.process_signals()
    assert wf.one("SELECT outcome FROM run_signal")["outcome"] == "rejected: no step in needs_human"


# ---- metrics ------------------------------------------------------------------------------------------------


def _gauge(g: Any, *labels: str) -> float:
    return float((g.labels(*labels) if labels else g)._value.get())  # noqa: SLF001


def test_metrics_runs_needing_attention_requested_and_pending_signals(wf: WfDb) -> None:
    cfg = EngineConfig(
        **{**TEST_CONFIG.__dict__, "admission_alert_after": 0.0, "signal_alert_after": 0.0}
    )
    eng = wf.make_engine(config=cfg)
    nh = wf.request(
        [plan_step("fail", cls="needs_human", reason="api_unreachable")], phase="window"
    )
    drive(eng, nh, wf)
    wf.request([plan_step("human", res="h")], defer=True)  # stays requested
    blocked = wf.request([plan_step("block", res="k", value="K", name="m")])
    eng.admit_pending()
    (claim,) = eng.claim(1)
    wf.signal(blocked, "rollback")  # pending while the step runs
    eng.process_signals()
    time.sleep(0.05)
    eng.refresh_metrics()
    assert _gauge(m.RUNS_NEEDING_ATTENTION, "window", "api_unreachable") == 1
    assert _gauge(m.RUNS, "probe", "requested") == 1
    assert _gauge(m.REQUESTED_OVERDUE) == 1 and _gauge(m.REQUESTED_OLDEST) > 0
    assert _gauge(m.SIGNALS_PENDING_OVERDUE) == 1 and _gauge(m.SIGNALS_PENDING_OLDEST) > 0
    assert _gauge(m.STEP_HEARTBEAT_AGE) >= 0 and _gauge(m.EXPIRED_LEASES) == 0
    wf.expire_leases()
    eng.refresh_metrics()
    assert _gauge(m.EXPIRED_LEASES) == 1
    BLOCKERS.setdefault("m", threading.Event()).set()
    del claim


# ---- scheduler ----------------------------------------------------------------------------------------------


def test_scheduler_creates_periodic_runs_once(wf: WfDb) -> None:
    engines = [wf.make_engine(), wf.make_engine()]
    for e in engines:
        e.registry.periodic.append(PeriodicJob("probe", "dummy", "1", 3600, {"plan": []}))
    created = _race(2, lambda i: engines[i].run_scheduler())
    assert sum(created) == 1
    assert engines[0].run_scheduler() == 0  # one non-terminal run exists
    assert len(wf.q("SELECT id FROM workflow_run WHERE state = 'requested'")) == 1


# ---- worker main loop ---------------------------------------------------------------------------------------


def test_worker_main_loop_runs_steps_in_slots_and_sweeps_before_claiming(wf: WfDb) -> None:
    settings = Settings(process_role="worker", worker={"heartbeat_interval": 0.05, "slots": 2})
    eng = wf.make_engine()
    seen_attempts_at_sweep: list[int] = []
    eng.registry.sweepers.append(
        lambda: seen_attempts_at_sweep.append(len(wf.q("SELECT id FROM workflow_step_attempt")))
    )
    runs = [
        wf.request(
            [plan_step("set", res=f"r{i}", value="V"), plan_step("async", res=f"q{i}", value="W")]
        )
        for i in range(3)
    ]
    # a step claimable before the worker starts: the sweeper must still run first
    eng.admit_pending()
    worker = Worker(settings, eng.db, eng)
    t = threading.Thread(target=worker.run)
    t.start()
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if all(wf.run(r)["state"] == "completed" for r in runs):
                break
            time.sleep(0.05)
    finally:
        worker.request_stop("test")
        t.join(30)
    assert not t.is_alive()
    assert all(wf.run(r)["state"] == "completed" for r in runs)
    assert seen_attempts_at_sweep == [0]
    hb = wf.one("SELECT * FROM worker_heartbeat WHERE worker_id = :w", w=eng.worker_id)
    assert hb["draining"] is True
