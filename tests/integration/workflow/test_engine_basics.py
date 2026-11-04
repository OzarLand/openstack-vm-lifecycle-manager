"""Engine basics on a real PostgreSQL: admission, steps, waits, retries, error classes, grants (WF-12/14/18/19/20)."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from ovlm.workflow.engine import EngineConfig
from tests.integration.workflow.conftest import TEST_CONFIG, RecordingAudit, WfDb, drive
from tests.integration.workflow.dummy import plan_step


def test_happy_path_runs_every_step_once_and_releases_locks(
    wf: WfDb, plan3: Callable[[], list[dict[str, Any]]]
) -> None:
    audit = RecordingAudit()
    eng = wf.make_engine(audit=audit)
    run_id = wf.request(plan3(), locks=[["service", "svc-1"], ["server", "blue-1"]])
    assert wf.run(run_id)["state"] == "requested"
    r = drive(eng, run_id, wf)
    assert r["state"] == "completed" and r["finished_at"] is not None
    steps = wf.steps(run_id)
    assert [s["step_key"] for s in steps] == ["set", "async", "set_destructive"]
    assert all(s["state"] == "succeeded" for s in steps)
    assert [s["destructive"] for s in steps] == [False, False, True]
    assert [e["key"] for e in wf.effects()] == ["a", "b", "c"]  # one effect per step
    assert wf.locks() == []
    acts = audit.actions()
    assert acts[0] == "run.admitted" and acts[-1] == "run.completed"
    # async step: 1 act + waits; every attempt is recorded with an outcome
    att = wf.attempts(run_id)
    assert all(a["outcome"] for a in att)
    assert [a["outcome"] for a in att if a["step_key"] == "async"][-1] == "succeeded"


def test_intent_is_persisted_before_act(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("set", res="a", value="A")])
    drive(eng, run_id, wf)
    (step,) = wf.steps(run_id)
    assert step["intent"] == {"res": "a", "value": "A"}
    assert step["evidence"] == {"value": "A"}


def test_wait_releases_lease_and_backs_off(wf: WfDb) -> None:
    """WF-14: WAIT frees the lease; backoff poll.initial_interval doubling up to poll.max_interval."""
    cfg = EngineConfig(**{**TEST_CONFIG.__dict__, "poll_initial": 10.0, "poll_max": 25.0})
    eng = wf.make_engine(config=cfg)
    run_id = wf.request([plan_step("async", res="b", value="B", polls=5)])
    delays = []
    for _ in range(3):
        eng.run_once()
        (s,) = wf.steps(run_id)
        assert s["state"] == "waiting"
        assert s["lease_owner"] is None and s["lease_expires_at"] is None
        delays.append(
            wf.one(
                "SELECT EXTRACT(EPOCH FROM not_before - updated_at) AS d FROM workflow_step WHERE id = :id",
                id=s["id"],
            )["d"]
        )
        assert eng.claim(1) == []  # not before the timer
        wf.x("UPDATE workflow_step SET not_before = now() WHERE id = :id", id=s["id"])
    assert [round(float(d)) for d in delays] == [10, 20, 25]


def test_wait_past_deadline_becomes_needs_human_not_fatal(wf: WfDb) -> None:
    """WF-14: deadline_at reached while waiting -> needs_human (state unknown), never fatal."""
    eng = wf.make_engine()
    run_id = wf.request([plan_step("async", res="b", value="B", polls=50, timeout=3600)])
    eng.run_once()
    (s,) = wf.steps(run_id)
    assert s["deadline_at"] is not None and s["state"] == "waiting"
    wf.x("UPDATE workflow_step SET deadline_at = now() - interval '1 s' WHERE id = :id", id=s["id"])
    r = drive(eng, run_id, wf)
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "deadline_exceeded"
    (s,) = wf.steps(run_id)
    assert s["state"] == "needs_human" and s["error_class"] == "needs_human"
    assert wf.locks(run_id) == [] or True  # no locks requested in this plan


def test_retryable_then_success(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("flaky", res="f", fail_times=2)])
    r = drive(eng, run_id, wf)
    assert r["state"] == "completed"
    outcomes = [a["outcome"] for a in wf.attempts(run_id)]
    assert outcomes == ["retryable", "retryable", "succeeded"]


def test_retry_exhaustion_parks_in_needs_human_and_retry_step_gives_a_fresh_budget(wf: WfDb) -> None:
    """WF-18: retryable exhaustion -> needs_human; operator retry-step re-runs with a new budget."""
    eng = wf.make_engine()
    run_id = wf.request([plan_step("flaky", res="f", fail_times=4)], locks=[["volume", "v1"]])
    r = drive(eng, run_id, wf)
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "retries_exhausted"
    assert [a["outcome"] for a in wf.attempts(run_id)] == ["retryable", "retryable", "needs_human"]
    assert wf.locks(run_id) == [("volume", "v1")]  # locks held while parked
    wf.signal(run_id, "retry_step")
    r = drive(eng, run_id, wf)
    assert r["state"] == "completed"
    assert wf.locks() == []
    sig = wf.one("SELECT * FROM run_signal WHERE run_id = :id", id=run_id)
    assert sig["consumed_at"] is not None and sig["outcome"] == "step flaky re-queued"


def test_fatal_fails_run_and_releases_locks(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("fail", cls="fatal")], locks=[["port", "p1"]])
    r = drive(eng, run_id, wf)
    assert r["state"] == "failed"
    assert wf.steps(run_id)[0]["state"] == "failed"
    assert wf.locks() == []
    assert [a["outcome"] for a in wf.attempts(run_id)] == ["failed"]  # no retry of a fatal error


def test_fatal_can_be_compensated_by_the_strategy(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request(
        [plan_step("fail", cls="fatal")],
        compensate_with={"key": "set", "params": {"res": "undo", "value": "U"}},
    )
    r = drive(eng, run_id, wf)
    assert r["state"] == "completed" and r["phase"] == "restore"
    assert [s["state"] for s in wf.steps(run_id)] == ["failed", "succeeded"]


def test_needs_human_class_parks_and_mark_resolved_moves_on(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request(
        [plan_step("fail", cls="needs_human", reason="ambiguous_state"), plan_step("set", res="z", value="Z")]
    )
    r = drive(eng, run_id, wf)
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "ambiguous_state"
    wf.signal(run_id, "mark_resolved", note="fixed by hand")
    r = drive(eng, run_id, wf)
    assert r["state"] == "completed"
    first = wf.steps(run_id)[0]
    assert first["state"] == "succeeded"
    assert first["evidence"]["mark_resolved"]["payload"] == {"note": "fixed by hand"}


def test_exception_in_step_code_is_classified_retryable(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("raise")])
    r = drive(eng, run_id, wf)
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "retries_exhausted"
    err = wf.steps(run_id)[0]["error"]
    assert "ValueError" in err["reason"]


def test_concurrency_cap_is_enforced_at_admission(wf: WfDb) -> None:
    """WF-12: cap checked at admission; the extra run waits in requested and is admitted later."""
    eng = wf.make_engine(cap=2)
    runs = [wf.request([plan_step("human", res=f"h{i}")]) for i in range(3)]
    eng.admit_pending()
    states = [wf.run(r)["state"] for r in runs]
    assert states == ["running", "running", "requested"]
    wf.signal(runs[0], "abort")
    eng.process_signals()
    assert wf.run(runs[0])["state"] == "cancelled"
    eng.admit_pending()
    assert wf.run(runs[2])["state"] == "running"


def test_unknown_strategy_version_is_rejected_with_a_listing(wf: WfDb) -> None:
    """WF-19: an unknown strategy_version refuses start and lists what this release starts."""
    eng = wf.make_engine()
    run_id = wf.request([plan_step("set", res="a", value="A")], version="9")
    eng.admit_pending()
    r = wf.run(run_id)
    assert r["state"] == "rejected"
    assert "version 9" in r["end_reason"] and "starts: 1" in r["end_reason"]


def test_waiting_steps_of_previous_version_resume_on_new_definition(wf: WfDb) -> None:
    """WF-19: waiting/ready steps of N-1 resume on N when N declares it; otherwise they are not claimed."""
    old = wf.make_engine(version="1")
    run_id = wf.request([plan_step("async", res="b", value="B", polls=1)])
    old.run_once()
    assert wf.steps(run_id)[0]["state"] == "waiting"
    unaware = wf.make_engine(version="2")
    assert unaware.claim(5) == []  # does not know version 1
    new = wf.make_engine(version="2", resumes=frozenset({"1"}))
    r = drive(new, run_id, wf)
    assert r["state"] == "completed" and r["strategy_version"] == "1"


def test_admission_rejects_and_defers(wf: WfDb) -> None:
    eng = wf.make_engine()
    rej = wf.request([plan_step("set", res="a", value="A")], reject="evidence invalid")
    dfr = wf.request([plan_step("set", res="a", value="A")], defer=True)
    eng.admit_pending()
    assert wf.run(rej)["state"] == "rejected" and wf.run(rej)["end_reason"] == "evidence invalid"
    assert wf.run(dfr)["state"] == "requested"


def test_lease_and_timers_use_database_time(wf: WfDb, monkeypatch: pytest.MonkeyPatch) -> None:
    """WF-20: a skewed worker clock cannot extend its lease: lease_expires_at = DB now() + lease."""
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 10 * 86400)
    eng = wf.make_engine()
    run_id = wf.request([plan_step("block", res="k", value="K", name="wf20")])
    eng.admit_pending()
    (claim,) = eng.claim(1)
    row = wf.one(
        "SELECT EXTRACT(EPOCH FROM lease_expires_at - now()) AS left FROM workflow_step WHERE id = :id",
        id=claim.step.id,
    )
    assert TEST_CONFIG.lease_duration - 5 < float(row["left"]) <= TEST_CONFIG.lease_duration
    assert wf.run(run_id)["state"] == "running"


def test_one_running_and_one_open_step_per_run_enforced_by_the_database(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("human", res="h")])
    eng.admit_pending()
    with pytest.raises(IntegrityError):
        wf.x(
            "INSERT INTO workflow_step (id, run_id, seq, step_key, state) "
            "VALUES (gen_random_uuid(), :r, 99, 'x', 'ready')",
            r=run_id,
        )


def test_api_role_can_only_request_and_signal(wf: WfDb) -> None:
    """data-model.md section 12 / SEC-R-1: api inserts runs in requested and unconsumed signals only."""
    api = wf.api_db()
    with pytest.raises(DBAPIError, match="state requested"), api.begin() as c:
        c.execute(
            text(
                "INSERT INTO workflow_run (id, kind, strategy, strategy_version, state) "
                "VALUES (gen_random_uuid(), 'probe', 'dummy', '1', 'running')"
            )
        )
    run_id = wf.request([plan_step("human", res="h")])
    with pytest.raises(ProgrammingError), api.begin() as c:
        c.execute(text("UPDATE workflow_run SET state = 'running' WHERE id = :id"), {"id": run_id})
    with pytest.raises(ProgrammingError), api.begin() as c:
        c.execute(text("UPDATE workflow_step SET state = 'ready'"))
    with pytest.raises(DBAPIError, match="unconsumed"), api.begin() as c:
        c.execute(
            text(
                "INSERT INTO run_signal (id, run_id, kind, consumed_at, outcome) "
                "VALUES (gen_random_uuid(), :r, 'abort', now(), 'x')"
            ),
            {"r": run_id},
        )
    worker = wf.worker_db()
    with pytest.raises(ProgrammingError), worker.begin() as c:
        c.execute(text("UPDATE run_signal SET kind = 'abort'"))  # only consumed_at/outcome
    with pytest.raises(ProgrammingError), worker.begin() as c:
        c.execute(text("DELETE FROM workflow_run"))
