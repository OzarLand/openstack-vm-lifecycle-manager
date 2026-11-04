"""Regression tests for the SRE code review of the engine (docs/reviews/sre-review-engine-e5-1.md).

SRE-C-1: a signal-driven transition that hits a lock conflict keeps the step open (needs_human), so the
operator can still retry, re-send the signal or mark it resolved.
SRE-C-2: ``mark_resolved`` re-queues the step; the next attempt must probe and reach Done by itself.
SRE-C-3: a step past its ``deadline_at`` does not act; it goes to needs_human(deadline_exceeded).
SRE-C-5/-7/-8 are covered here too (backoff, parked attempt, lost COMMIT, signal race, set_lease failure).
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from ovlm.workflow import crashpoint
from ovlm.workflow.clock import FakeClock
from ovlm.workflow.crashpoint import CrashPlan
from ovlm.workflow.engine import EngineConfig
from tests.integration.workflow.conftest import (
    TEST_CONFIG,
    RecordingAudit,
    WfDb,
    assert_open_step_invariant,
    drive,
)
from tests.integration.workflow.dummy import BLOCKERS, plan_step
from tests.integration.workflow.test_concurrency_signals import _race


def _open_steps(wf: WfDb, run_id: str) -> list[Any]:
    return [
        s for s in wf.steps(run_id) if s["state"] in ("ready", "running", "waiting", "needs_human")
    ]


# ---- SRE-C-1 ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("parked", [True, False], ids=["run_parked", "step_waiting"])
def test_sre_c1_signal_transition_lock_conflict_keeps_the_step_open(wf: WfDb, parked: bool) -> None:
    audit = RecordingAudit()
    eng = wf.make_engine(audit=audit)
    holder = wf.request([plan_step("human", res="h")], locks=[["port", "green-port"]])
    first = (
        plan_step("fail", cls="needs_human", reason="ambiguous_state")
        if parked
        else plan_step("human", res="gate")
    )
    run_id = wf.request(
        [first],
        locks=[["service", "s1"]],
        rollback_to={
            "key": "set",
            "params": {"res": "restored", "value": "R"},
            "acquire_locks": [["port", "green-port"], ["server", "blue"]],
        },
    )
    eng.admit_pending()
    drive(eng, run_id, wf)
    wf.signal(run_id, "rollback")
    eng.process_signals()

    r = wf.run(run_id)
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "lock_conflict"
    (open_step,) = _open_steps(wf, run_id)  # exactly one open step: the operator still has buttons
    assert open_step["state"] == "needs_human" and open_step["step_key"] == first["key"]
    assert "green-port" in open_step["error"]["reason"]
    assert wf.locks(run_id) == [("service", "s1")]  # nothing partial
    assert_open_step_invariant(wf)
    assert "step.parked" in audit.actions()

    # The holder goes away; the operator re-sends the rollback and it applies.
    wf.signal(holder, "abort")
    eng.process_signals()
    wf.signal(run_id, "rollback")
    eng.process_signals()
    r = drive(eng, run_id, wf)
    assert r["state"] == "completed" and r["phase"] == "restore"
    assert wf.resource("restored") == "R"
    assert wf.locks() == []


def test_sre_c1_retry_step_works_after_a_signal_lock_conflict(wf: WfDb) -> None:
    eng = wf.make_engine()
    wf.request([plan_step("human", res="h")], locks=[["port", "p1"]])
    run_id = wf.request(
        [plan_step("human", res="gate")],
        rollback_to={
            "key": "set",
            "params": {"res": "x", "value": "X"},
            "acquire_locks": [["port", "p1"]],
        },
    )
    drive(eng, run_id, wf)
    wf.signal(run_id, "rollback")
    eng.process_signals()
    wf.signal(run_id, "retry_step")
    eng.process_signals()
    assert (
        wf.q("SELECT outcome FROM run_signal WHERE run_id = :id ORDER BY created_at", id=run_id)[
            -1
        ]["outcome"]
        == "step human re-queued"
    )
    assert wf.run(run_id)["state"] == "running"


# ---- SRE-C-2 ------------------------------------------------------------------------------------------------


def test_sre_c2_mark_resolved_re_probes_and_never_completes_on_attestation_alone(wf: WfDb) -> None:
    audit = RecordingAudit()
    eng = wf.make_engine(audit=audit)
    run_id = wf.request(
        [
            plan_step("set", res="a", value="A"),
            # last step of the run (like X1 retire_old): nothing after it would re-check its effect
            plan_step("fail", cls="needs_human", reason="ambiguous_state", res="blue-gone"),
        ]
    )
    r = drive(eng, run_id, wf)
    assert r["state"] == "needs_human"

    # Attestation without the fix: the engine re-probes, sees the goal not reached, parks again.
    wf.signal(run_id, "mark_resolved", note="trust me")
    r = drive(eng, run_id, wf)
    assert r["state"] == "needs_human", "completed on the operator's attestation alone"
    last = wf.steps(run_id)[-1]
    assert last["state"] == "needs_human"
    assert last["evidence"]["mark_resolved"]["payload"] == {"note": "trust me"}
    assert_open_step_invariant(wf)

    # The admin fixed it by hand: the re-probe sees it and the step reaches Done by itself.
    wf.x("INSERT INTO fake_resource (key, value) VALUES ('blue-gone', 'resolved')")
    wf.signal(run_id, "mark_resolved", note="deleted by hand")
    r = drive(eng, run_id, wf)
    assert r["state"] == "completed"
    last = wf.steps(run_id)[-1]
    assert last["state"] == "succeeded"
    assert last["evidence"]["resolved_seen_by_probe"] is True
    assert last["evidence"]["mark_resolved"]["payload"] == {"note": "deleted by hand"}
    att = [a for a in wf.attempts(run_id) if a["step_key"] == "fail"]
    assert [a["outcome"] for a in att] == ["needs_human", "needs_human", "succeeded"]


def test_sre_c2_mark_resolved_resets_budget_and_deadline(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("flaky", res="f", fail_times=3, timeout=600)])
    r = drive(eng, run_id, wf)
    assert r["needs_human_reason"] == "retries_exhausted"
    wf.x(
        "UPDATE workflow_step SET deadline_at = now() - interval '1 s' WHERE run_id = :id",
        id=run_id,
    )
    wf.signal(run_id, "mark_resolved")
    eng.process_signals()
    (s,) = wf.steps(run_id)
    assert s["state"] == "ready" and s["retry_floor"] == s["attempt"]
    assert wf.one(
        "SELECT deadline_at > now() + interval '500 s' AS fresh FROM workflow_step WHERE id = :id",
        id=s["id"],
    )["fresh"]
    assert drive(eng, run_id, wf)["state"] == "completed"


# ---- SRE-C-3 ------------------------------------------------------------------------------------------------


def test_sre_c3_step_claimed_after_its_deadline_does_not_act(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("set", res="a", value="A", timeout=60)])
    eng.admit_pending()
    wf.x(
        "UPDATE workflow_step SET deadline_at = now() - interval '1 s' WHERE run_id = :id",
        id=run_id,
    )
    r = drive(eng, run_id, wf)
    assert wf.effects() == [], "a step past its deadline acted"
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "deadline_exceeded"
    (s,) = wf.steps(run_id)
    assert s["state"] == "needs_human" and s["intent"] is None
    assert "deadline" in s["error"]["reason"]


def test_sre_c3_late_step_whose_goal_is_already_reached_completes(wf: WfDb) -> None:
    eng = wf.make_engine()
    run_id = wf.request([plan_step("set", res="a", value="A", timeout=60)])
    eng.admit_pending()
    wf.x("INSERT INTO fake_resource (key, value) VALUES ('a', 'A')")
    wf.x(
        "UPDATE workflow_step SET deadline_at = now() - interval '1 s' WHERE run_id = :id",
        id=run_id,
    )
    assert drive(eng, run_id, wf)["state"] == "completed"
    assert wf.effects() == []


def test_sre_c3_deadline_passing_locally_between_claim_and_act_stops_the_act(wf: WfDb) -> None:
    """The DB says "not late" at claim; the deadline passes on the local clock before act (e.g. during the
    takeover delay or a slow probe): still no act."""
    clock = FakeClock()
    eng = wf.make_engine(clock=clock)
    run_id = wf.request([plan_step("set", res="a", value="A", timeout=20)])
    crashpoint.install(
        CrashPlan("set.after_probe", 1, action=lambda _n: clock.advance(21))
    )  # < fence deadline (25 s)
    eng.run_once()
    crashpoint.install(None)
    assert wf.effects() == []
    r = wf.run(run_id)
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "deadline_exceeded"


# ---- SRE-C-5 ------------------------------------------------------------------------------------------------


def test_sre_c5_backoff_counts_consecutive_waits_only_and_is_clamped_to_the_deadline(
    wf: WfDb,
) -> None:
    cfg = EngineConfig(**{**TEST_CONFIG.__dict__, "poll_initial": 10.0, "poll_max": 300.0})
    eng = wf.make_engine(config=cfg)
    run_id = wf.request([plan_step("async", res="b", value="B", polls=50, timeout=3600)])

    def delay() -> float:
        (s,) = wf.steps(run_id)
        return round(
            float(
                wf.one(
                    "SELECT EXTRACT(EPOCH FROM not_before - updated_at) AS d FROM workflow_step "
                    "WHERE id = :id",
                    id=s["id"],
                )["d"]
            )
        )

    def due() -> None:
        wf.x("UPDATE workflow_step SET not_before = now() WHERE run_id = :id", id=run_id)

    eng.run_once()  # act -> wait: the exponent starts at 0
    assert delay() == 10
    due()
    eng.run_once()
    assert delay() == 20
    # a takeover (lost attempt) does not advance the exponent
    due()
    (claim,) = eng.claim(1)
    wf.expire_leases()
    del claim
    eng.run_once()
    assert delay() == 40
    # clamp: with 15 s left before the deadline the next poll is at the deadline, not 80 s later
    due()
    wf.x(
        "UPDATE workflow_step SET deadline_at = now() + interval '15 s' WHERE run_id = :id",
        id=run_id,
    )
    eng.run_once()
    assert delay() <= 15


# ---- SRE-C-7 ------------------------------------------------------------------------------------------------


def test_sre_c7_outcome_lock_conflict_marks_the_attempt_parked(wf: WfDb) -> None:
    audit = RecordingAudit()
    eng = wf.make_engine(audit=audit)
    holder = wf.request([plan_step("human", res="h")], locks=[["port", "gp"]])
    run_id = wf.request(
        [
            plan_step("set", res="a", value="A"),
            plan_step("set", res="b", value="B", acquire_locks=[["port", "gp"]]),
        ]
    )
    r = drive(eng, run_id, wf)
    assert r["needs_human_reason"] == "lock_conflict"
    (att,) = wf.attempts(run_id)
    assert att["outcome"] == "parked"
    (ev,) = [e for e in audit.events if e.action == "step.parked"]
    assert ev.after["lock"] == "port/gp" and ev.after["holder_run_id"] == holder
    assert wf.steps(run_id)[0]["state"] == "needs_human"
    assert_open_step_invariant(wf)


# ---- SRE-C-8 ------------------------------------------------------------------------------------------------


def _terminate_worker_backends(wf: WfDb) -> None:
    with wf.admin.connect() as c:
        c.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE usename = 'ovlm_worker' AND datname = current_database()"
            )
        )


def test_sre_c8_commit_fails_on_a_terminated_backend_next_attempt_re_probes(wf: WfDb) -> None:
    """The COMMIT of the outcome transaction meets a terminated backend: ``commit_unknown`` runs, the attempt
    stays ``running`` until its lease expires, and the next attempt re-probes without doubling the effect."""
    eng = wf.make_engine()
    run_id = wf.request(
        [plan_step("set", res="a", value="A"), plan_step("set", res="b", value="B")]
    )
    eng.admit_pending()
    (claim,) = eng.claim(1)
    crashpoint.install(
        CrashPlan("outcome.before_commit", 1, action=lambda _n: _terminate_worker_backends(wf))
    )
    assert eng.execute(claim) == "commit_unknown"
    crashpoint.install(None)
    assert wf.steps(run_id)[0]["state"] == "running"  # not committed
    wf.expire_leases()
    r = drive(eng, run_id, wf)
    assert r["state"] == "completed"
    assert len(wf.effects("a")) == 1 and len(wf.effects("b")) == 1
    first = [a for a in wf.attempts(run_id) if a["step_key"] == "set"][:2]
    assert [a["outcome"] for a in first] == ["lost", "succeeded"]
    assert first[1]["evidence"] == {"already": True, "value": "A"}  # re-probed, did not act again


def test_sre_c8_commit_acknowledgement_lost_after_commit_is_harmless(wf: WfDb) -> None:
    """The COMMIT happened but the worker saw an error (lost acknowledgement): the step already left
    ``running``; nothing is retried and nothing doubles."""
    eng = wf.make_engine()
    run_id = wf.request(
        [plan_step("set", res="a", value="A"), plan_step("set", res="b", value="B")]
    )
    eng.admit_pending()
    (claim,) = eng.claim(1)

    def lose_ack(_n: str) -> None:
        raise OperationalError("COMMIT", {}, Exception("server closed the connection unexpectedly"))

    crashpoint.install(CrashPlan("set.after_commit", 1, action=lose_ack))
    assert eng.execute(claim) == "commit_unknown"
    crashpoint.install(None)
    assert wf.steps(run_id)[0]["state"] == "succeeded"
    assert drive(eng, run_id, wf)["state"] == "completed"
    assert len(wf.effects("a")) == 1


def test_sre_c8_two_workers_racing_one_signal_apply_it_once(wf: WfDb) -> None:
    for round_ in range(6):
        audit = RecordingAudit()
        engines = [wf.make_engine(audit=audit), wf.make_engine(audit=audit)]
        run_id = wf.request(
            [plan_step("human", res=f"h{round_}")], locks=[["volume", f"v{round_}"]]
        )
        drive(engines[0], run_id, wf)
        wf.signal(run_id, "abort")
        applied = _race(2, lambda i, e=engines: e[i].process_signals())  # type: ignore[misc]
        assert sum(applied) == 1, applied
        assert audit.actions().count("signal.abort") == 1
        assert audit.actions().count("run.cancelled") == 1
        assert wf.run(run_id)["state"] == "cancelled"
        sig = wf.one("SELECT * FROM run_signal WHERE run_id = :id", id=run_id)
        assert sig["outcome"] == "aborted at boundary"


def test_sre_c8_set_lease_heartbeat_failure_stops_before_probe(wf: WfDb) -> None:
    """The guarded heartbeat that installs a per-step lease fails (DB refuses the worker role): the attempt
    stops before probing or spawning anything; the DB lease was never extended to the step lease."""
    run_id = wf.request([plan_step("block", res="k", value="K", name="setlease", lease=3600)])
    eng = wf.make_engine(clock=FakeClock(sleep_advances=False))
    eng.admit_pending()
    (claim,) = eng.claim(1)
    probes: list[str] = []
    crashpoint.record(probes)

    def deny(_n: str) -> None:
        wf.x("ALTER ROLE ovlm_worker NOLOGIN")
        _terminate_worker_backends(wf)

    crashpoint.install(CrashPlan("block.after_claim", 1, action=deny))
    try:
        out = eng.execute(claim)
    finally:
        crashpoint.install(None)
        crashpoint.record(None)
        wf.x("ALTER ROLE ovlm_worker LOGIN")
    assert out == "fence_lost"
    assert "block.after_probe" not in probes
    left = wf.one(
        "SELECT EXTRACT(EPOCH FROM lease_expires_at - now()) AS left FROM workflow_step WHERE id = :id",
        id=claim.step.id,
    )["left"]
    assert float(left) <= TEST_CONFIG.lease_duration
    BLOCKERS.setdefault("setlease", threading.Event()).set()
    wf.expire_leases()
    assert drive(wf.make_engine(), run_id, wf)["state"] == "completed"
    assert len(wf.effects("k")) == 1


# ---- SRE-C-10 -----------------------------------------------------------------------------------------------


def test_sre_c10_stale_worker_rows_are_swept_and_live_count_uses_recent_rows(wf: WfDb) -> None:
    from ovlm.workflow.workers import count_live_workers

    eng = wf.make_engine()
    eng.register_worker("test")
    wf.x(
        "INSERT INTO worker_heartbeat (worker_id, hostname, version, last_seen_at) "
        "VALUES ('dead-1', 'h', 'v', now() - interval '1 hour')"
    )
    with wf.admin.connect() as c:
        assert count_live_workers(c, max_age=60) == 1
    assert eng.sweep_worker_rows(older_than=600) == 1
    ids = [r["worker_id"] for r in wf.q("SELECT worker_id FROM worker_heartbeat")]
    assert ids == [eng.worker_id]
    # a worker whose row was swept (paused for long) re-creates it on its next beat
    wf.x("DELETE FROM worker_heartbeat")
    eng.beat_worker()
    assert [r["worker_id"] for r in wf.q("SELECT worker_id FROM worker_heartbeat")] == [
        eng.worker_id
    ]
