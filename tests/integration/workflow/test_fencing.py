"""Leases, takeover and fencing (WF-04, WF-05, WF-06, WF-07, WF-09) against a real PostgreSQL.

WF-05 runs a real worker process and pauses it with SIGSTOP longer than its lease (ADR-0003 consequences): the
resumed worker's mutating call and commit are refused locally, and the DB guard rejects a stale commit even when
the local fence is fooled.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from ovlm.workflow import crashpoint
from ovlm.workflow import metrics as m
from ovlm.workflow.clock import FakeClock, SystemClock
from ovlm.workflow.crashpoint import CrashPlan, SimulatedCrash
from ovlm.workflow.engine import EngineConfig
from tests.integration.workflow.conftest import (
    TEST_CONFIG,
    BeatGate,
    CrashWithBeatDue,
    RecordingAudit,
    WfDb,
    drive,
)
from tests.integration.workflow.dummy import BLOCKERS, REVOKED, plan_step
from tests.integration.workflow.test_crash_matrix import worker_process


def _wait_for(cond: Callable[[], bool], timeout: float, what: str = "condition") -> None:
    deadline = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > deadline:
            raise AssertionError(f"{what} not reached within {timeout}s")
        time.sleep(0.02)


def _in_thread(fn: Callable[[], str]) -> tuple[threading.Thread, list[str]]:
    out: list[str] = []
    t = threading.Thread(target=lambda: out.append(fn()), daemon=True)
    t.start()
    return t, out


# ---- WF-04 -------------------------------------------------------------------------------------------------


def test_wf04_heartbeat_stops_lease_expires_takeover_resumes_once(wf: WfDb) -> None:
    run_id = wf.request(
        [plan_step("block", res="k", value="K", name="wf04")], locks=[["server", "s1"]]
    )
    clock_a = FakeClock(sleep_advances=False)
    a = wf.make_engine(clock=clock_a)
    a.admit_pending()
    crashpoint.install(CrashPlan("lease.heartbeat", 1, "raise"))  # A's heartbeat thread dies
    (claim_a,) = a.claim(1)
    t, out = _in_thread(lambda: a.execute(claim_a))
    _wait_for(
        lambda: crashpoint._state.plan is not None and crashpoint._state.plan.fired, 5, "hb crash"
    )  # noqa: SLF001
    crashpoint.install(None)

    wf.expire_leases()  # the injectable clock passes lease_expires_at
    audit = RecordingAudit()
    b = wf.make_engine(audit=audit)
    (claim_b,) = b.claim(1)
    assert claim_b.takeover and claim_b.step.attempt == claim_a.step.attempt + 1
    assert claim_b.fencing_token > claim_a.fencing_token
    assert "step.takeover" in audit.actions()

    clock_a.advance(TEST_CONFIG.lease_duration)  # A's local deadline passes: it stops by itself
    t.join(5)
    assert out == ["fence_lost"]
    assert (
        "wf04",
        "local fence deadline passed",
    ) in REVOKED  # its "subprocess" would be killed now

    BLOCKERS["wf04"].set()
    assert b.execute(claim_b) == "succeeded"
    r = drive(b, run_id, wf)
    assert r["state"] == "completed"
    assert [e["worker_id"] for e in wf.effects("k")] == [b.worker_id]  # resumed exactly once, by B
    assert [a["outcome"] for a in wf.attempts(run_id)] == ["lost", "succeeded"]


# ---- WF-05: stale commit refused by the DB guard (local fence fooled) --------------------------------------


def test_wf05_db_guard_rejects_stale_commit_even_when_local_fence_passes(wf: WfDb) -> None:
    """A's local fence never expires (e.g. a DB failover re-issued state, SRE-R-4); only the guard on
    ``fencing_token`` + ``lease_owner`` stops it."""
    run_id = wf.request([plan_step("set", res="a", value="A")])
    a = wf.make_engine(clock=FakeClock())
    b = wf.make_engine(clock=FakeClock())
    gate = BeatGate(a)
    a.admit_pending()
    (claim_a,) = a.claim(1)
    claims_b = []

    def b_takes_over(_name: str) -> None:  # runs inside A, right after A's act
        # A's beats stop reaching the DB from here on (A does not notice); otherwise a beat between the expiry and
        # B's claim extends A's lease again, B claims nothing and A commits legitimately (see the test below)
        gate.hold()
        wf.expire_leases()
        claims_b.extend(b.claim(1))

    crashpoint.install(CrashPlan("set.after_act", 1, action=b_takes_over))
    before = m.FENCED_COMMIT_REJECTED._value.get()  # noqa: SLF001
    try:
        got = a.execute(claim_a)
    finally:
        crashpoint.install(None)
    # B really took the step over
    assert len(claims_b) == 1 and claims_b[0].lease_owner == b.worker_id
    assert got == "commit_rejected"  # A's fence still passed locally: only the DB guard refused
    assert m.FENCED_COMMIT_REJECTED._value.get() == before + 1  # noqa: SLF001
    (s,) = wf.steps(run_id)
    assert s["state"] == "running" and s["lease_owner"] == b.worker_id  # A wrote nothing

    assert b.execute(claims_b[0]) == "succeeded"
    (s,) = wf.steps(run_id)
    assert s["evidence"] == {"already": True, "value": "A"}  # B probed and found A's effect
    assert len(wf.effects("a")) == 1  # no duplicate effect
    assert drive(b, run_id, wf)["state"] == "completed"


def test_wf05_a_live_beat_between_expiry_and_claim_keeps_the_step(wf: WfDb) -> None:
    """Reproduction of the CI flake of the test above (before ``BeatGate.hold``): A's own heartbeat lands between
    ``expire_leases()`` and B's claim. The lease is A's again, B claims nothing, and A commits: correct engine
    behaviour (A is alive and owns the step), but the takeover the test meant to stage never happened."""
    run_id = wf.request([plan_step("set", res="a", value="A")])
    a = wf.make_engine(clock=FakeClock())
    b = wf.make_engine(clock=FakeClock())
    gate = BeatGate(a)
    a.admit_pending()
    (claim_a,) = a.claim(1)
    claims_b = []

    def b_too_late(_name: str) -> None:
        wf.expire_leases()
        gate.next_beat()  # what a slow runner does: A's heartbeat thread runs before B's claim
        claims_b.extend(b.claim(1))

    crashpoint.install(CrashPlan("set.after_act", 1, action=b_too_late))
    try:
        got = a.execute(claim_a)
    finally:
        crashpoint.install(None)
    assert claims_b == []
    assert got == "succeeded"
    assert len(wf.effects("a")) == 1
    assert drive(b, run_id, wf)["state"] == "completed"
    assert len(wf.effects("a")) == 1


def test_wf05_stale_intent_checkpoint_is_rejected_before_any_act(wf: WfDb) -> None:
    """Intent is persisted (fenced) before acting: a stale attempt cannot even reach its act."""
    run_id = wf.request([plan_step("set", res="a", value="A")])
    a = wf.make_engine(clock=FakeClock())
    b = wf.make_engine()
    a.admit_pending()
    (claim_a,) = a.claim(1)
    wf.expire_leases()
    (claim_b,) = b.claim(1)
    assert a.execute(claim_a) == "commit_rejected"
    assert wf.effects() == []
    assert b.execute(claim_b) == "succeeded"
    assert len(wf.effects("a")) == 1
    assert wf.run(run_id)["state"] == "completed"


# ---- WF-05: SIGSTOP longer than the lease, then SIGCONT (real worker process) ------------------------------


def _proc_state(pid: int) -> str:
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]


@pytest.mark.parametrize("pause_at", ["after_probe", "after_act"])
def test_wf05_sigstop_beyond_lease_then_sigcont_is_refused_locally(wf: WfDb, pause_at: str) -> None:
    run_id = wf.request(
        [plan_step("set_destructive", res="c", value="C")], locks=[["volume", "v1"]]
    )
    proc = worker_process(wf, {"OVLM_TEST_CRASHPOINT": f"set_destructive.{pause_at}:stop"})
    try:
        _wait_for(lambda: _proc_state(proc.pid) == "T", 30, "worker stopped")
        # the paused worker cannot heartbeat: wait for the DB lease to expire (real time, documented sleep)
        _wait_for(
            lambda: bool(
                wf.q(
                    "SELECT 1 FROM workflow_step WHERE state = 'running' AND lease_expires_at < now()"
                )
            ),
            15,
            "lease expiry",
        )
        cfg = EngineConfig(**{**TEST_CONFIG.__dict__, "takeover_delay": 0.3})
        b = wf.make_engine(clock=SystemClock(), config=cfg)
        r = drive(b, run_id, wf)
        assert r["state"] == "completed"
        os.kill(proc.pid, signal.SIGCONT)
        _wait_for(lambda: _proc_state(proc.pid) != "T", 5, "worker resumed")
        time.sleep(
            1.0
        )  # let the resumed worker reach its next gate (documented real-process sleep)
    finally:
        os.kill(proc.pid, signal.SIGCONT)
        proc.send_signal(signal.SIGTERM)
        out, _ = proc.communicate(timeout=30)
    assert "fence gate refused an action" in out, out
    assert "attempt stopped by the fence" in out
    effects = wf.effects("c")
    assert len(effects) == 1  # exactly one effect on the "cloud"
    if pause_at == "after_probe":
        assert effects[0]["worker_id"] == b.worker_id  # A's mutating call was refused locally
    else:
        assert effects[0]["worker_id"] != b.worker_id  # A acted before the pause; B only verified
        assert wf.steps(run_id)[0]["evidence"]["already"] is True
    outcomes = [a["outcome"] for a in wf.attempts(run_id)]
    assert outcomes == ["lost", "succeeded"]
    assert wf.locks() == []


# ---- WF-06: limit of fencing -------------------------------------------------------------------------------


class _LandingClock(FakeClock):
    """B's clock: during B's takeover delay the stale in-flight request lands (as it would in real time)."""

    def __init__(self, on_sleep: Callable[[], None]) -> None:
        super().__init__()
        self._on_sleep = on_sleep

    def sleep(self, seconds: float, interrupt: threading.Event | None = None) -> bool:
        self._on_sleep()
        return super().sleep(seconds, interrupt)


def test_wf06_in_flight_call_of_stale_worker_lands_during_takeover_delay(wf: WfDb) -> None:
    run_id = wf.request([plan_step("inflight", res="f", value="F", name="wf06")], phase="window")
    clock_a = FakeClock()
    a = wf.make_engine(clock=clock_a)
    gate = BeatGate(a)
    a.admit_pending()
    (claim_a,) = a.claim(1)
    t, out = _in_thread(lambda: a.execute(claim_a))
    _wait_for(
        lambda: "wf06" in BLOCKERS, 5, "request in flight"
    )  # A passed the gate; request on the wire
    gate.hold()  # A's live heartbeat must not extend the lease between the expiry and B's claim
    wf.expire_leases()

    def land() -> None:
        BLOCKERS["wf06"].set()
        _wait_for(lambda: len(wf.effects("f")) == 1, 5, "stale request landed")

    clock_b = _LandingClock(land)
    b = wf.make_engine(clock=clock_b)
    (claim_b,) = b.claim(1)
    gate.resume()  # A's next beat matches 0 rows now: it may fence A (fence_lost) before A's commit is refused
    clock_a.advance(TEST_CONFIG.lease_duration)
    assert b.execute(claim_b) == "succeeded"
    assert clock_b.sleeps[0] == TEST_CONFIG.takeover_delay  # wait, then probe
    t.join(5)
    assert out[0] in ("fence_lost", "commit_rejected")
    assert len(wf.effects("f")) == 1  # B's probe saw A's landed effect: no duplicate
    assert wf.steps(run_id)[0]["evidence"] == {"already": True}
    assert wf.run(run_id)["state"] == "completed"


# ---- WF-07: self-fencing -----------------------------------------------------------------------------------


def test_wf07_zero_row_heartbeat_stops_the_step_at_once(wf: WfDb) -> None:
    cfg = EngineConfig(**{**TEST_CONFIG.__dict__, "heartbeat_interval": 0.05})
    run_id = wf.request([plan_step("block", res="k", value="K", name="wf07a")])
    a = wf.make_engine(
        config=cfg, clock=FakeClock(sleep_advances=False)
    )  # deadline never passes alone
    a.admit_pending()
    (claim,) = a.claim(1)
    before = m.HEARTBEAT_LOST._value.get()  # noqa: SLF001
    t, out = _in_thread(lambda: a.execute(claim))
    _wait_for(lambda: "wf07a" in BLOCKERS, 5, "step acting")
    # another worker took the step (simulated: new token and owner)
    wf.x(
        "UPDATE workflow_step SET fencing_token = nextval('fencing_seq'), lease_owner = 'other' "
        "WHERE id = :id",
        id=claim.step.id,
    )
    t.join(5)
    assert out == ["fence_lost"]
    assert m.HEARTBEAT_LOST._value.get() == before + 1  # noqa: SLF001
    assert REVOKED and REVOKED[0][0] == "wf07a" and "0 rows" in REVOKED[0][1]
    BLOCKERS["wf07a"].set()
    assert wf.effects() == []  # nothing sent after the loss
    assert wf.run(run_id)["state"] == "running"


def test_wf07_database_unreachable_self_fences_at_local_deadline(wf: WfDb) -> None:
    """Heartbeats fail (worker role cannot reach the DB): the step stops at its *local* deadline and revoke
    callbacks fire (the automation runner kills non-data subprocesses there)."""
    cfg = EngineConfig(
        **{
            **TEST_CONFIG.__dict__,
            "lease_duration": 2.0,
            "fence_margin": 0.5,
            "heartbeat_interval": 0.1,
        }
    )
    run_id = wf.request([plan_step("block", res="k", value="K", name="wf07b")])
    a = wf.make_engine(clock=SystemClock(), config=cfg)
    a.admit_pending()
    (claim,) = a.claim(1)
    started = time.monotonic()
    t, out = _in_thread(lambda: a.execute(claim))
    _wait_for(lambda: "wf07b" in BLOCKERS, 5, "step acting")
    try:
        wf.x("ALTER ROLE ovlm_worker NOLOGIN")
        with wf.admin.connect() as c:
            c.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE usename = 'ovlm_worker' AND datname = current_database()"
                )
            )
        t.join(10)
        elapsed = time.monotonic() - started
    finally:
        wf.x("ALTER ROLE ovlm_worker LOGIN")
    assert out == ["fence_lost"]
    assert elapsed < cfg.lease_duration  # stopped before the DB lease could expire
    assert ("wf07b", "local fence deadline passed") in REVOKED
    BLOCKERS["wf07b"].set()
    assert wf.effects() == []
    # after recovery the lease expires and a new attempt resumes from a probe
    wf.expire_leases()
    assert drive(wf.make_engine(), run_id, wf)["state"] == "completed"
    assert len(wf.effects("k")) == 1


def test_wf07_late_heartbeat_after_the_local_fence_does_not_extend_the_lease(wf: WfDb) -> None:
    """A heartbeat stuck on the connection while the attempt fenced itself must not extend the lease once the DB is
    reachable again: the attempt has stopped, and a late extension only delays the takeover (WF-07 flake)."""
    from ovlm.workflow.fence import Fence

    run_id = wf.request([plan_step("block", res="k", value="K", name="wf07c")])
    a = wf.make_engine(clock=SystemClock())
    a.admit_pending()
    (claim,) = a.claim(1)
    fence = Fence(
        clock=SystemClock(), lease_duration=60.0, fence_margin=1.0, t_send=time.monotonic()
    )
    wf.expire_leases()

    def lease() -> Any:
        with wf.admin.connect() as c:
            q = "SELECT lease_expires_at FROM workflow_step WHERE id = :id"
            return c.execute(text(q), {"id": claim.step.id}).scalar()

    expired = lease()
    fence.revoke("local fence deadline passed")
    assert a.heartbeat(claim, fence) is False
    after = lease()
    assert after == expired, "a heartbeat after the local fence extended the lease"
    assert wf.run(run_id)["state"] == "running"


@pytest.mark.parametrize(
    "exc",
    [SimulatedCrash("set.after_claim"), RuntimeError("bug outside the step contract")],
    ids=["simulated_crash", "exception"],
)
def test_wf07_heartbeat_in_flight_when_the_attempt_raises_cannot_extend_the_lease(
    wf: WfDb, exc: BaseException
) -> None:
    """CI flake 2026-11-09 (renewal crash window): an attempt that leaves ``execute`` by an exception must stop
    and fence its heartbeat before the exception escapes. Before the fix a beat that was already due went out
    after the attempt had gone and extended the lease by a full ``lease_duration`` (a crash harness had already
    expired it; in a live worker an exception logged by the step thread had the same effect): the takeover
    waited for a lease that no attempt held any more."""
    run_id = wf.request([plan_step("set", res="k", value="K")])
    a = wf.make_engine()
    a.admit_pending()
    (claim,) = a.claim(1)
    plan = CrashWithBeatDue("set.after_claim", exc=exc)
    crashpoint.install(plan)
    with pytest.raises(type(exc)):
        a.execute(claim)
    # the attempt is gone: the dead worker's lease runs out (what the crash harnesses do), then the held beat
    # is released; with the fix ``execute`` has already waited for it, and it was refused
    wf.expire_leases()
    plan.release()
    crashpoint.install(None)
    (step,) = wf.steps(run_id)
    assert step["state"] == "running" and step["attempt"] == 1
    assert step["lease_expires_at"] < wf.one("SELECT now() AS n")["n"], (
        "a heartbeat sent after the attempt raised extended its lease"
    )
    b = wf.make_engine()
    (claim_b,) = b.claim(1)
    assert claim_b.takeover and claim_b.step.attempt == 2
    assert b.execute(claim_b) == "succeeded"
    assert drive(b, run_id, wf)["state"] == "completed"
    assert [e["key"] for e in wf.effects()] == ["k"]


def test_wf07_beat_whose_attempt_ended_during_the_update_is_rolled_back(wf: WfDb) -> None:
    """The other half of the fix: a beat that outlived ``_Heartbeater.stop``'s bounded wait (its UPDATE was on
    the wire when the attempt ended) re-checks the fence before COMMIT and rolls the extension back."""
    from sqlalchemy import event as sa_event

    from ovlm.workflow.fence import Fence

    run_id = wf.request([plan_step("block", res="k", value="K", name="wf07d")])
    a = wf.make_engine(clock=SystemClock())
    a.admit_pending()
    (claim,) = a.claim(1)
    wf.expire_leases()
    fence = Fence(
        clock=SystemClock(), lease_duration=60.0, fence_margin=1.0, t_send=time.monotonic()
    )

    def end_attempt_during_update(_c: Any, _cur: Any, stmt: str, *_a: Any) -> None:
        if stmt.lstrip().startswith("UPDATE workflow_step"):
            fence.close("attempt ended")

    sa_event.listen(a.db, "after_cursor_execute", end_attempt_during_update)
    try:
        assert a.heartbeat(claim, fence) is False
    finally:
        sa_event.remove(a.db, "after_cursor_execute", end_attempt_during_update)
    lease = wf.one(
        "SELECT lease_expires_at < now() AS expired FROM workflow_step WHERE id = :id",
        id=claim.step.id,
    )
    assert lease["expired"], "a beat whose attempt ended during the UPDATE extended the lease"
    assert wf.run(run_id)["state"] == "running"


# ---- WF-09: connection loss mid-step, mid-wait and idle ----------------------------------------------------


def _terminate_worker_backends(wf: WfDb) -> None:
    with wf.admin.connect() as c:
        c.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE usename = 'ovlm_worker' AND datname = current_database()"
            )
        )


def test_wf09_connection_loss_mid_step_mid_wait_and_idle(wf: WfDb) -> None:
    """A full PostgreSQL restart is not possible against the CI service container; every worker connection is
    killed instead (what the worker observes of a restart). Reconnect via pool pre-ping; nothing doubled."""
    run_id = wf.request(
        [
            plan_step("set", res="a", value="A"),
            plan_step("async", res="b", value="B", polls=2),
            plan_step("set_destructive", res="c", value="C"),
        ]
    )
    eng = wf.make_engine()
    crashpoint.install(
        CrashPlan("set.after_act", 1, action=lambda _n: _terminate_worker_backends(wf))
    )
    eng.run_once()  # mid-step: the outcome commit reconnects
    crashpoint.install(None)
    _terminate_worker_backends(wf)  # idle
    eng.run_once()
    assert [s["state"] for s in wf.steps(run_id)][-1] == "waiting"
    _terminate_worker_backends(wf)  # mid-wait
    r = drive(eng, run_id, wf)
    assert r["state"] == "completed"
    assert sorted(e["key"] for e in wf.effects()) == ["a", "b", "c"]
    assert all(a["outcome"] for a in wf.attempts(run_id))


# ---- WF-08 (engine part): per-step lease covering a bounded subprocess ---------------------------------------


def test_wf08_step_lease_covers_its_subprocess_timeout(wf: WfDb) -> None:
    """A step declaring ``lease_for`` (Ansible: hard timeout + kill grace + fence_margin) holds that lease from
    before its probe; a dead worker's step is not claimable until it ends. The orphan kill itself is E5-3."""
    run_id = wf.request([plan_step("block", res="k", value="K", name="wf08", lease=3600)])
    a = wf.make_engine(clock=FakeClock(sleep_advances=False))
    a.admit_pending()
    (claim,) = a.claim(1)
    t, out = _in_thread(lambda: a.execute(claim))
    _wait_for(lambda: "wf08" in BLOCKERS, 5, "step acting")
    left = wf.one(
        "SELECT EXTRACT(EPOCH FROM lease_expires_at - now()) AS left FROM workflow_step WHERE run_id = :id",
        id=run_id,
    )["left"]
    assert 3500 < float(left) <= 3600
    assert wf.make_engine().claim(1) == []  # nobody can take over while the subprocess may run
    BLOCKERS["wf08"].set()
    t.join(5)
    assert out == ["succeeded"]
