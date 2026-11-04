"""WF-01 crash-point matrix (testing-strategy.md section 4.1) on a real PostgreSQL, with dummy steps.

Enumeration: one uninterrupted run records every crash point hit, in order, with occurrence index. The expected
list is pinned below; a change in the engine's crash points (or a new step) fails ``test_enumeration`` until the
matrix is updated, so no point goes untested.

Matrix: for each point, crash there (``SimulatedCrash`` in-process; ``os._exit(137)`` in a real worker process for
the L2 subset), "restart" with a new worker (new ``lease_owner``), let the lease expire, run to completion, then
check the oracle.
"""

from __future__ import annotations

import collections
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest

from ovlm.workflow import crashpoint
from ovlm.workflow.clock import FakeClock
from ovlm.workflow.crashpoint import CrashPlan, SimulatedCrash
from tests.integration.conftest import ROOT
from tests.integration.workflow.conftest import TEST_CONFIG, RecordingAudit, WfDb, drive
from tests.integration.workflow.dummy import BLOCKERS, plan_step

LOCKS = [["service", "svc-1"], ["server", "blue-1"], ["volume", "vol-1"]]

EXPECTED_POINTS = [
    "run.create",
    *(f"set.{p}" for p in ("after_claim", "after_probe", "after_intent", "after_act")),
    "set.after_verify_before_commit",
    "set.after_commit",
    *(f"async.{p}" for p in ("after_claim", "after_probe", "after_intent", "after_act")),
    "async.after_verify_before_commit",
    "async.after_commit",
    *["async.after_claim", "async.after_probe", "async.after_verify_before_commit", "async.after_commit"] * 2,
    *(f"set_destructive.{p}" for p in ("after_claim", "after_probe", "after_intent", "after_act")),
    "set_destructive.after_verify_before_commit",
    "lease.release",
    "set_destructive.after_commit",
]


def _with_occurrence(points: list[str]) -> list[tuple[str, int]]:
    seen: collections.Counter[str] = collections.Counter()
    out = []
    for p in points:
        seen[p] += 1
        out.append((p, seen[p]))
    return out


MATRIX = _with_occurrence(EXPECTED_POINTS)


def test_enumeration(wf: WfDb, plan3: Callable[[], list[dict[str, Any]]]) -> None:
    rec: list[str] = []
    crashpoint.record(rec)
    run_id = wf.request(plan3(), locks=LOCKS)
    drive(wf.make_engine(), run_id, wf)
    crashpoint.record(None)
    assert [p for p in rec if p != "lease.heartbeat"] == EXPECTED_POINTS
    # coverage rule (testing-strategy.md 4.1.2): every acting step has after_intent and after_act points
    for key in ("set", "async", "set_destructive"):
        assert f"{key}.after_intent" in rec and f"{key}.after_act" in rec


def _oracle(wf: WfDb, run_id: str) -> None:
    """Invariants of testing-strategy.md 4.1.6 that apply to the generic engine."""
    r = wf.run(run_id)
    assert r["state"] == "completed", r  # defined end state, never stuck running
    # same final "cloud" state as the uninterrupted run
    assert (wf.resource("a"), wf.resource("b"), wf.resource("c")) == ("A", "B", "C")
    assert wf.one("SELECT pending_polls FROM fake_resource WHERE key = 'b'")["pending_polls"] == 0
    # no duplicated effect: every mutating call happened exactly once (probe-first + intent-before-act)
    assert sorted(e["key"] for e in wf.effects()) == ["a", "b", "c"]
    # no double-applied step: one committed success per step, no extra step rows
    steps = wf.steps(run_id)
    assert [s["step_key"] for s in steps] == ["set", "async", "set_destructive"]
    assert all(s["state"] == "succeeded" for s in steps)
    # attempts: every attempt closed with an outcome, attempt numbers contiguous (none lost)
    by_step: dict[str, list[int]] = collections.defaultdict(list)
    for a in wf.attempts(run_id):
        assert a["outcome"] is not None and a["ended_at"] is not None
        by_step[a["step_key"]].append(a["attempt"])
    for nums in by_step.values():
        assert nums == list(range(1, len(nums) + 1))
    tokens = [a["fencing_token"] for a in wf.attempts(run_id)]
    assert len(set(tokens)) == len(tokens)  # a fresh fencing token per attempt
    assert wf.locks() == []  # released in the terminal transaction only


def _crash_in_process(wf: WfDb, point: str, occurrence: int) -> None:
    plan = CrashPlan(point, occurrence, "raise")
    crashpoint.install(plan)
    a = wf.make_engine()
    with pytest.raises(SimulatedCrash):
        for _ in range(100):
            a.run_once()
    crashpoint.install(None)
    assert plan.fired


@pytest.mark.parametrize(("point", "occurrence"), MATRIX, ids=[f"{p}#{n}" for p, n in MATRIX])
def test_crash_at_every_point_in_process(
    wf: WfDb, plan3: Callable[[], list[dict[str, Any]]], point: str, occurrence: int
) -> None:
    run_id = wf.request(plan3(), locks=LOCKS)
    _crash_in_process(wf, point, occurrence)
    audit = RecordingAudit()
    state = wf.run(run_id)["state"]
    if point == "run.create":
        assert state == "requested" and wf.locks() == []  # admission rolled back as a whole
    elif state != "completed":
        # locks are held by the run across the crash (not by the dead worker)
        assert sorted(map(list, wf.locks(run_id))) == sorted(LOCKS)
    running = [s for s in wf.steps(run_id) if s["state"] == "running"]
    wf.expire_leases()
    clock = FakeClock()
    b = wf.make_engine(clock=clock, audit=audit)
    drive(b, run_id, wf)
    _oracle(wf, run_id)
    if running:
        assert "step.takeover" in audit.actions()
        (dead,) = running
        outcomes = [a["outcome"] for a in wf.attempts(run_id) if a["step_id"] == dead["id"]]
        assert "lost" in outcomes
        # SEC-R-26 / SRE-R-27: the takeover of a destructive step waits before probing; others do not
        delay_expected = dead["destructive"]
        assert (TEST_CONFIG.takeover_delay in clock.sleeps) == delay_expected


# ---- L2: real process death (os._exit(137)) and an external SIGKILL ---------------------------------------

REAL_KILL_POINTS = [
    ("run.create", 1),
    ("set.after_intent", 1),
    ("async.after_act", 1),
    ("async.after_commit", 2),
    ("set_destructive.after_act", 1),
    ("set_destructive.after_verify_before_commit", 1),
    ("lease.release", 1),
]


def worker_process(wf: WfDb, extra_env: dict[str, str]) -> subprocess.Popen[str]:
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("OVLM_")},
        "OVLM_CONFIG_FILE": "/nonexistent",
        "WF_WORKER_URL": wf.worker_url.render_as_string(hide_password=False),
        "OVLM_WORKER__HEARTBEAT_INTERVAL": "0.2",
        "OVLM_WORKER__LEASE_DURATION": "3",
        "OVLM_WORKER__FENCE_MARGIN": "0.8",
        "OVLM_WORKER__TAKEOVER_DELAY": "1",
        "OVLM_POLL__INITIAL_INTERVAL": "0.05",
        "OVLM_POLL__MAX_INTERVAL": "0.05",
        **extra_env,
    }
    return subprocess.Popen(
        [sys.executable, "-m", "tests.integration.workflow.worker_proc"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@pytest.mark.parametrize(
    ("point", "occurrence"), REAL_KILL_POINTS, ids=[f"{p}#{n}" for p, n in REAL_KILL_POINTS]
)
def test_real_process_exit_at_crash_points(
    wf: WfDb, plan3: Callable[[], list[dict[str, Any]]], point: str, occurrence: int
) -> None:
    run_id = wf.request(plan3(), locks=LOCKS)
    proc = worker_process(wf, {"OVLM_TEST_CRASHPOINT": f"{point}@{occurrence}:exit"})
    out, _ = proc.communicate(timeout=60)
    assert proc.returncode == 137, out
    assert f"crashpoint {point}: exit" in out
    wf.expire_leases()
    drive(wf.make_engine(), run_id, wf)
    _oracle(wf, run_id)


def test_external_sigkill_mid_step(wf: WfDb) -> None:
    """No cooperating hook: the worker is SIGKILLed while a step runs (and heartbeats)."""
    run_id = wf.request([plan_step("block", res="k", value="K", name="sigkill")], locks=LOCKS)
    proc = worker_process(wf, {})
    try:
        _wait_for(lambda: _heartbeated(wf, run_id), 30)
    finally:
        proc.kill()
        proc.communicate(timeout=30)
    assert proc.returncode == -9
    assert sorted(map(list, wf.locks(run_id))) == sorted(LOCKS)
    assert wf.effects() == []
    wf.expire_leases()
    BLOCKERS.setdefault("sigkill", threading.Event()).set()
    r = drive(wf.make_engine(), run_id, wf)
    assert r["state"] == "completed"
    assert [e["key"] for e in wf.effects()] == ["k"]
    assert [a["outcome"] for a in wf.attempts(run_id)] == ["lost", "succeeded"]
    assert wf.locks() == []


def _heartbeated(wf: WfDb, run_id: str) -> bool:
    rows = wf.q(
        "SELECT 1 FROM workflow_step s JOIN workflow_step_attempt a ON a.step_id = s.id "
        "AND a.attempt = s.attempt WHERE s.run_id = :id AND s.state = 'running' "
        "AND s.heartbeat_at > a.started_at",
        id=run_id,
    )
    return bool(rows)


def _wait_for(cond: Callable[[], bool], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached")
        time.sleep(0.05)
