"""``accept-step`` (ADR-0008, roadmap P0-2): the approver's audited exit when a restore step's own pinned playbook
refuses a state OVLM verified safe.

T-D8 reproduces lab finding D-8 against the fake cloud and the fake guest: the worker dies after W5 (volume attached
to green) and before W6 (mount); the operator rolls back; S2 runs the run's pinned ``quiesce.yml``, which predates
lab fix AA (``FakeGuest.pre_aa_role``: it ignores ``quiesce_allow_unmounted``) and refuses "not mounted, no earlier
quiesce record". retry-step and mark-resolved re-run the same playbook and park again. Before this change no OVLM
path was left (the lab mounted the volume on green by hand). With it, an approver who is not the run's requester
probes, then accepts S2: OVLM's own read-only probe shows the postcondition, S2 is closed without running its
playbook, S3-S10 converge with the volume and the FIP back on blue, and no guest was changed by hand.

The refusals, the late outcome of the parked attempt, the table rules and the api checks follow.
"""

from __future__ import annotations

import json
import time
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
import sqlalchemy.exc
from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm.auth.errors import ProblemError
from ovlm.auth.principal import Principal
from ovlm.registry.errors import DomainError
from ovlm.renewal import metrics
from ovlm.renewal import service as svc
from ovlm.renewal.reprobe import REPROBE_KIND, REPROBE_STRATEGY
from ovlm.workflow import crashpoint
from ovlm.workflow.clock import FakeClock
from ovlm.workflow.contract import Done
from ovlm.workflow.crashpoint import CrashPlan
from ovlm.workflow.fence import Fence, FencedCommitRejected
from ovlm.workflow.requests import request_run, send_signal
from tests.integration.renewal.conftest import World, explain, to_cutover
from tests.integration.renewal.test_failures import restored

ATTESTATION = (
    "Checked on green: lsblk shows the data device mounted nowhere, /srv/data is not a mount, app.service is "
    "inactive. The old quiesce role refuses 'never mounted', which is safe to detach."
)


def _crash(target: str) -> None:
    crashpoint.install(CrashPlan(target=target, mode="raise"))


def park_s2(w: World) -> Any:
    """D-8: W5 attached the volume to green, the worker died before W6 mounted it, rollback; S2's pinned playbook
    (before fix AA) refuses the never-mounted green. Returns the parked S2 step."""
    w.guest.pre_aa_role = True
    to_cutover(w)
    _crash("data_attach_green.after_intent")
    w.drive()
    r = w.run()
    assert r["needs_human_reason"] == "data_phase_interrupted", explain(w)
    green = w.green_id()
    assert green is not None and w.attached() == [green] and not w.guest.g(green).mounted
    w.signal("rollback", tc=w.blue_tc())
    w.drive()
    return parked_s2(w)


def parked_s2(w: World) -> Any:
    r = w.run()
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "quiesce_green_failed", (
        explain(w)
    )
    st = w.open_step()
    assert st["step_key"] == "quiesce_green" and st["state"] == "needs_human", explain(w)
    assert st["error"]["playbook_reported"] == "needs_human", st["error"]
    return st


def probe(w: World, user: str = "ap2") -> dict[str, Any]:
    """The Re-probe button: a probe signal (an approver may send it), applied by the worker."""
    sig = w.signal("probe", user=user)
    w.drive()
    out = w.q("SELECT outcome FROM run_signal WHERE id = :i", i=sig)[0]["outcome"]
    assert out == "current truth refreshed", out
    p = w.run()["current_truth"].get("accept_probe")
    assert p is not None, w.run()["current_truth"]
    return dict(p)


def who(w: World, user: str, roles: tuple[str, ...] = ("approver",)) -> Principal:
    return Principal(
        user_id=UUID(w.users[user]), username=f"user-{user}", principal_type="human",
        auth_method="password+totp", grants=frozenset((r, w.ids["scope"]) for r in roles), session_hash="sess",
    )  # fmt: skip


def api_accept(
    w: World, user: str = "ap2", *, roles: tuple[str, ...] = ("approver",), tc: str | None = None,
    attestation: str = ATTESTATION, probe_id: str | None = None, stepup: str | None | bool = True,
) -> dict[str, Any]:  # fmt: skip
    """``POST /runs/{id}/actions/accept-step`` as the api handles it (service layer, ``ovlm_api`` role)."""
    st = w.open_step()
    if probe_id is None:
        probe_id = str((w.run()["current_truth"] or {}).get("accept_probe", {}).get("id"))
    sid = (
        w.stepup(user, "run.accept_step", w.run_id, consumed=False)
        if stepup is True
        else (stepup or None)
    )
    with Session(w.api) as s:
        out = svc.action(
            s, who(w, user, roles), UUID(w.run_id), "accept-step", typed=tc or w.green_tc(),
            stepup_id=UUID(sid) if sid else None, attestation=attestation, step_id=st["id"] if st else None,
            probe_id=probe_id,
        )  # fmt: skip
        s.commit()
    return out


def worker_accept(w: World, user: str = "ap2", **kw: Any) -> str:
    """An accept_step signal written directly (bypassing the api's checks): the worker re-validates everything."""
    st = w.open_step()
    p = (w.run()["current_truth"] or {}).get("accept_probe") or {}
    payload = {"step_id": str(st["id"]) if st else None, "attempt": st["attempt"] if st else None,
               "probe_id": p.get("id"), "attestation": ATTESTATION}  # fmt: skip
    tc = kw.pop("tc", None) or w.green_tc()
    good = kw.pop("good_stepup", True)
    payload |= kw
    return w.signal("accept_step", user=user, tc=tc, good_stepup=good, **payload)


def outcome(w: World, sig: str) -> str:
    return str(w.q("SELECT outcome FROM run_signal WHERE id = :i", i=sig)[0]["outcome"])


def acceptances(w: World) -> list[Any]:
    return w.q("SELECT * FROM step_acceptance WHERE run_id = :r ORDER BY created_at", r=w.run_id)


def age_probe(w: World, seconds: float) -> None:
    truth = w.run()["current_truth"]
    at = datetime.fromisoformat(truth["accept_probe"]["at"]) - timedelta(seconds=seconds)
    truth["accept_probe"]["at"] = at.isoformat()
    w.x(
        "UPDATE workflow_run SET current_truth = CAST(:t AS jsonb) WHERE id = :r",
        t=json.dumps(truth),
        r=w.run_id,
    )


def counter() -> float:
    return float(metrics.STEP_ACCEPTED.labels("quiesce_green")._value.get())  # noqa: SLF001


# --- T-D8 -----------------------------------------------------------------------------------------------------------


def test_d8_retry_and_mark_resolved_park_again_accept_step_converges(world: World) -> None:
    w = world
    s2 = park_s2(w)
    green = w.green_id()
    assert green is not None
    assert w.guest.quiesce_calls[-1] == (
        green,
        True,
    )  # OVLM passed the AA flag; the old role ignored it

    # retry-step re-runs the same pinned playbook: parks again
    w.signal("retry_step")
    w.drive()
    parked_s2(w)
    # mark-resolved re-queues the step, which must reach Done from its own probe and act: parks again (SRE-C-2)
    w.signal(
        "mark_resolved", user="ap2", tc=w.blue_tc(), attestation="nothing to fix on green, see S2"
    )
    w.drive()
    st = parked_s2(w)
    assert (
        st["id"] == s2["id"]
        and [c for c in w.guest.quiesce_calls if c[0] == green] == [(green, True)] * 3
    )

    # the action is listed but not usable before OVLM probed the postcondition
    with Session(w.api) as s:
        offer = next(
            a
            for a in svc.run_body(s, w.run_id)["available_actions"]
            if a["action"] == "accept-step"
        )
    assert offer["available"] is False and "press Probe first" in offer["effect"]

    p = probe(w)  # an approver (no operator role) may re-probe: read-only
    assert p["ok"] is True and p["step_id"] == str(st["id"]) and p["attempt"] == st["attempt"], p
    assert {c["check"] for c in p["checks"]} == {
        "cloud_reachable", "green_active", "volume_on_green_only", "guest_reachable", "data_device_mounted_nowhere",
        "mount_point_not_a_mount", "service_units_stopped",
    }  # fmt: skip
    assert (
        p["guest"]["unit_states"] == {"app.service": "inactive"}
        and p["guest"]["device_mounted"] is False
    )
    with Session(w.api) as s:
        offer = next(
            a
            for a in svc.run_body(s, w.run_id)["available_actions"]
            if a["action"] == "accept-step"
        )
    assert offer["available"] is True and offer["probe_id"] == p["id"], offer
    assert "without running quiesce.yml" in offer["effect"] and "S3 stops green" in offer["effect"]

    before, calls_before = counter(), list(w.guest.calls)
    locks_before = w.locks()
    pin_before = w.q(
        "SELECT plan_hash, resolved -> 'automation' AS a FROM renewal_plan WHERE id = :p",
        p=w.ids["plan"],
    )
    api_accept(w)
    assert w.locks() == locks_before  # nothing changes before the worker applies it
    r = w.drive()

    # S2 closed without running its playbook; S3-S10 ran on their own
    restored(w)
    assert r["state"] == "running" and w.open_step()["step_key"] == "await_discard", explain(w)
    s2_row = next(s for s in w.steps() if s["id"] == st["id"])
    assert s2_row["state"] == "succeeded" and s2_row["resolution"] == "accepted", s2_row
    ev = s2_row["evidence"]
    assert ev["playbook_not_run"] is True and ev["resolution"] == "accepted"
    assert ev["marker_comparison"] == "skipped: step accepted, playbook not run"
    acc = ev["accepted"]
    assert (
        acc["by"] == w.users["ap2"]
        and acc["playbook_not_run"] is True
        and acc["attestation"] == ATTESTATION
    )
    assert (
        acc["probe_id"] == p["id"]
        and acc["probe"]["ok"] is True
        and acc["attestation_ref"].startswith("step_acceptance:")
    )
    keys = w.keys()
    assert keys[keys.index("quiesce_green") + 1 :] == [
        "stop_green", "detach_from_green", "attach_to_old", "boot_old", "recover_old_service", "move_fip_to_old",
        "verify_external_old", "lock_green", "await_discard",
    ]  # fmt: skip
    # no quiesce, mount or any other playbook on green after the accept; only OVLM's read-only probes reached it
    new_calls = w.guest.calls[len(calls_before) :]
    assert all(sid != green for _, sid in new_calls), new_calls
    assert ("data_attach", green) not in w.guest.calls and not w.guest.g(green).mounted
    assert (green, w.ids["volume"]) in w.guest.probes
    # one accepted row, the audit trail, the metric
    [row] = acceptances(w)
    assert (
        row["outcome"] == "accepted"
        and str(row["approver_id"]) == w.users["ap2"]
        and row["step_key"] == "quiesce_green"
    )
    assert (
        row["attempt"] == st["attempt"]
        and row["probe_id"] == p["id"]
        and row["attestation"] == ATTESTATION
    )
    assert row["pinned_sha"] == "a" * 40 and row["parked_reason"] == "quiesce_green_failed"
    assert (
        row["refused_result_sha256"] == acc["refused_result_sha256"]
        and len(row["refused_result_sha256"]) == 64
    )
    actions = w.audit_actions()
    assert actions.index("run.accept_step.requested") < actions.index("run.accept_step.accepted")
    assert "run.accept_step.refused" not in actions
    assert counter() == before + 1
    # nothing changed in the pin, the plan hash or the approvals
    after = w.q(
        "SELECT plan_hash, resolved -> 'automation' AS a FROM renewal_plan WHERE id = :p",
        p=w.ids["plan"],
    )
    assert after == pin_before
    # downtime: the window interval (open since W1) closed at S9, and only there
    [dt] = w.q("SELECT * FROM run_downtime WHERE run_id = :r", r=w.run_id)
    assert dt["kind"] == "window" and dt["ended_by_step"] == "verify_external_old", dt
    # the run summary names the accepted step
    with Session(w.api) as s:
        body = svc.run_body(s, w.run_id)
    assert [a["step_key"] for a in body["accepted_steps"]] == ["quiesce_green"]

    # discard: the run ends rolled_back with no lock left; data safety held after every pass (check_invariants)
    w.signal("discard", tc=w.green_tc())
    r = w.drive()
    assert r["state"] == "rolled_back" and w.locks() == [], explain(w)
    assert w.attached() == [w.ids["blue"]] and w.fip_port() == w.ids["blue_port"]


def test_without_accept_step_d8_has_no_exit(world: World) -> None:
    """Control: after the refusals, nothing OVLM offers moves S2 except accept-step (lab: a manual mount)."""
    w = world
    park_s2(w)
    with Session(w.api) as s:
        names = [a["action"] for a in svc.run_body(s, w.run_id)["available_actions"]]
    assert "reprepare-automation" not in names and "rollback" not in names and "abort" not in names
    assert "accept-step" in names


# --- refusals at the worker (the signal bypasses the api) -----------------------------------------------------------


def _refused(w: World, sig: str, code: str) -> None:
    w.drive()
    out = outcome(w, sig)
    assert out.startswith(f"refused: {code}"), out
    assert w.run()["state"] == "needs_human"  # nothing moved
    rows = [a for a in acceptances(w) if str(a["signal_id"]) == sig]
    assert len(rows) == 1 and rows[0]["outcome"] == "refused" and rows[0]["refusal_code"] == code, (
        rows
    )
    audits = w.q(
        "SELECT after FROM audit_event WHERE run_id = :r AND action = 'run.accept_step.refused'",
        r=w.run_id,
    )
    assert any(
        a["after"]["refusal_code"] == code and a["after"]["signal_id"] == sig for a in audits
    ), audits


@pytest.mark.parametrize(
    "case",
    ["requester", "operator", "stepup", "tc", "attestation", "stale", "probe_id", "attempt"],
)
def test_worker_refuses_an_invalid_accept(world: World, case: str) -> None:
    w = world
    park_s2(w)
    probe(w)
    cases: dict[str, tuple[str, dict[str, Any], str]] = {
        "requester": ("sod-violation", {}, "op"),
        "operator": ("forbidden", {}, "op"),
        "stepup": ("stepup-invalid", {"good_stepup": False}, "ap2"),
        "tc": ("confirmation-mismatch", {"tc": "app01-prod 000000"}, "ap2"),
        "attestation": ("attestation-invalid", {"attestation": "looks fine"}, "ap2"),
        "stale": ("probe-stale", {}, "ap2"),
        "probe_id": ("probe-mismatch", {"probe_id": "0" * 32}, "ap2"),
        "attempt": ("not-applicable", {"attempt": 99}, "ap2"),
    }
    code, kw, user = cases[case]
    # op started the run and created the plan; for "requester", op holds the approver role too
    if case == "requester":
        w.x("INSERT INTO role_binding (id, user_id, role, scope, created_at) VALUES "
            "(gen_random_uuid(), :u, 'approver', :s, now() - interval '1 day')", u=w.users["op"], s=w.ids["scope"])  # fmt: skip
    if case == "stale":
        age_probe(w, 61)
    sig = worker_accept(w, user, **kw)
    _refused(w, sig, code)
    assert w.run()["state"] == "needs_human" and acceptances(w)[-1]["outcome"] == "refused"
    assert not any(a["outcome"] == "accepted" for a in acceptances(w))


@pytest.mark.parametrize(
    "state", ["device_elsewhere", "mount_point", "unit_active", "volume_on_blue"]
)
def test_worker_refuses_when_the_probe_does_not_show_the_postcondition(
    world: World, state: str
) -> None:
    w = world
    park_s2(w)
    green = w.green_id()
    assert green is not None
    p0 = probe(w)  # the approver saw a probe meeting the postcondition
    assert p0["ok"]
    g = w.guest.g(green)
    if state == "device_elsewhere":
        g.mounted_elsewhere = (
            True  # by-id device mounted at another path: findmnt on the mount point misses it
        )
    elif state == "mount_point":
        g.mounted = True
    elif state == "unit_active":
        g.units = True
    else:  # the volume is on another server than green (the fake moves it under OVLM)
        w.cloud.strict_gate = False
        w.cloud.detach_volume(green, w.ids["volume"])
        w.cloud.tick(60)
        w.cloud.attach_volume(w.ids["blue"], w.ids["volume"])
        w.cloud.tick(60)
        w.cloud.strict_gate = True
    # the worker's own probe, just before the commit, disagrees: refused
    sig = worker_accept(w)
    _refused(w, sig, "postcondition-not-met")
    # and a fresh probe now shows it: the api does not offer the action and refuses the request
    p = probe(w)
    assert p["ok"] is False
    with Session(w.api) as s:
        offer = next(
            a
            for a in svc.run_body(s, w.run_id)["available_actions"]
            if a["action"] == "accept-step"
        )
    assert offer["available"] is False and "does not show the postcondition" in offer["effect"], (
        offer
    )
    with pytest.raises(DomainError) as exc:
        api_accept(w)
    assert exc.value.code == "postcondition-not-met"


def test_worker_refuses_when_the_state_changed_since_the_probe_shown(world: World) -> None:
    w = world
    park_s2(w)
    probe(w)
    # the probe the approver saw still meets the postcondition but is not what the worker reads now (a unit the
    # approver saw "failed" reads "inactive"): any difference refuses, the approver must look again
    truth = w.run()["current_truth"]
    truth["accept_probe"]["guest"]["unit_states"] = {"app.service": "failed"}
    w.x(
        "UPDATE workflow_run SET current_truth = CAST(:t AS jsonb) WHERE id = :r",
        t=json.dumps(truth),
        r=w.run_id,
    )
    sig = worker_accept(w)
    _refused(w, sig, "probe-mismatch")


def test_pmr4_the_shown_probe_is_timestamped_when_taken_not_when_stored(world: World) -> None:
    """Review PMR-4 (a): the probe's ``at`` was the commit time of the probe signal, after the cloud reads and the
    SSH commands; the approver read a probe older than its timestamp by the probe's duration. ``at`` is now the
    database time read before the probe starts, and its duration is stored next to it."""
    w = world
    park_s2(w)
    w.guest.probe_hang = 1.5  # a slow green: each guest probe takes 1.5 s (well under the budget)
    sig = w.signal("probe", user="ap2")
    w.drive()
    assert outcome(w, sig) == "current truth refreshed"
    p = w.run()["current_truth"]["accept_probe"]
    [stored] = w.q("SELECT consumed_at FROM run_signal WHERE id = :i", i=sig)
    taken = datetime.fromisoformat(p["at"])
    assert (stored["consumed_at"] - taken).total_seconds() >= 1.4, (taken, stored["consumed_at"])
    assert p["duration_s"] >= 1.4, p
    # its age is judged from when it started: aged by the probe's duration already
    with Session(w.api) as s:
        now = s.execute(text("SELECT now()")).scalar_one()
    from ovlm.renewal import accept

    age = accept.probe_age(p, now)
    assert age is not None and age >= 1.4


def test_pmr8_a_replayed_stepup_does_not_authorize_another_accept_signal(world: World) -> None:
    """Review PMR-8 (REN-10 for the new kinds): the worker accepts an ``accept_step`` signal only with a step-up spent
    by **that** signal. A second signal carrying the step-up of an earlier one (a replay only a compromised api could
    write: the api's consume is single-use) is refused, and so is a step-up spent before the binding existed."""
    w = world
    park_s2(w)
    probe(w)
    # the approver's first request is refused (too short an attestation): its step-up is spent by that signal
    first = worker_accept(w, attestation="looks fine")
    _refused(w, first, "attestation-invalid")
    [payload] = [r["payload"] for r in w.q("SELECT payload FROM run_signal WHERE id = :i", i=first)]
    spent = payload["stepup_id"]
    [bound] = w.q("SELECT consumed_by_signal FROM stepup WHERE id = :i", i=spent)
    assert str(bound["consumed_by_signal"]) == first
    # replayed on a new, otherwise valid signal: refused, nothing accepted
    replay = worker_accept(w, stepup_id=spent)
    _refused(w, replay, "stepup-invalid")
    # a consumed step-up bound to no signal (spent before the binding, or by another path): refused too
    unbound = w.stepup("ap2", "run.accept_step", w.run_id)
    _refused(w, worker_accept(w, stepup_id=unbound), "stepup-invalid")
    assert not any(a["outcome"] == "accepted" for a in acceptances(w))
    # the same request with its own step-up goes through
    ok = worker_accept(w)
    w.drive()
    assert any(a["outcome"] == "accepted" and str(a["signal_id"]) == ok for a in acceptances(w)), (
        outcome(w, ok)
    )


def test_pmr8_the_api_binds_the_stepup_to_its_signal_and_cannot_rebind_it(world: World) -> None:
    w = world
    park_s2(w)
    probe(w)
    api_accept(w)
    [sig] = w.q(
        "SELECT id, payload FROM run_signal WHERE run_id = :r AND kind = 'accept_step'", r=w.run_id
    )
    [step] = w.q(
        "SELECT consumed_at, consumed_by_signal FROM stepup WHERE id = :i",
        i=sig["payload"]["stepup_id"],
    )
    assert step["consumed_at"] is not None and str(step["consumed_by_signal"]) == str(sig["id"])
    # write-once, whoever writes: the api role (which holds UPDATE on stepup) and the owner cannot rebind or re-arm
    for engine in (w.api, w.admin):
        for sql in (
            "UPDATE stepup SET consumed_by_signal = gen_random_uuid() WHERE id = :i",
            "UPDATE stepup SET consumed_by_signal = NULL WHERE id = :i",
            "UPDATE stepup SET consumed_at = NULL WHERE id = :i",
        ):
            with pytest.raises(sqlalchemy.exc.DBAPIError), engine.begin() as c:
                c.execute(text(sql), {"i": sig["payload"]["stepup_id"]})
    # a step-up binds at most one signal
    other = w.stepup("ap3", "run.accept_step", w.run_id, consumed=False)
    with pytest.raises(sqlalchemy.exc.IntegrityError), w.api.begin() as c:
        c.execute(
            text("UPDATE stepup SET consumed_at = now(), consumed_by_signal = :s WHERE id = :i"),
            {"s": str(sig["id"]), "i": other},
        )
    w.drive()
    assert any(a["outcome"] == "accepted" for a in acceptances(w)), explain(w)


def test_refused_when_s2_parked_on_an_interrupted_data_phase(world: World) -> None:
    """Maintainer decision Q3: S2 parked on data_phase_interrupted keeps retry-step as its exit."""
    w = world
    to_cutover(w)
    _crash("data_attach_green.after_intent")
    w.drive()
    w.signal("rollback", tc=w.blue_tc())
    _crash("quiesce_green.after_intent")
    w.drive()
    r = w.run()
    assert (
        r["needs_human_reason"] == "data_phase_interrupted"
        and w.open_step()["step_key"] == "quiesce_green"
    ), explain(w)
    sig = worker_accept(w)
    _refused(w, sig, "not-applicable")
    assert "data_phase_interrupted" in outcome(w, sig)
    with Session(w.api) as s:
        assert "accept-step" not in [
            a["action"] for a in svc.run_body(s, w.run_id)["available_actions"]
        ]
    with pytest.raises(DomainError) as exc:
        api_accept(w, probe_id="x")
    assert exc.value.code == "not-applicable"


def test_refused_when_s2_parked_on_a_lost_checkout(world: World) -> None:
    w = world
    st = park_s2(w)
    w.x("UPDATE workflow_step SET error = CAST(:e AS jsonb) WHERE id = :i",
        e='{"reason": "automation_checkout_lost", "playbook_reported": "needs_human"}', i=st["id"])  # fmt: skip
    sig = worker_accept(w)
    _refused(w, sig, "not-applicable")
    assert "automation_checkout_lost" in outcome(w, sig)


def test_refused_on_a_window_step_and_when_the_run_is_not_parked(world: World) -> None:
    w = world
    w.start()
    w.drive(until="await_cutover")  # waiting at G2: nothing parked
    sig = worker_accept(w)
    w.drive(until="await_cutover")
    assert outcome(w, sig).startswith(
        "refused: not-applicable: the run is not stopped on a parked step"
    ), outcome(w, sig)
    w.approve("cutover")
    _crash("data_attach_green.after_intent")
    w.drive()
    assert w.open_step()["step_key"] == "data_attach_green"  # W6 parked inside the window
    sig = worker_accept(w)
    w.drive()
    assert outcome(w, sig).startswith(
        "refused: not-applicable: accept-step applies only in the restore phase"
    ), outcome(w, sig)
    assert w.open_step()["step_key"] == "data_attach_green" and w.run()["state"] == "needs_human"
    assert all(a["outcome"] == "refused" for a in acceptances(w)) and len(acceptances(w)) == 2


def test_a_second_accept_is_refused_and_one_pending_accept_per_run(world: World) -> None:
    w = world
    park_s2(w)
    probe(w)
    first, second = worker_accept(w), worker_accept(w, "ap3")
    assert w.engine is not None
    w.engine.process_signals()  # both in one pass, before S3 runs
    assert outcome(w, first).startswith("step quiesce_green accepted"), outcome(w, first)
    assert outcome(w, second).startswith("refused: not-applicable"), outcome(w, second)
    assert [a["outcome"] for a in acceptances(w)] == ["accepted", "refused"]
    # the table refuses a second accepted row for the same (run, step) even if the worker were wrong
    row = acceptances(w)[0]
    third = w.signal("probe", user="ap3")  # any signal row to reference
    with pytest.raises(sqlalchemy.exc.IntegrityError, match="step_acceptance_once"):
        w.x("INSERT INTO step_acceptance (id, run_id, signal_id, step_id, step_key, attempt, approver_id, probe, "
            "probed_at, attestation, outcome) VALUES (gen_random_uuid(), :r, :s, :st, 'quiesce_green', 1, :a, '{}', "
            "now(), :t, 'accepted')", r=w.run_id, s=third, st=row["step_id"], a=w.users["ap3"], t=ATTESTATION)  # fmt: skip


def test_api_refuses_a_second_pending_accept(world: World) -> None:
    w = world
    park_s2(w)
    probe(w)
    api_accept(w)
    with pytest.raises(DomainError) as exc:
        api_accept(w, "ap3")
    assert exc.value.code == "accept-pending"


# --- the parked attempt's late outcome ----------------------------------------------------------------------------


def test_a_late_outcome_of_the_parked_attempt_is_discarded_after_accept(world: World) -> None:
    w = world
    w.guest.pre_aa_role = True
    to_cutover(w)
    _crash("data_attach_green.after_intent")
    w.drive()
    w.signal("rollback", tc=w.blue_tc())
    assert w.engine is not None
    eng = w.engine
    claims: list[Any] = []
    real_claim = eng.claim

    def recording(limit: int = 1) -> list[Any]:
        got = real_claim(limit)
        claims.extend(got)
        return got

    eng.claim = recording  # type: ignore[method-assign]
    w.drive()
    st = parked_s2(w)
    claim = next(c for c in reversed(claims) if c.step.step_key == "quiesce_green")
    assert claim.step.attempt == st["attempt"] and claim.fencing_token == st["fencing_token"]
    probe(w)
    sig = worker_accept(w)
    eng.process_signals()
    assert outcome(w, sig).startswith("step quiesce_green accepted"), outcome(w, sig)
    row = next(s for s in w.steps() if s["id"] == st["id"])
    assert (
        row["fencing_token"] != claim.fencing_token and row["state"] == "succeeded"
    )  # the token is retired
    # the parked attempt reports late (a stale worker): its commit and its heartbeat match 0 rows
    clock = FakeClock()
    fence = Fence(clock=clock, lease_duration=600, fence_margin=10, t_send=clock.monotonic(),
                  verify_ownership=lambda: True)  # fmt: skip
    defn = eng.registry.resolve(claim.run.kind, claim.run.strategy, claim.run.strategy_version)
    with pytest.raises(FencedCommitRejected):
        eng._commit_outcome(claim, fence, defn, Done({"late": True}))  # noqa: SLF001
    assert eng.heartbeat(claim, fence) is False
    after = next(s for s in w.steps() if s["id"] == st["id"])
    assert (
        after["evidence"] == row["evidence"]
        and after["state"] == "succeeded"
        and "late" not in after["evidence"]
    )
    assert (
        w.open_step()["step_key"] == "stop_green"
    )  # the run went on, untouched by the late outcome


# --- table rules ----------------------------------------------------------------------------------------------------


def test_step_acceptance_is_append_only_and_the_api_cannot_insert(world: World) -> None:
    w = world
    park_s2(w)
    probe(w)
    api_accept(w)
    w.drive()
    [row] = acceptances(w)
    with w.worker.begin() as c:  # the worker may read
        assert c.execute(text("SELECT count(*) FROM step_acceptance")).scalar_one() == 1
    for engine in (w.worker, w.admin):  # not even the owner may change or delete a row (trigger)
        for sql in (
            "UPDATE step_acceptance SET attestation = 'x' WHERE id = :i",
            "DELETE FROM step_acceptance WHERE id = :i",
        ):
            with pytest.raises(sqlalchemy.exc.DBAPIError), engine.begin() as c:
                c.execute(text(sql), {"i": row["id"]})
    with pytest.raises(sqlalchemy.exc.DBAPIError), w.admin.begin() as c:
        c.execute(text("TRUNCATE step_acceptance"))
    with pytest.raises(sqlalchemy.exc.ProgrammingError), w.api.begin() as c:  # api: read only
        c.execute(
            text("INSERT INTO step_acceptance (id, run_id, signal_id, approver_id, attestation, outcome, refusal_code) "
                 "VALUES (gen_random_uuid(), :r, :s, :a, 'x', 'refused', 'x')"),
            {"r": w.run_id, "s": str(row["signal_id"]), "a": w.users["ap2"]},
        )  # fmt: skip
    with w.api.begin() as c:
        assert c.execute(text("SELECT count(*) FROM step_acceptance")).scalar_one() == 1
    assert acceptances(w)[0]["attestation"] == ATTESTATION


# --- api ------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case",
    [
        "requester",
        "operator",
        "no_stepup",
        "consumed_stepup",
        "tc",
        "attestation",
        "stale",
        "probe_id",
    ],
)
def test_api_refuses_and_audits(world: World, case: str) -> None:
    w = world
    park_s2(w)
    p = probe(w)
    kw: dict[str, Any] = {}
    user = "ap2"
    roles: tuple[str, ...] = ("approver",)
    code = {
        "requester": "sod-violation", "operator": "forbidden", "no_stepup": "human-session-required",
        "consumed_stepup": "stepup-invalid", "tc": "confirmation-mismatch", "attestation": "attestation-invalid",
        "stale": "probe-stale", "probe_id": "probe-mismatch",
    }[case]  # fmt: skip
    if case == "requester":
        user, roles = "op", ("operator", "approver")
    elif case == "operator":
        user, roles = "op", ("operator",)
    elif case == "no_stepup":
        kw["stepup"] = None
    elif case == "consumed_stepup":
        kw["stepup"] = w.stepup("ap2", "run.accept_step", w.run_id, consumed=True)
    elif case == "tc":
        kw["tc"] = w.blue_tc()  # the blue VM's confirmation: accept-step targets green
    elif case == "attestation":
        kw["attestation"] = "x" * 19
    elif case == "stale":
        age_probe(w, 61)
    else:
        kw["probe_id"] = p["id"][:-1] + ("0" if p["id"][-1] != "0" else "1")
    with pytest.raises((DomainError, ProblemError)) as exc:
        api_accept(w, user, roles=roles, **kw)
    assert getattr(exc.value, "code", None) == code, exc.value
    assert (
        w.q(
            "SELECT count(*) AS n FROM run_signal WHERE run_id = :r AND kind = 'accept_step'",
            r=w.run_id,
        )[0]["n"]
        == 0
    )
    if case != "consumed_stepup":  # the step-up refusal is audited as auth.stepup.refused
        refused = w.q("SELECT after FROM audit_event WHERE run_id = :r AND action = 'run.accept_step.refused'",
                      r=w.run_id)  # fmt: skip
        assert [r["after"]["refusal_code"] for r in refused] == [code], refused
    assert w.run()["state"] == "needs_human"


# --- PMR-1: the guest probe is bounded and not repeated -----------------------------------------------------------

BUDGET = 0.5


def api_probe(w: World, user: str = "ap2") -> None:
    """The Re-probe button as the api handles it."""
    with Session(w.api) as s:
        svc.action(
            s, who(w, user), UUID(w.run_id), "probe", typed=None, stepup_id=None, attestation=None
        )
        s.commit()


def test_a_hanging_green_does_not_hold_another_runs_signal_beyond_the_budget(world: World) -> None:
    """Review PMR-1: green answers TCP but a command hangs. The probe signal of the parked run is ahead of another
    run's abort in the queue; the worker's signal pass must apply the abort within the probe's budget, not after the
    guest gives up. While that probe still runs, a second probe of the run does not start another one."""
    w = world
    park_s2(w)
    w.make_engine(replace(w.cfg, accept_probe_timeout=BUDGET))
    w.guest.probe_hang = 8.0  # longer than the budget, short enough that a regression fails fast
    started = len(w.guest.probes)
    try:
        first = w.signal("probe", user="ap2")
        with w.api.begin() as c:
            other = request_run(
                c, kind=REPROBE_KIND, strategy=REPROBE_STRATEGY, strategy_version="1"
            )
            abort = send_signal(c, other, "abort", actor_id=w.users["op"])
        assert w.engine is not None
        t0 = time.monotonic()
        w.engine.process_signals()
        elapsed = time.monotonic() - t0
        assert elapsed < BUDGET + 3.0, f"the signal pass took {elapsed:.1f} s"
        # applied in this pass (that job's definition refuses every signal: the outcome is its answer)
        assert outcome(w, abort) == "refused: this job takes no signals"
        assert outcome(w, first) == "current truth refreshed"
        shown = w.run()["current_truth"]["accept_probe"]
        assert shown["ok"] is False and shown["guest"]["error"] == "GuestProbeTimeout", shown
        assert w.guest.probe_timeouts[-1] == BUDGET  # the port got the budget too
        # the same run again while the first guest probe still hangs: no second SSH probe, refused at once
        second = w.signal("probe", user="ap2")
        t0 = time.monotonic()
        w.engine.process_signals()
        assert time.monotonic() - t0 < BUDGET
        assert outcome(w, second) == "current truth refreshed"
        shown = w.run()["current_truth"]["accept_probe"]
        assert shown["ok"] is False and shown["guest"]["error"] == "GuestProbeInProgress", shown
        assert len(w.guest.probes) == started + 1
    finally:
        w.guest.probe_release.set()
    # once the hanging probe ended, the next one runs again and shows the postcondition
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        sig = w.signal("probe", user="ap2")
        w.engine.process_signals()
        assert outcome(w, sig) == "current truth refreshed"
        if w.run()["current_truth"]["accept_probe"]["ok"]:
            break
        time.sleep(0.1)
    assert w.run()["current_truth"]["accept_probe"]["ok"], w.run()["current_truth"]


def test_api_refuses_a_second_pending_probe(world: World) -> None:
    """Review PMR-1: repeated Re-probe clicks are not queued; the worker applies one probe per run at a time."""
    w = world
    park_s2(w)
    api_probe(w)
    with pytest.raises(DomainError) as exc:
        api_probe(w, "ap3")
    assert exc.value.code == "probe-pending" and exc.value.status == 409
    assert len(w.q("SELECT id FROM run_signal WHERE run_id = :r AND kind = 'probe' AND consumed_at IS NULL",
                   r=w.run_id)) == 1  # fmt: skip
    w.drive()
    api_probe(w, "ap3")  # applied: a new probe is accepted
