"""Engine crash points on the window and restore steps (testing-strategy.md 4.1, WF-01/WF-02/WF-06 for E5-4).

A worker "dies" (``SimulatedCrash``, never seen by step code) at a named point; its lease is expired and a new worker
process (new ``lease_owner``, new fencing token) takes over: it waits ``worker.takeover_delay`` for destructive or
window steps, then **probes first**. Oracle:

* OpenStack steps: the run finishes as if nothing happened, and each mutating call was sent exactly once (the
  probe sees the landed effect and does not repeat it blindly).
* Data phases (W1, W6): a takeover goes to ``needs_human(data_phase_interrupted)`` with a read-only probe; an
  operator rollback (TC) then restores and the restore converges (W1: blue quiesced but ACTIVE -> S6 boot-cycle).
* Data safety holds after every pass (``World.check_invariants``): never two VMs attached, never two mounts, no
  volume or FIP deleted.
"""

from __future__ import annotations

import pytest

from ovlm.workflow import crashpoint
from ovlm.workflow.crashpoint import CrashPlan
from tests.integration.renewal.conftest import World, explain, to_cutover
from tests.integration.renewal.test_failures import restored

POINTS = ("after_intent", "after_act", "after_verify_before_commit", "after_commit")

#: step -> (mutating fake operation, expected total count at the end; the seed already did one attach and one FIP update)
OPENSTACK_STEPS = {
    "stop_old": ("stop_server", 1),
    "detach_volume": ("detach_volume", 1),
    "attach_volume_green": ("attach_volume", 2),
    "move_fip": ("update_floating_ip", 2),
}
ANSIBLE_STEPS = ("start_service_green", "healthcheck_green")
DATA_STEPS = ("quiesce_old", "data_attach_green")


def _crash(step: str, point: str) -> None:
    crashpoint.install(CrashPlan(target=f"{step}.{point}", mode="raise"))


@pytest.mark.parametrize("point", POINTS)
@pytest.mark.parametrize("step", sorted(OPENSTACK_STEPS))
def test_crash_in_openstack_window_step_never_repeats_the_call(
    world: World, step: str, point: str
) -> None:
    w = world
    to_cutover(w)
    _crash(step, point)
    r = w.drive(until="await_retirement")
    assert w.crashes == 1
    assert r["state"] == "running" and w.run()["phase"] == "retained", explain(w)
    op, expected = OPENSTACK_STEPS[step]
    assert w.cloud.calls.count(op) == expected, (op, w.cloud.calls.count(op))
    assert w.attached() == [w.green_id()] and w.fip_port() != w.ids["blue_port"]
    attempts = w.q(
        "SELECT a.takeover FROM workflow_step_attempt a JOIN workflow_step s ON s.id = a.step_id "
        "WHERE s.run_id = :r AND s.step_key = :k ORDER BY a.attempt",
        r=w.run_id,
        k=step,
    )
    if point != "after_commit":
        assert any(a["takeover"] for a in attempts)


@pytest.mark.parametrize("point", ("after_act", "after_verify_before_commit"))
@pytest.mark.parametrize("step", ANSIBLE_STEPS)
def test_crash_in_non_data_ansible_step_reruns_safely(world: World, step: str, point: str) -> None:
    w = world
    to_cutover(w)
    _crash(step, point)
    r = w.drive(until="await_retirement")
    assert r["state"] == "running" and w.run()["phase"] == "retained", explain(w)


@pytest.mark.parametrize("point", ("after_intent", "after_act", "after_verify_before_commit"))
@pytest.mark.parametrize("step", DATA_STEPS)
def test_crash_in_data_phase_is_needs_human_then_rollback_converges(
    world: World, step: str, point: str
) -> None:
    w = world
    to_cutover(w)
    _crash(step, point)
    w.drive()
    r = w.run()
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "data_phase_interrupted", (
        explain(w)
    )
    ev = w.open_step()["error"]
    assert "guest_probe" in ev  # automatic read-only probe attached (renewal-workflow.md 5)
    w.signal("rollback", tc=w.blue_tc())
    w.drive()
    restored(w)


@pytest.mark.parametrize(
    "step",
    (
        "unlock_old",
        "stop_green",
        "detach_from_green",
        "attach_to_old",
        "boot_old",
        "move_fip_to_old",
    ),
)
def test_crash_in_restore_converges(world: World, step: str) -> None:
    """Revert after cutover (every restore step has work to do), crash after the act of one restore step."""
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    _crash(step, "after_act")
    w.signal("revert", tc=w.blue_tc())
    w.drive()
    assert w.crashes == 1
    restored(w)
    assert w.cloud.calls.count("detach_volume") == 2  # W3 once, S4 once


@pytest.mark.parametrize("point", ("after_act", "after_verify_before_commit"))
def test_abort_crash_after_green_was_deleted_finishes_the_discard(world: World, point: str) -> None:
    """Lab bug S: the worker dies right after Nova accepted green's delete. Nova then still lists green as DELETED
    (a tombstone, not a 404). The next attempt must treat it as gone, not unlock it again and stop on an
    'unverifiable' ownership check."""
    w = world
    w.cloud.keep_tombstones = True
    # as Felcloud did: GET after the delete answers status DELETED, not 404
    w.cloud.get_returns_deleted = True
    w.start()
    w.drive(until="await_cutover")
    _crash("discard_green", point)
    w.signal("abort", tc=w.green_tc())
    r = w.drive()
    assert w.crashes == 1
    assert r["state"] == "rolled_back", explain(w)
    assert w.cloud.calls.count("delete_server") == 1
    assert w.locks() == [] and w.cloud.snapshot()["servers"][w.ids["blue"]]["status"] == "ACTIVE"


def test_worker_killed_between_w5_and_w6_rollback_quiesces_the_unmounted_green(
    world: World,
) -> None:
    """Lab finding AA (2026-11-08): the worker dies after W5 attached the volume to green and before W6 mounted it.
    W6's takeover parks (data_phase_interrupted); the operator rolls back. S2 then quiesces a green that holds the
    volume but never mounted it and has no earlier quiesce record. OVLM passes ``quiesce_allow_unmounted`` from S2
    only, so that state is ok there (nothing to stop or unmount) and the restore reaches S10 with the volume and the
    FIP back on blue. Without it, S2 refused "state is unknown" and the restore parked."""
    w = world
    to_cutover(w)
    _crash("data_attach_green", "after_intent")
    w.drive()
    r = w.run()
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "data_phase_interrupted", (
        explain(w)
    )
    green = w.green_id()
    assert green is not None and w.attached() == [green]
    assert not w.guest.g(green).mounted and w.guest.g(green).quiesce_record is None
    assert ("data_attach", green) not in w.guest.calls  # W6 never ran its playbook
    w.signal("rollback", tc=w.blue_tc())
    w.drive()
    restored(w)
    s2 = next(s for s in w.steps() if s["step_key"] == "quiesce_green")
    assert s2["state"] == "succeeded", explain(w)
    assert (
        s2["evidence"]["green_was_mounted"] is False and s2["evidence"]["marker_checksum"] is None
    )
    assert s2["evidence"]["marker_comparison"].startswith("skipped"), s2["evidence"]
    lock = next(s for s in w.steps() if s["step_key"] == "lock_green")
    assert lock["state"] == "succeeded" and lock["evidence"]["green_locked"].startswith(
        "ovlm:restored:"
    )
    # S2 is the only quiesce that may accept "never mounted"; W1 on blue never got the flag
    assert (w.ids["blue"], False) in w.guest.quiesce_calls and (
        green,
        True,
    ) in w.guest.quiesce_calls
    assert all(not allow for sid, allow in w.guest.quiesce_calls if sid == w.ids["blue"])
