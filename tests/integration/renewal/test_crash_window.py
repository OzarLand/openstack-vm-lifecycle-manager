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
