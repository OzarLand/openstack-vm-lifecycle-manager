"""W4 pre-handoff snapshot (renewal-workflow.md 2.2, 4, 4.1; SRE-R-7, SRE-R-30/31; maintainer brief E5-4), end to
end against the fake cloud's Cinder snapshot model (strict gate) and the fake guest. One test per rule:

* policy switch off (the default): no W4 step, no snapshot call;
* on: snapshot of the detached volume, ``available`` before W5; kept after X1 (OVLM never deletes a snapshot);
* B1 quota pre-check (snapshots +1, gigabytes + volume size): refused before any resource exists;
* create refused inside the window (quota race), snapshot ``error``, snapshot stuck ``creating`` until the deadline:
  automatic restore "snapshot failed"; whatever exists is marked ``orphan`` and left in place;
* kept after a restore (W7 failure with a snapshot), recorded in the ``restore.auto`` audit row;
* crash after the create, before the ledger got the id: adopted by name, never created twice;
* a squatted name (a snapshot of another volume carrying the run's name): never adopted.
"""

from __future__ import annotations

from typing import Any

from ovlm.openstack.errors import ServerError
from tests.integration.renewal.conftest import World, explain, to_cutover
from tests.integration.renewal.test_failures import expire_deadline, parked, restored


def snaps(w: World) -> dict[str, Any]:
    out: dict[str, Any] = w.cloud.snapshot()["snapshots"]
    return out


def ledger(w: World) -> list[Any]:
    return w.q("SELECT * FROM owned_resource WHERE run_id = :r AND role = 'snapshot'", r=w.run_id)


def test_policy_off_by_default_takes_no_snapshot(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    steps = w.keys()  # step keys of the run
    assert "snapshot_volume" not in steps
    assert "create_volume_snapshot" not in w.cloud.calls and snaps(w) == {}


def test_snapshot_taken_in_the_window_and_kept_after_retirement(world_factory: Any) -> None:
    w = world_factory(snapshot=True)
    to_cutover(w)
    r = w.drive(until="await_retirement")
    assert r["state"] == "running", explain(w)
    keys = w.keys()
    assert (
        keys.index("detach_volume")
        < keys.index("snapshot_volume")
        < keys.index("attach_volume_green")
    )
    ((sid, snap),) = snaps(w).items()
    assert snap == {
        "status": "available",
        "volume_id": w.ids["volume"],
        "name": f"ovlm-prehandoff-{w.run_id}",
    }
    (row,) = ledger(w)
    assert row["state"] == "present" and row["openstack_id"] == sid
    w4 = next(s for s in w.steps() if s["step_key"] == "snapshot_volume")
    assert w4["state"] == "succeeded" and w4["evidence"]["snapshot_id"] == sid
    w.approve("retirement", decider="ap2")
    assert w.drive()["state"] == "completed", explain(w)
    assert snaps(w)[sid]["status"] == "available"  # never deleted by OVLM
    x1 = next(s for s in w.steps() if s["step_key"] == "retire_old")
    assert (
        x1["evidence"]["snapshot_kept"] == sid
        and "release it manually" in x1["evidence"]["snapshot_note"]
    )


def test_b1_refuses_when_the_snapshot_quota_has_no_room(world_factory: Any) -> None:
    w = world_factory(snapshot=True)
    w.cloud.quota_snapshots = 0
    w.start()
    r = w.drive()
    assert r["state"] == "failed", explain(w)
    pre = next(s for s in w.steps() if s["step_key"] == "preflight")
    assert any("snapshot quota" in p for p in pre["error"]["problems"]), pre["error"]
    assert w.green_id() is None and "create_server" not in w.cloud.calls  # nothing was created


def test_b1_counts_the_volume_size_against_the_gigabytes_quota(world_factory: Any) -> None:
    w = world_factory(snapshot=True)
    w.cloud.quota_gigabytes = 0  # the data volume is 1 GB
    w.start()
    assert w.drive()["state"] == "failed", explain(w)


def test_create_refused_in_the_window_restores_automatically(world_factory: Any) -> None:
    w = world_factory(snapshot=True)
    to_cutover(w)
    w.drive(until="snapshot_volume")
    w.cloud.quota_snapshots = (
        0  # quota consumed by someone else after B1 (the race the B1 check cannot close)
    )
    w.drive()
    restored(w)
    assert w.run()["auto_restore_used"] and snaps(w) == {}
    audit = w.q(
        "SELECT after FROM audit_event WHERE run_id = :r AND action = 'restore.auto'", r=w.run_id
    )
    assert (
        audit[0]["after"]["trigger"] == "snapshot_failed"
        and audit[0]["after"]["snapshot_id"] is None
    )


def test_snapshot_error_restores_and_the_failed_snapshot_is_reported_not_deleted(
    world_factory: Any,
) -> None:
    w = world_factory(snapshot=True)
    w.cloud.snapshot_outcome = "error"
    to_cutover(w)
    w.drive()
    restored(w)
    ((sid, snap),) = snaps(w).items()
    assert snap["status"] == "error"  # left in place
    (row,) = ledger(w)
    assert row["state"] == "orphan" and row["openstack_id"] == sid
    assert (
        row["detail"]["orphan_candidate"] == "snapshot_failed"
        and row["detail"]["never_deleted_by_ovlm"]
    )


def test_snapshot_stuck_creating_until_the_deadline_restores_and_is_reported(
    world_factory: Any,
) -> None:
    w = world_factory(snapshot=True)
    w.cloud.snapshot_outcome = "stuck"
    to_cutover(w)
    w.drive(until="snapshot_volume")
    eng = w.engine
    assert eng is not None
    for _ in range(4):  # create, then wait on "creating"
        eng.run_once()
        w.cloud.tick(20)
    assert next(iter(snaps(w).values()))["status"] == "creating"
    expire_deadline(w)
    w.drive()
    restored(w)
    assert w.run()["auto_restore_used"]
    (snap,) = snaps(w).values()
    assert snap["status"] == "creating"  # never deleted
    (row,) = ledger(w)
    assert row["state"] == "orphan"
    w4 = next(s for s in w.steps() if s["step_key"] == "snapshot_volume")
    assert "deadline" in w4["error"]["reason"], w4["error"]


def test_snapshot_kept_after_a_restore_and_named_in_the_audit(world_factory: Any) -> None:
    w = world_factory(snapshot=True)
    w.guest.failures["start_service"] = ["retryable"] * 3
    to_cutover(w)
    w.drive()
    restored(w)
    ((sid, snap),) = snaps(w).items()
    assert snap["status"] == "available"
    (row,) = ledger(w)
    assert row["state"] == "present"  # kept as a manual way back, not an orphan
    audit = w.q(
        "SELECT after FROM audit_event WHERE run_id = :r AND action = 'restore.auto'", r=w.run_id
    )
    assert audit[0]["after"]["snapshot_id"] == sid
    assert w.run()["current_truth"]["snapshot"] == {"id": sid, "ledger_state": "present"}


def test_lost_create_response_is_adopted_by_name_never_created_twice(world_factory: Any) -> None:
    w = world_factory(snapshot=True)
    w.cloud.fail(
        "create_volume_snapshot", ServerError("gateway timeout", status=504), when="after_apply"
    )
    to_cutover(w)
    r = w.drive(until="await_retirement")
    assert r["state"] == "running", explain(w)
    assert w.cloud.calls.count("create_volume_snapshot") == 1
    (sid,) = snaps(w)
    (row,) = ledger(w)
    assert row["state"] == "present" and row["openstack_id"] == sid
    assert not w.run()["auto_restore_used"]


def test_a_squatted_snapshot_name_is_never_adopted(world_factory: Any) -> None:
    w = world_factory(snapshot=True)
    other = w.cloud.add_volume("someone-elses")
    to_cutover(w)
    w.drive(until="snapshot_volume")
    squat = w.cloud.add_volume_snapshot(
        other, f"ovlm-prehandoff-{w.run_id}", metadata={"ovlm.run": w.run_id}
    )
    w.drive()
    # W4 failed with the volume detached and blue stopped: the closed table restores; the squatter is untouched
    restored(w)
    w4 = next(s for s in w.steps() if s["step_key"] == "snapshot_volume")
    assert w4["error"]["reason"] == "snapshot_adoption_refused", w4["error"]
    assert "the snapshot is not a copy of the data volume" in w4["error"]["problems"]
    assert (
        snaps(w)[squat]["status"] == "available" and "create_volume_snapshot" not in w.cloud.calls
    )


def test_needs_human_when_two_snapshots_carry_the_name(world_factory: Any) -> None:
    w = world_factory(snapshot=True, policy={"auto_restore": False})
    to_cutover(w)
    w.drive(until="snapshot_volume")
    for _ in range(2):
        w.cloud.add_volume_snapshot(w.ids["volume"], f"ovlm-prehandoff-{w.run_id}")
    w.drive()
    parked(w, "duplicate_resource")
    assert "create_volume_snapshot" not in w.cloud.calls


def test_rollback_consequence_names_the_snapshot_only_once_w4_succeeded(world_factory: Any) -> None:
    from sqlalchemy.orm import Session

    from ovlm.renewal.service import _snapshot_id, available_actions

    w = world_factory(snapshot=True, policy={"auto_restore": False})
    w.guest.failures["start_service"] = ["retryable"] * 3
    to_cutover(w)
    w.drive()
    parked(w, "auto_restore_disabled")
    (sid,) = snaps(w)
    resolved = w.q("SELECT resolved FROM renewal_plan WHERE id = :p", p=w.ids["plan"])[0][
        "resolved"
    ]
    with Session(w.api) as s:
        assert _snapshot_id(s, w.run_id) == sid
    actions = available_actions(w.run(), w.open_step(), resolved, sid)
    rollback = next(a for a in actions if a["action"] == "rollback")
    assert f"snapshot {sid} is kept" in rollback["effect"]
    none = next(
        a
        for a in available_actions(w.run(), w.open_step(), resolved, None)
        if a["action"] == "rollback"
    )
    assert "no snapshot exists" in none["effect"]


def test_b1_refuses_an_expired_write_credential(world: World) -> None:
    from datetime import UTC, datetime, timedelta

    w = world
    w.port.credential_expires = datetime.now(UTC) - timedelta(minutes=1)
    w.start()
    assert w.drive()["state"] == "failed", explain(w)
    pre = next(s for s in w.steps() if s["step_key"] == "preflight")
    assert "the write credential has expired" in pre["error"]["problems"]
