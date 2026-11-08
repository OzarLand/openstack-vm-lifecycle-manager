"""Failure scenarios of renewal-workflow.md section 7 and the closed table of section 4.1 (with D-1 = B), against the
fake cloud (strict gate) and the fake guest. Each test names the row it covers."""

from __future__ import annotations

import contextlib
from typing import Any

import pytest

from ovlm.openstack.errors import ServerError
from ovlm.renewal.config import RenewalConfig
from tests.integration.renewal.conftest import CFG, World, explain, to_cutover


def expire_deadline(w: World) -> None:
    w.x("UPDATE workflow_step SET deadline_at = now() - interval '1 second' WHERE run_id = :r "
        "AND state IN ('ready', 'waiting')", r=w.run_id)  # fmt: skip


def restored(w: World) -> None:
    """The restore target (section 4): volume on blue, blue ACTIVE and serving, FIP on blue, green SHUTOFF + locked."""
    snap = w.cloud.snapshot()["servers"]
    green = w.green_id()
    assert w.attached() == [w.ids["blue"]], explain(w)
    assert snap[w.ids["blue"]]["status"] == "ACTIVE"
    assert w.fip_port() == w.ids["blue_port"]
    assert w.guest.state[w.ids["blue"]].mounted and w.guest.state[w.ids["blue"]].units
    if green is not None:
        assert snap[green]["status"] == "SHUTOFF" and snap[green]["locked"]
    st = w.open_step()
    assert st is not None and st["step_key"] == "await_discard", explain(w)


def parked(w: World, reason: str) -> Any:
    r = w.run()
    assert r["state"] == "needs_human" and r["needs_human_reason"] == reason, explain(w)
    return r


def deleted(w: World, server_id: str | None) -> bool:
    return server_id is not None and w.cloud._servers[server_id].deleted  # noqa: SLF001


def calls(w: World, op: str) -> int:
    return w.cloud.calls.count(op)


# --- build phase -------------------------------------------------------------------------------------------------


def test_overquota_at_create_is_fatal_build_failed_then_rollback(world: World) -> None:
    w = world
    w.cloud.quota_instances = 1  # blue uses the only instance
    w.start()
    w.drive()
    parked(w, "build_failed")
    assert w.open_step()["step_key"] == "create_green"
    assert ("server", w.ids["blue"]) in w.locks()  # BuildFailed keeps the locks
    w.signal("rollback", tc=w.blue_tc())  # no green exists: the TC is blue's
    r = w.drive()
    assert r["state"] == "rolled_back", explain(w)
    assert w.locks() == []
    assert w.attached() == [w.ids["blue"]]


def test_no_valid_host_green_kept_until_operator_rollback(world: World) -> None:
    w = world
    w.cloud.force_no_valid_host = True
    w.start()
    w.drive()
    parked(w, "build_failed")
    green = w.green_id()
    assert (
        green is not None and w.cloud.snapshot()["servers"][green]["status"] == "ERROR"
    )  # kept for diagnosis
    assert calls(w, "create_server") == 1  # never retried while a green of the run exists
    assert calls(w, "delete_server") == 0  # never deleted automatically
    w.signal("rollback", tc=w.blue_tc())  # wrong VM: refused (build phase TC is green's)
    w.drive()
    assert calls(w, "delete_server") == 0
    w.signal("rollback", tc=w.green_tc())
    r = w.drive()
    assert r["state"] == "rolled_back", explain(w)
    assert deleted(w, green)
    assert w.cloud.snapshot()["servers"][w.ids["blue"]]["status"] == "ACTIVE"  # blue untouched


def test_lost_create_response_adopts_never_duplicates(world: World) -> None:
    """WF-02 for create_green: the create landed, the response was lost. Lookup by run tag + exact name finds it,
    ``adopt_checks`` passes (image, flavor, created after the ledger row, no volumes, OVLM's write user): adopted."""
    w = world
    w.cloud.fail("create_server", ServerError("lost", status=502), when="after_apply")
    w.start()
    w.drive(until="await_cutover")
    servers = [s for s in w.cloud.snapshot()["servers"] if s != w.ids["blue"]]
    assert len(servers) == 1 and calls(w, "create_server") == 1
    ev = next(
        s for s in w.steps() if s["step_key"] == "create_green" and s["state"] == "succeeded"
    )["evidence"]
    assert ev["adopted"] is True and ev["green_id"] == servers[0]


def test_adoption_refused_for_a_server_of_another_user(world: World) -> None:
    """SEC-R-23: a server carrying this run's tag and name but created by someone else is never adopted."""
    w = world
    w.cloud.fail("create_server", ServerError("lost", status=502), when="after_apply")
    orig = w.cloud.create_server

    def create(spec: Any) -> Any:
        info = orig(spec)  # (the injected fault fires after this returns)
        return info

    w.cloud.user_id = (
        "00000000-0000-0000-0000-0000000000ee"  # the "creator" is not OVLM's write user ...
    )
    w.port.cloud = w.cloud
    w.cloud.create_server = create  # type: ignore[method-assign]
    w.port.write_user_id = lambda project: "00000000-0000-0000-0000-0000000000a1"  # type: ignore[method-assign]
    w.start()
    w.drive()
    parked(w, "adoption_refused")
    assert calls(w, "create_server") == 1


def test_green_active_but_ssh_late_waits_on_reachability(world: World) -> None:
    w = world
    w.guest.ssh_after = 3  # EXP-01b: ACTIVE ~85 s before SSH answers
    to_cutover(w)
    assert w.guest.pin_attempts == 4
    ev = next(s for s in w.steps() if s["step_key"] == "wait_green_ssh")["evidence"]
    assert ev["mode"] == "rotated"


def test_configure_fatal_build_failed_volume_never_left_blue(world: World) -> None:
    w = world
    w.guest.failures["configure"] = ["fatal"]
    w.start()
    w.drive()
    parked(w, "build_failed")
    assert w.attached() == [w.ids["blue"]]
    w.signal("rollback", tc=w.green_tc())
    assert w.drive()["state"] == "rolled_back"


def test_preflight_admin_locked_blue_fails_without_side_effects(world: World) -> None:
    w = world
    w.cloud.touch_server(w.ids["blue"], locked=True, locked_by="admin")
    w.start()
    r = w.drive()
    assert r["state"] == "failed" and w.locks() == []
    assert calls(w, "add_server_tag") == 0


def test_missing_config_keys_reject_at_admission(world: World) -> None:
    w = world
    w.make_engine(RenewalConfig(timeouts={}, automation={}))
    w.start()
    r = w.drive()
    assert r["state"] == "rejected" and "timeouts.green_build" in r["end_reason"]


def test_policy_edited_after_plan_rejects_the_run(world: World) -> None:
    w = world
    w.x(
        "UPDATE policy SET version = version + 1, auto_restore_in_window = false WHERE id = :p",
        p=w.ids["policy"],
    )
    w.start()
    r = w.drive()
    assert r["state"] == "rejected" and "plan hash" in r["end_reason"]


def test_g1_forged_bound_hash_stops_at_admission_or_b1(world_factory: Any) -> None:
    w = world_factory(g1=False)
    w.approve("plan", decider="ap3", bound_hash="f" * 64)
    w.start()
    w.drive()
    parked(w, "approval_evidence_invalid")
    assert calls(w, "add_server_tag") == 0


# --- G2 and the W1 claim ------------------------------------------------------------------------------------------


def test_g2_expired_never_claims_w1(world: World) -> None:
    w = world
    w.start()
    w.drive(until="await_cutover")
    w.approve("cutover", expires="-1 minute")
    r = w.drive()
    st = w.open_step()
    assert (
        r["state"] == "running" and st["step_key"] == "await_cutover" and st["state"] == "waiting"
    )
    assert w.run()["downtime_started_at"] is None


def test_g2_forged_is_needs_human_before_any_outage(world: World) -> None:
    w = world
    w.start()
    w.drive(until="await_cutover")
    w.approve("cutover", bound_hash="0" * 64)
    w.drive()
    parked(w, "approval_evidence_invalid")
    assert w.run()["downtime_started_at"] is None and calls(w, "stop_server") == 0


def test_g2_self_approved_by_requester_is_refused(world: World) -> None:
    """The operator who started the run approves its cutover: SoD check 2/3 fail."""
    w = world
    w.x("INSERT INTO role_binding (id, user_id, role, scope, created_at) VALUES (gen_random_uuid(), :u, 'approver', "
        ":s, now() - interval '1 day')", u=w.users["op"], s=w.ids["scope"])  # fmt: skip
    w.start()
    w.drive(until="await_cutover")
    # the DB refuses a decider inside the stored requester set; a forger would store an empty set instead
    w.approve("cutover", decider="op", requester_set="{}")
    w.drive()
    parked(w, "approval_evidence_invalid")
    assert w.run()["downtime_started_at"] is None


def test_w1_claim_outside_policy_window_waits(world_factory: Any) -> None:
    from datetime import UTC, datetime, timedelta

    later = datetime.now(UTC) + timedelta(hours=3)
    w = world_factory(policy={"windows": [{"weekdays": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
                                           "start": later.strftime("%H:00"),
                                           "end": (later + timedelta(hours=1)).strftime("%H:00"), "timezone": "UTC"}]})  # fmt: skip
    w.start()
    w.drive(until="await_cutover")
    w.approve("cutover")
    w.drive(until="await_cutover", max_passes=5)
    st = w.open_step()
    assert st["step_key"] == "await_cutover" and st["evidence"]["window"] == "closed"
    assert st["not_before"] is not None and w.run()["downtime_started_at"] is None


def test_w1_claim_refused_when_b9_is_stale_no_outage(world: World) -> None:
    w = world
    w.make_engine(RenewalConfig(**{**CFG.__dict__, "green_ready_max_age": 1e-9}))
    to_cutover(w)
    with contextlib.suppress(AssertionError):
        w.drive(
            max_passes=40
        )  # it loops B9 -> W1 (refused) -> B9 ... by design: never claims W1 with a stale B9
    keys = w.keys()
    assert keys.count("verify_green_ready") >= 2 and "stop_old" not in keys
    assert w.run()["downtime_started_at"] is None
    assert not any(c[0] == "quiesce" for c in w.guest.calls)


def test_w1_claim_refused_when_credential_expires_within_worst_case(world: World) -> None:
    from datetime import UTC, datetime, timedelta

    w = world
    w.port.credential_expires = datetime.now(UTC) + timedelta(minutes=5)
    to_cutover(w)
    w.drive(until="await_cutover", max_passes=30)
    assert w.run()["downtime_started_at"] is None
    w1 = [s for s in w.steps() if s["step_key"] == "quiesce_old"]
    assert w1 and w1[0]["error"]["reason"] == "w1_claim_refused"


# --- window rows ------------------------------------------------------------------------------------------------


def test_w1_quiesce_failure_needs_human_no_restore(world: World) -> None:
    w = world
    w.guest.failures["quiesce"] = ["retryable"]
    to_cutover(w)
    w.drive()
    r = parked(w, "quiesce_old_failed")
    assert (
        not r["auto_restore_used"]
        and r["phase"] == "window"
        and r["downtime_started_at"] is not None
    )
    assert ("volume", w.ids["volume"]) in w.locks()


@pytest.mark.parametrize(
    "service_units", [[], ["app.service"]], ids=["no-unit-names", "unit-names"]
)
def test_w1_parked_after_the_stop_operator_rollback_restarts_blue_service(
    world_factory: Any, service_units: list[str]
) -> None:
    """Lab bug X (2026-11-07): W1 stopped the units, then parked before the unmount (bug W). Blue stayed ACTIVE with
    the volume mounted. Without unit names in the profile, S6 cannot see the units are down and does not boot-cycle;
    S7 must start the service itself (start_service on blue) instead of health-checking a stopped service."""
    w = world_factory(service_units=service_units)
    blue = w.ids["blue"]

    def stop_units_only() -> None:
        w.guest.g(blue).units = False  # the role stopped the units; the mount is still there

    w.guest.hooks["quiesce"] = stop_units_only
    w.guest.failures["quiesce"] = ["needs_human"]
    to_cutover(w)
    w.drive()
    parked(w, "quiesce_old_failed")
    assert w.guest.state[blue].mounted and not w.guest.state[blue].units
    w.signal("rollback", tc=w.blue_tc())
    w.drive()
    restored(w)
    recover = next(s for s in w.steps() if s["step_key"] == "recover_old_service")
    assert recover["state"] == "succeeded" and recover["attempt"] == 1, explain(w)
    assert ("start_service", blue) in w.guest.calls


def test_w2_admin_lock_is_needs_human_directly(world: World) -> None:
    w = world
    w.guest.hooks["quiesce"] = lambda: w.cloud.touch_server(
        w.ids["blue"], locked=True, locked_by="admin"
    )
    to_cutover(w)
    w.drive()
    parked(w, "server_locked")
    assert not w.run()["auto_restore_used"]


def test_w2_stop_exhausted_quiesced_but_active_restore_boot_cycles_blue(world: World) -> None:
    """Row W2 exhausted (not locked) -> restore; S6 boot-cycles the quiesced-but-ACTIVE blue (SRE-R-1)."""
    w = world
    w.cloud.fail("stop_server", ServerError("boom", status=500), times=3)
    to_cutover(w)
    w.drive()
    restored(w)
    r = w.run()
    assert r["auto_restore_used"]
    boot = next(s for s in w.steps() if s["step_key"] == "boot_old")
    assert boot["evidence"]["booted"] is True  # stop + start happened: blue booted since quiesce
    assert "restore.auto" in w.audit_actions()


def test_w3_detach_rolled_back_retried_once_then_auto_restore_converges(world: World) -> None:
    w = world
    w.cloud.touch_server(w.ids["blue"], guest_refuses_detach=True)
    to_cutover(w)
    w.drive(tick=200)
    restored(w)
    assert calls(w, "detach_volume") == 2  # the call and one retry
    r = w.run()
    assert r["auto_restore_used"] and r["phase"] == "restore"
    auto = w.q(
        "SELECT * FROM audit_event WHERE action = 'restore.auto' AND run_id = :r", r=w.run_id
    )
    assert len(auto) == 1 and auto[0]["principal_type"] == "system" and auto[0]["authority_ref"]
    # discard green (TC of green) -> RolledBack, locks released, volume still on blue
    green = w.green_id()
    w.signal("discard", tc=w.green_tc())
    assert w.drive()["state"] == "rolled_back", explain(w)
    assert w.locks() == [] and w.attached() == [w.ids["blue"]]
    assert deleted(w, green)


def test_w3_stuck_detaching_is_needs_human(world: World) -> None:
    w = world
    w.cloud.detach_delay = 10_000
    to_cutover(w)
    w.drive(until="detach_volume")
    for _ in range(3):
        w.drive(until="__never__", max_passes=1) if False else w.engine.run_once()  # type: ignore[union-attr]
    expire_deadline(w)
    w.drive()
    parked(w, "volume_stuck_detaching")
    assert not w.run()["auto_restore_used"]


def test_w4_snapshot_failure_auto_restores(world_factory: Any) -> None:
    w = world_factory(snapshot=True)
    w.cloud.snapshot_outcome = "error"
    to_cutover(w)
    w.drive()
    restored(w)
    assert w.run()["auto_restore_used"]


def lose_green_attach(w: World, *, fail_blue: bool = False) -> None:
    """The attach to green is accepted, then never completes: the volume is ``available`` with no attachment."""
    orig = w.cloud.attach_volume

    def attach(server_id: str, volume_id: str) -> None:
        if server_id == w.ids["blue"]:
            if fail_blue:
                raise ServerError("attach refused", status=500)
            orig(server_id, volume_id)
            return
        orig(server_id, volume_id)
        w.cloud._events.clear()  # noqa: SLF001
        w.cloud.admin_reset(w.ids["volume"], "available")

    w.cloud.attach_volume = attach  # type: ignore[method-assign]


def test_w5_attach_not_done_auto_restores(world: World) -> None:
    w = world
    lose_green_attach(w)
    to_cutover(w)
    w.drive()
    restored(w)


def test_w5_stuck_attaching_is_needs_human(world: World) -> None:
    w = world
    w.x("SELECT 1")
    w.cloud._volumes[w.ids["volume"]].attach_fails = True  # noqa: SLF001 - fault injection
    # only the attach to green fails: blue's attachment already exists
    to_cutover(w)
    w.drive(until="attach_volume_green")
    for _ in range(4):
        w.engine.run_once()  # type: ignore[union-attr]
        w.cloud.tick(20)
    expire_deadline(w)
    w.drive()
    parked(w, "volume_stuck_attaching")


def test_w6_data_attach_failure_needs_human_no_restore(world: World) -> None:
    w = world
    w.guest.failures["data_attach"] = ["needs_human"]
    to_cutover(w)
    w.drive()
    r = parked(w, "data_attach_green_failed")
    assert not r["auto_restore_used"]


def test_w7_failure_without_snapshot_pages_and_holds(world: World) -> None:
    """D-1 = B: no automatic restore after the service started on green unless a W4 snapshot exists."""
    w = world
    w.guest.failures["start_service"] = ["retryable"] * 3
    to_cutover(w)
    w.drive()
    r = parked(w, "post_start_failure")
    assert not r["auto_restore_used"] and r["phase"] == "window"
    assert ("volume", w.ids["volume"]) in w.locks()
    before = list(w.cloud.calls)
    w.drive(max_passes=5)  # nothing more happens: no further OpenStack mutation
    assert [
        c
        for c in w.cloud.calls[len(before) :]
        if c in ("stop_server", "detach_volume", "update_floating_ip")
    ] == []
    assert r["current_truth"]["volume"]["attached_to"] == [w.green_id()]


def test_w7_failure_with_snapshot_restores_and_keeps_snapshot(world_factory: Any) -> None:
    w = world_factory(snapshot=True)
    w.guest.failures["start_service"] = ["retryable"] * 3
    to_cutover(w)
    w.drive()
    restored(w)
    snaps = w.cloud.snapshot()["snapshots"]
    assert [x["status"] for x in snaps.values()] == ["available"]  # kept: a manual way back
    assert "create_volume_snapshot" in w.cloud.calls


def test_w8_healthcheck_exhausted_pages(world: World) -> None:
    w = world
    w.guest.failures["healthcheck"] = ["retryable"] * 3
    to_cutover(w)
    w.drive()
    parked(w, "post_start_failure")


def test_w9_no_router_path_pages(world: World) -> None:
    w = world
    w.cloud._router_paths.clear()  # noqa: SLF001 - the misleading 404 (OSI 6.1)
    to_cutover(w)
    w.drive()
    parked(w, "post_start_failure")
    assert w.fip_port() == w.ids["blue_port"]


def test_w10_external_verify_exhausted_with_snapshot_restores_fip(world_factory: Any) -> None:
    w = world_factory(snapshot=True)
    to_cutover(w)
    w.drive(until="verify_external")
    w.guest.external_down = True
    w.engine.run_once()
    expire_deadline(w)
    w.engine.run_once()
    w.guest.external_down = False
    w.drive()
    restored(w)


def test_w10_external_verify_exhausted_without_snapshot_pages(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="verify_external")
    w.guest.external_down = True
    w.engine.run_once()  # type: ignore[union-attr]
    expire_deadline(w)
    w.drive()
    r = parked(w, "post_start_failure")
    assert r["downtime_ended_at"] is None


def test_budget_exceeded_before_w5_restores(world: World) -> None:
    w = world
    w.guest.hooks["quiesce"] = lambda: None
    to_cutover(w)
    w.drive(until="attach_volume_green")
    w.x(
        "UPDATE workflow_run SET downtime_started_at = now() - interval '2 hours' WHERE id = :r",
        r=w.run_id,
    )
    w.drive()
    restored(w)
    assert (
        w.q("SELECT after FROM audit_event WHERE action = 'restore.auto'")[0]["after"]["trigger"]
        == "budget"
    )


def test_budget_exceeded_before_w7_pages(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="start_service_green")
    w.x(
        "UPDATE workflow_run SET downtime_started_at = now() - interval '2 hours' WHERE id = :r",
        r=w.run_id,
    )
    w.drive()
    parked(w, "post_start_failure")


def test_evidence_invalid_inside_window_restores_known_state(world: World) -> None:
    """WF-21: a forged change of the G2 row at W3 -> needs_human-class failure, restore (known state rows)."""
    w = world
    to_cutover(w)
    w.drive(until="detach_volume")
    w.x("UPDATE approval SET bound_hash = :h WHERE subject_type = 'cutover'", h="e" * 64)
    w.drive()
    restored(w)
    after = w.q("SELECT after FROM audit_event WHERE action = 'restore.auto'")[0]["after"]
    assert after["trigger"] == "approval_evidence_invalid"


def test_legitimate_later_role_revocation_does_not_trip_the_check(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="stop_old")
    w.x("UPDATE role_binding SET revoked_at = now() WHERE user_id = :u", u=w.users["ap"])
    r = w.drive(until="await_retirement")
    assert r["state"] == "running" and w.run()["phase"] == "retained", explain(w)


def test_auto_restore_disabled_by_policy_parks(world_factory: Any) -> None:
    w = world_factory(policy={"auto_restore": False})
    w.cloud.touch_server(w.cloud.snapshot()["volumes"] and list(w.cloud.snapshot()["servers"])[0],
                         guest_refuses_detach=True)  # fmt: skip
    to_cutover(w)
    w.drive(tick=200)
    r = parked(w, "detach_rolled_back")
    assert not r["auto_restore_used"]


def test_restore_failure_is_needs_human_and_never_reenters_window(world: World) -> None:
    w = world
    lose_green_attach(
        w, fail_blue=True
    )  # W5 not done -> restore; S5 (attach to blue) keeps failing
    to_cutover(w)
    w.drive()
    r = w.run()
    assert r["state"] == "needs_human" and r["phase"] == "restore", explain(w)
    assert r["needs_human_reason"] in ("attach_not_done", "retries_exhausted")
    assert w.open_step()["step_key"] == "attach_to_old"
    assert [s["step_key"] for s in w.steps()].count(
        "attach_volume_green"
    ) == 1  # never re-enters the window


# --- operator actions -----------------------------------------------------------------------------------------


def test_operator_rollback_from_needs_human_window_converges(world: World) -> None:
    w = world
    w.guest.failures["data_attach"] = ["needs_human"]
    to_cutover(w)
    w.drive()
    parked(w, "data_attach_green_failed")
    w.signal("rollback", tc="wrong 000000")
    w.drive(max_passes=3)
    assert w.run()["state"] == "needs_human"  # refused: wrong TC
    w.signal("rollback", tc=w.blue_tc(), good_stepup=False)
    w.drive(max_passes=3)
    assert w.run()["state"] == "needs_human"  # refused: step-up for another action
    w.signal("rollback", tc=w.blue_tc())
    w.drive()
    restored(w)
    assert "restore.operator" in w.audit_actions()
    outcomes = [
        r["outcome"]
        for r in w.q("SELECT outcome FROM run_signal WHERE kind = 'rollback' ORDER BY created_at")
    ]
    assert (
        outcomes[0].startswith("refused")
        and outcomes[1].startswith("refused")
        and outcomes[2] == "rollback applied"
    )


def test_abort_in_build_discards_green(world: World) -> None:
    w = world
    w.start()
    w.drive(until="await_cutover")
    w.signal("abort", tc=w.green_tc())
    assert w.drive()["state"] == "rolled_back", explain(w)
    assert w.locks() == [] and w.cloud.snapshot()["servers"][w.ids["blue"]]["status"] == "ACTIVE"


def test_abort_after_cutover_is_refused_revert_restores_and_voids_g3(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    g3 = w.approve("retirement", decider="ap2")
    w.signal("abort", tc=w.blue_tc())
    w.signal("revert", tc=w.blue_tc())
    w.drive()
    restored(w)
    sig = {
        r["kind"]: r["outcome"]
        for r in w.q("SELECT kind, outcome FROM run_signal WHERE kind IN ('abort','revert')")
    }
    assert sig["abort"].startswith("refused") and sig["revert"] == "revert applied"
    roles = {r["openstack_server_id"]: r["role"] for r in w.q("SELECT * FROM managed_vm")}
    assert roles[w.ids["blue"]] == "current" and roles[w.green_id()] == "candidate"
    from ovlm.auth.sod import Gate
    from ovlm.renewal.evidence import _voided_by_run

    with w.admin.connect() as c:
        row = (
            c.execute(
                __import__("sqlalchemy").text("SELECT * FROM approval WHERE id = :i"), {"i": g3}
            )
            .mappings()
            .one()
        )
        assert _voided_by_run(c, w.run_id, row)  # SEC-R-8: the revert voided G3
    assert Gate.RETIREMENT.value == "retirement"


def test_g3_by_the_g2_approver_is_refused(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    w.approve("retirement", decider="ap")  # decided G2: two-person rule refuses
    w.drive()
    st = w.open_step()
    assert st["step_key"] == "await_retirement" or w.run()["state"] == "running"
    assert not any(s["step_key"] == "retire_old" for s in w.steps())


def test_x1_mismatch_needs_human_and_voids_g3(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    g3 = w.approve("retirement", decider="ap2")
    w.cloud.strict_gate = False
    w.cloud.update_floating_ip(
        w.ids["fip"], w.ids["blue_port"]
    )  # someone moved the FIP back by hand
    w.cloud.strict_gate = True
    w.drive()
    parked(w, "retire_precondition_mismatch")
    assert w.cloud.snapshot()["servers"][w.ids["blue"]]["status"] == "SHUTOFF"  # not deleted
    from ovlm.renewal.evidence import _voided_by_run

    with w.admin.connect() as c:
        row = (
            c.execute(
                __import__("sqlalchemy").text("SELECT * FROM approval WHERE id = :i"), {"i": g3}
            )
            .mappings()
            .one()
        )
        assert _voided_by_run(c, w.run_id, row)


def test_retry_step_after_needs_human_runs_the_step_again(world: World) -> None:
    w = world
    w.guest.failures["start_service"] = ["retryable"] * 3
    to_cutover(w)
    w.drive()
    parked(w, "post_start_failure")
    w.signal("retry_step")
    r = w.drive(until="await_retirement")
    assert r["state"] == "running" and w.run()["phase"] == "retained", explain(w)


def test_stateless_profile_skips_handoff_steps(world_factory: Any) -> None:
    w = world_factory()
    import json

    w.x("UPDATE renewal_plan SET resolved = jsonb_set(jsonb_set(resolved, '{data_volume}', 'null'), '{stateless}', "
        "'true')")  # fmt: skip
    # the plan hash binds ``resolved``: recompute it as the api would for a stateless plan
    from ovlm.renewal.plans import load_facts

    with w.admin.connect() as c:
        h = load_facts(c, w.ids["plan"]).recomputed_hash
    w.x("UPDATE renewal_plan SET plan_hash = :h", h=h)
    w.x("UPDATE approval SET bound_hash = :h", h=h)
    w.guest.volume_id = None
    to_cutover(w)
    w.drive(until="await_retirement")
    keys = w.keys()
    assert not any(k in keys for k in ("detach_volume", "attach_volume_green", "data_attach_green"))
    assert json.dumps(w.run()["phase"]) == '"retained"'


def test_w1_unmounted_blue_without_quiesce_record_stays_needs_human(world: World) -> None:
    """Lab finding AA keeps W1 strict: blue with the data volume not mounted and no earlier quiesce record is an
    unknown state. OVLM never passes ``quiesce_allow_unmounted`` to W1, so the quiesce refuses and the run parks
    inside the window, with no automatic restore."""
    w = world
    blue = w.ids["blue"]

    def unmounted_by_hand() -> None:
        w.guest.g(
            blue
        ).mounted = False  # somebody unmounted the volume on blue; no quiesce ever ran there

    w.guest.hooks["quiesce"] = unmounted_by_hand
    to_cutover(w)
    w.drive()
    r = parked(w, "quiesce_old_failed")
    assert not r["auto_restore_used"] and r["phase"] == "window"
    assert w.guest.quiesce_calls == [(blue, False)]
    assert w.attached() == [blue] and w.fip_port() == w.ids["blue_port"]
