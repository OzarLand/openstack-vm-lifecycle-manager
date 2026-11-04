"""Regression tests for the independent review of the renewal code (docs/reviews/review-renewal-code.md).

Each test reproduces a reviewer finding (REN-n) against the fake cloud and guest; each one failed before its fix.
"""

from __future__ import annotations

from typing import Any

from ovlm.openstack.errors import ServerError
from ovlm.renewal.config import RenewalConfig
from ovlm.renewal.definition import BUILD
from ovlm.renewal.service import available_actions
from tests.integration.renewal.conftest import CFG, World, explain, to_cutover
from tests.integration.renewal.test_failures import (
    calls,
    deleted,
    expire_deadline,
    parked,
    restored,
)


def _expire_g2(w: World) -> None:
    w.x("UPDATE approval SET expires_at = now() - interval '1 minute' WHERE subject_type = 'cutover' "
        "AND subject_id = :r", r=w.run_id)  # fmt: skip


def _outcome(w: World, kind: str) -> str:
    rows = w.q("SELECT outcome FROM run_signal WHERE run_id = :r AND kind = :k ORDER BY created_at DESC",
               r=w.run_id, k=kind)  # fmt: skip
    return str(rows[0]["outcome"])


def _never_back_to_build(w: World) -> None:
    keys = w.keys()
    after_claim = keys[keys.index("quiesce_old") :]
    assert not [k for k in after_claim if k in BUILD or k == "discard_green"], explain(w)


# --- REN-1: a W1 re-run inside the outage never returns to the build phase ------------------------------------------


def _quiesce_failed(w: World, failures: int) -> Any:
    w.guest.failures["quiesce"] = ["retryable"] * failures
    to_cutover(w)
    w.drive()
    r = parked(w, "quiesce_old_failed")
    assert r["phase"] == "window" and r["downtime_started_at"] is not None
    return r["downtime_started_at"]


def test_ren1_w1_rerun_with_expired_g2_stale_b9_and_short_credential_finishes_forward(
    world: World,
) -> None:
    """Reviewer probe 1, forward variant: after the claim the refusing checks no longer apply (section 2.2: an
    approval never expires mid-outage). retry-step re-runs W1 inside the window and the run completes the cutover."""
    from datetime import UTC, datetime, timedelta

    w = world
    started = _quiesce_failed(w, 1)
    _expire_g2(w)  # a 3 a.m. page: G2's validity ran out while the run waited for a human
    w.port.credential_expires = datetime.now(UTC) + timedelta(minutes=5)
    w.make_engine(RenewalConfig(**{**CFG.__dict__, "green_ready_max_age": 1e-9}))  # B9 now "stale"
    w.signal("retry_step", tc=w.blue_tc())
    r = w.drive(until="await_retirement")
    assert r["state"] == "running" and r["phase"] == "retained", explain(w)
    assert r["downtime_started_at"] == started  # the first claim's timestamp is kept
    _never_back_to_build(w)
    assert not deleted(w, w.green_id())


def test_ren1_w1_rerun_failing_again_stays_in_window_and_rollback_restores_blue(
    world: World,
) -> None:
    """Reviewer probe 1, verbatim: quiesce fails after the claim, G2 expires, retry-step. Before the fix the run went
    back to ``await_cutover`` in phase ``build`` and ``rollback`` deleted green with blue still quiesced. Now: the
    re-run fails inside the window, and rollback restores blue (expected end state: ``await_discard``, blue ACTIVE,
    mounted, units active)."""
    w = world
    _quiesce_failed(w, 2)
    _expire_g2(w)
    w.signal("retry_step", tc=w.blue_tc())
    w.drive()
    r = parked(w, "quiesce_old_failed")
    assert r["phase"] == "window" and r["downtime_ended_at"] is None
    _never_back_to_build(w)
    effects = {a["action"]: a["effect"] for a in _actions(w)}
    assert (
        "delete green" not in effects["rollback"]
        and "attach the volume to blue" in effects["rollback"]
    )
    w.signal("rollback", tc=w.blue_tc())
    w.drive()
    restored(w)
    assert not deleted(w, w.green_id()) and calls(w, "delete_server") == 0
    _never_back_to_build(w)


def test_ren1_w1_rerun_with_voided_g2_is_needs_human_in_the_window(world: World) -> None:
    """Inside the outage W1 still re-validates G2's integrity: a voided approval parks in the window (not build)."""
    w = world
    _quiesce_failed(w, 1)
    w.x("UPDATE approval SET void_reason = 'test' WHERE subject_type = 'cutover' AND subject_id = :r",
        r=w.run_id)  # fmt: skip
    w.signal("retry_step", tc=w.blue_tc())
    w.drive()
    r = parked(w, "approval_evidence_invalid")
    assert r["phase"] == "window"
    _never_back_to_build(w)
    assert [c for c in w.guest.calls if c[0] == "quiesce"] == [
        ("quiesce", w.ids["blue"])
    ]  # not re-run


def _actions(w: World) -> list[dict[str, Any]]:
    resolved = w.q("SELECT resolved FROM renewal_plan WHERE id = :p", p=w.ids["plan"])[0][
        "resolved"
    ]
    return available_actions(w.run(), w.open_step(), resolved, None)


def test_ren1_open_outage_with_a_stored_build_phase_restores_never_discards(world: World) -> None:
    """Belt for a run an older version left in ``build`` with the outage open: the page offers the restore, the TC is
    blue's, and rollback restores blue; green is never deleted."""
    w = world
    _quiesce_failed(w, 1)
    w.x("UPDATE workflow_run SET phase = 'build' WHERE id = :r", r=w.run_id)
    effects = {a["action"]: a["effect"] for a in _actions(w)}
    assert (
        "attach the volume to blue" in effects["rollback"]
        and "delete green" not in effects["rollback"]
    )
    w.signal("rollback", tc=w.green_tc())  # green's TC (the build-phase target) is refused
    w.drive(max_passes=3)
    assert _outcome(w, "rollback").startswith("refused"), explain(w)
    w.signal("rollback", tc=w.blue_tc())
    w.drive()
    restored(w)
    assert not deleted(w, w.green_id())


# --- REN-3: a deadline without a fresh probe is not "api_unreachable" ------------------------------------------------


def test_ren3_w2_deadline_before_acting_parks_deadline_exceeded(world: World) -> None:
    """Reviewer probe 3: the deadline passes before W2 acts. The API answered: park ``deadline_exceeded`` (no
    self-resolution, no automatic restore), not ``api_unreachable``."""
    w = world
    to_cutover(w)
    w.drive(until="stop_old")
    expire_deadline(w)
    w.drive()
    r = parked(w, "deadline_exceeded")
    assert not r["auto_restore_used"] and calls(w, "stop_server") == 0


# --- REN-4: revert is refused once X1 persisted its delete intent ------------------------------------------------


def test_ren4_revert_refused_after_x1_sent_the_delete_run_still_completes(world: World) -> None:
    """X1's delete lands but its response is lost (retryable); an operator sends revert meanwhile. Before the fix the
    revert started a restore on a deleted blue that could never finish. Now the revert is refused and X1 completes."""
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    w.approve("retirement", decider="ap2")
    w.drive(until="retire_old")
    w.cloud.fail("delete_server", ServerError("lost", status=502), when="after_apply")
    assert w.engine is not None
    w.engine.run_once()  # X1: probe, intent, unlock + delete (applied, response lost)
    assert w.open_step()["step_key"] == "retire_old" and calls(w, "delete_server") == 1
    w.signal("revert", tc=w.blue_tc())
    r = w.drive()
    assert r["state"] == "completed", explain(w)
    assert _outcome(w, "revert").startswith("refused") and "revert impossible" in _outcome(
        w, "revert"
    )
    assert "unlock_old" not in w.keys()  # noqa: SIM118 - World.keys() lists step keys


# --- REN-5: mark-resolved needs the approver when the *current* step is destructive ---------------------------------


def test_ren5_mark_resolved_on_a_destructive_current_step_needs_the_approver(world: World) -> None:
    """X1 (destructive) parks; nothing follows it. The engine re-queues X1 itself on mark-resolved, so its delete is
    the next destructive call: an operator without the approver role is refused."""
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    w.approve("retirement", decider="ap2")
    w.cloud.strict_gate = False
    w.cloud.update_floating_ip(w.ids["fip"], w.ids["blue_port"])  # precondition mismatch at X1
    w.cloud.strict_gate = True
    w.drive()
    parked(w, "retire_precondition_mismatch")
    w.signal("mark_resolved", tc=w.blue_tc(), attestation="fixed by hand")
    w.drive(max_passes=3)
    assert "approver" in _outcome(w, "mark_resolved") and _outcome(w, "mark_resolved").startswith(
        "refused"
    )
    parked(w, "retire_precondition_mismatch")


# --- REN-6: S6 never starts blue without its data volume -------------------------------------------------------------


def test_ren6_boot_old_refuses_when_the_volume_is_not_on_blue(world: World) -> None:
    """W2 exhausted -> restore. Between S5 and S6 someone detaches the data volume from blue by hand: S6 parks
    ``volume_not_on_blue`` instead of booting blue without its data."""
    w = world
    w.cloud.fail("stop_server", ServerError("boom", status=500), times=3)
    to_cutover(w)
    w.drive(until="boot_old")
    w.cloud.strict_gate = False
    w.cloud.detach_volume(w.ids["blue"], w.ids["volume"])
    w.cloud.strict_gate = True
    w.cloud.tick(60)
    assert w.attached() == []
    stops, starts = calls(w, "stop_server"), calls(w, "start_server")
    w.drive()
    r = parked(w, "volume_not_on_blue")
    assert r["phase"] == "restore"
    assert (calls(w, "stop_server"), calls(w, "start_server")) == (stops, starts)


# --- REN-7: Discarding finds a run-tagged green the ledger has no id for ----------------------------------------------


def test_ren7_discard_finds_an_unrecorded_green_by_tag_and_name(world: World) -> None:
    """The Nova create landed but its response was lost (the ledger row has no id); the operator rolls back before
    any retry. Before the fix Discarding answered "absent" and left the server; now it parks ``green_unrecorded``."""
    w = world
    w.start()
    w.drive(until="create_green")
    w.cloud.fail("create_server", ServerError("lost", status=502), when="after_apply")
    assert w.engine is not None
    w.engine.run_once()  # B3: ledger intent, create (applied, response lost) -> retryable
    assert w.green_id() is None
    live = [sid for sid, s in w.cloud.snapshot()["servers"].items() if sid != w.ids["blue"]]
    assert len(live) == 1
    w.signal("rollback", tc=w.blue_tc())  # no green id recorded: the TC is blue's
    w.drive()
    r = parked(w, "green_unrecorded")
    assert r["state"] == "needs_human" and calls(w, "delete_server") == 0
    st = w.open_step()
    assert st["step_key"] == "discard_green" and st["error"]["servers"] == live
