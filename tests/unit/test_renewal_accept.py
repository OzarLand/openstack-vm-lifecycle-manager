"""``accept-step`` rules without a database (ADR-0008, :mod:`ovlm.renewal.accept`): where it applies (T1, the parts
that do not need a run) and S2's postcondition check by check (T2). The engine, refusals with audit rows and the D-8
reproduction are in ``tests/integration/renewal/test_accept_step.py``."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from ovlm.renewal import accept
from ovlm.renewal.service import available_actions

GREEN, BLUE = "green-0000-0001", "blue-0000-0001"
REFUSED = {
    "reason": "quiesce_green_failed",
    "playbook_reported": "needs_human",
    "phase_reason": "state unknown",
}


def _na(
    step_key: str = "quiesce_green", phase: str = "restore", error: Any = None, **kw: Any
) -> str | None:
    return accept.not_applicable(
        run_state=kw.get("run_state", "needs_human"), step_key=step_key, step_state=kw.get("step_state", "needs_human"),
        phase=phase, error=REFUSED if error is None else error,
    )  # fmt: skip


def test_applies_only_to_s2_parked_on_its_own_playbook_refusal_in_restore() -> None:
    assert _na() is None
    assert accept.applies_to("quiesce_green", {**REFUSED, "playbook_reported": "fatal"})


@pytest.mark.parametrize(
    "step",
    ["quiesce_old", "data_attach_green", "detach_from_green", "attach_to_old", "move_fip_to_old",
     "recover_old_service", "unlock_old", "stop_green", "boot_old", "verify_external_old"],
)  # fmt: skip
def test_no_other_step_is_allowlisted(step: str) -> None:
    """W1, W6 (marker proof), S4, S5, S8 (volume, FIP), S1, S3, S6, S10 (OpenStack), S7 (maintainer Q2)."""
    assert _na(step, error={**REFUSED, "reason": f"{step}_failed"}) is not None


@pytest.mark.parametrize("phase", ["build", "window", "retained", "retire"])
def test_never_outside_the_restore_phase(phase: str) -> None:
    why = _na(phase=phase)
    assert why is not None and "restore phase" in why


@pytest.mark.parametrize(
    "error",
    [
        {"reason": "data_phase_interrupted"},  # maintainer decision Q3: retry-step is the exit
        {"reason": "automation_checkout_lost"},  # reprepare-automation
        {"reason": "automation_checkout_unverifiable"},
        {"reason": "approval_evidence_invalid"},
        {"reason": "ownership_violation"},
        {"reason": "lock_conflict"},
        {"reason": "api_unreachable"},
        {
            "reason": "quiesce_green_failed",
            "phase_reason": "timeout in quiesce",
        },  # did not run to a result
        {"reason": "quiesce_green_failed", "playbook_reported": "retryable"},
        {"reason": "automation_error", "playbook_reported": "needs_human"},
        {},
    ],
)
def test_only_a_playbook_refusal_is_an_entry(error: dict[str, Any]) -> None:
    assert _na(error=error) is not None and not accept.applies_to("quiesce_green", error)


def test_not_while_the_run_or_step_is_not_parked() -> None:
    assert _na(run_state="running") is not None
    assert _na(step_state="succeeded") is not None


@pytest.mark.parametrize(("text", "ok"), [("", False), ("x" * 19, False), ("x" * 20, True),
                                          ("x" * 2000, True), ("x" * 2001, False), (" " * 30, False)])  # fmt: skip
def test_attestation_is_20_to_2000_characters(text: str, ok: bool) -> None:
    assert (accept.attestation_problem(text) is None) is ok


# --- the postcondition (T2) ---------------------------------------------------------------------------------------


def _cloud(**kw: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "api_reachable": True,
        "green": {"id": GREEN, "status": "ACTIVE", "task_state": None},
        "volume": {"status": "in-use", "attached_to": [GREEN]},
    }
    for k, v in kw.items():
        out[k] = {**out[k], **v} if isinstance(v, dict) else v
    return out


def _guest(**kw: Any) -> dict[str, Any]:
    return {
        "reachable": True, "mount_point": "/srv/data", "mount_point_mounted": False, "device_mounted": False,
        "device_mountpoints": [], "unit_states": {"app.service": "inactive", "db.service": "failed"},
    } | kw  # fmt: skip


def _failed(cloud: dict[str, Any], guest: dict[str, Any]) -> list[str]:
    checks = accept.evaluate(
        cloud=cloud, guest=guest, green_id=GREEN, units=("app.service", "db.service")
    )
    return [c["check"] for c in checks if not c["ok"]]


def test_the_postcondition_holds() -> None:
    assert _failed(_cloud(), _guest()) == []


@pytest.mark.parametrize(
    ("cloud", "guest", "check"),
    [
        ({}, {"mount_point_mounted": True, "device_mounted": True, "device_mountpoints": ["/srv/data"]},
         "data_device_mounted_nowhere"),
        ({}, {"device_mounted": True, "device_mountpoints": ["/mnt/other"]}, "data_device_mounted_nowhere"),
        ({}, {"device_mounted": None}, "data_device_mounted_nowhere"),
        ({}, {"mount_point_mounted": None}, "mount_point_not_a_mount"),
        ({}, {"unit_states": {"app.service": "active", "db.service": "inactive"}}, "service_units_stopped"),
        ({}, {"unit_states": {"app.service": "activating", "db.service": "inactive"}}, "service_units_stopped"),
        ({}, {"unit_states": {"app.service": "inactive"}}, "service_units_stopped"),  # db.service unknown
        ({}, {"unit_states": None}, "service_units_stopped"),
        ({}, {"reachable": False}, "guest_reachable"),
        ({"volume": {"attached_to": [GREEN, BLUE]}}, {}, "volume_on_green_only"),
        ({"volume": {"attached_to": [BLUE]}}, {}, "volume_on_green_only"),
        ({"volume": {"status": "detaching"}}, {}, "volume_on_green_only"),
        ({"green": {"status": "SHUTOFF"}}, {}, "green_active"),
        ({"green": {"task_state": "powering-off"}}, {}, "green_active"),
        ({"api_reachable": False}, {}, "cloud_reachable"),
    ],
)  # fmt: skip
def test_each_unmet_or_unknown_fact_fails_the_postcondition(
    cloud: dict[str, Any], guest: dict[str, Any], check: str
) -> None:
    assert check in _failed(_cloud(**cloud), _guest(**guest))


def test_probe_age_and_facts() -> None:
    now = datetime.now(UTC)
    p = {
        "id": "p1",
        "at": (now - timedelta(seconds=61)).isoformat(),
        "cloud": {"a": 1},
        "guest": {"b": 2},
    }
    age = accept.probe_age(p, now)
    assert age is not None and age > accept.FRESH_SECONDS
    assert (
        accept.probe_age({"id": "p1"}, now) is None
        and accept.probe_age({"at": "nonsense"}, now) is None
    )
    assert accept.facts(p) == accept.facts({**p, "id": "p2", "at": "later"})
    assert accept.facts(p) != accept.facts({**p, "guest": {"b": 3}})


def test_refused_result_digest_is_canonical() -> None:
    a = accept.refused_result_sha256({"reason": "x", "facts": {"b": 1, "a": 2}})
    b = accept.refused_result_sha256({"facts": {"a": 2, "b": 1}, "reason": "x"})
    assert a == b and len(a) == 64


# --- available actions ------------------------------------------------------------------------------------------


def _offer(truth: Any, now: datetime, error: dict[str, Any] | None = None) -> dict[str, Any] | None:
    run = {"state": "needs_human", "phase": "restore", "current_truth": truth, "downtime_started_at": None,
           "downtime_ended_at": None}  # fmt: skip
    step = {"id": "s2", "step_key": "quiesce_green", "state": "needs_human", "attempt": 1,
            "error": error or REFUSED}  # fmt: skip
    resolved = {"data_volume": {"volume_id": "v"}}
    return next(
        (
            a
            for a in available_actions(run, step, resolved, now=now)
            if a["action"] == "accept-step"
        ),
        None,
    )


def test_offered_only_with_a_fresh_probe_meeting_the_postcondition() -> None:
    now = datetime.now(UTC)
    probe = {"id": "p1", "step_id": "s2", "attempt": 1, "at": now.isoformat(), "ok": True, "volume_id": "v",
             "checks": [], "guest": {"mount_point": "/srv/data"}}  # fmt: skip
    offer = _offer({"accept_probe": probe}, now)
    assert offer is not None and offer["available"] is True and offer["probe_id"] == "p1"
    assert "without running quiesce.yml" in offer["effect"] and "S3 stops green" in offer["effect"]
    none = _offer({}, now)
    assert none is not None and none["available"] is False and "press Probe first" in none["effect"]
    stale = _offer({"accept_probe": probe}, now + timedelta(seconds=61))
    assert stale is not None and stale["available"] is False and "press Probe" in stale["effect"]
    other = _offer({"accept_probe": {**probe, "attempt": 2}}, now)
    assert other is not None and other["available"] is False
    bad = {**probe, "ok": False, "checks": [{"check": "data_device_mounted_nowhere", "ok": False,
                                             "detail": "data device mounted /srv/data"}]}  # fmt: skip
    unmet = _offer({"accept_probe": bad}, now)
    assert (
        unmet is not None
        and unmet["available"] is False
        and "data device mounted /srv/data" in unmet["effect"]
    )
    assert (
        _offer({"accept_probe": probe}, now, {"reason": "data_phase_interrupted"}) is None
    )  # not listed at all
