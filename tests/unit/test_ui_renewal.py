"""Unit tests of the renewal view models (E6-3, E6-4): wording, timers, hash inputs, the restore table."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ovlm.ui import renewal_view as rv
from ovlm.ui.readiness_view import blockers, quota_check

RENEWAL_SRC = Path(rv.__file__).parents[1] / "renewal"
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)


def test_every_needs_human_reason_the_engine_can_set_has_plain_words() -> None:
    """A reason added to the steps without wording here would reach the operator as the generic text."""
    seen: set[str] = set()
    for path in RENEWAL_SRC.glob("*.py"):
        text = path.read_text()
        seen |= set(re.findall(r'NEEDS_HUMAN,\s*"([a-z_]+)"', text))
        seen |= set(re.findall(r'needs_human_reason="([a-z_]+)"', text))
    seen |= {
        "api_unreachable",
        "post_start_failure",
        "window_budget_exceeded",
        "volume_stuck_attaching",
        "server_locked",
    }
    missing = sorted(r for r in seen if r not in rv.NEEDS_HUMAN)
    assert not missing, f"no operator wording for needs_human reasons: {missing}"
    for reason, (what, todo) in rv.NEEDS_HUMAN.items():
        assert what.endswith(".") and todo, reason
        assert all(t for t in todo), reason


def test_needs_human_text_has_a_generic_fallback_and_says_it_is_unknown() -> None:
    known = rv.needs_human_text("post_start_failure")
    assert known["known"] and "pages an operator" in known["what"] and len(known["todo"]) >= 2
    unknown = rv.needs_human_text("something_new")
    assert not unknown["known"] and unknown["reason"] == "something_new" and unknown["todo"]
    assert rv.needs_human_text(None)["reason"] == "unknown"


def test_every_step_the_run_can_show_has_a_title() -> None:
    from ovlm.renewal.config import RESTORE_STEPS, WINDOW_STEPS
    from ovlm.renewal.definition import AFTER, BUILD

    for key in (*BUILD, *WINDOW_STEPS, *AFTER, *RESTORE_STEPS, "await_discard", "discard_green"):
        code, text = rv.step_title(key)
        assert code and text and text != key, key
    assert rv.step_title("unheard_of") == ("", "unheard of")


def test_duration_formats() -> None:
    assert (
        rv.duration(45) == "45s" and rv.duration(723) == "12m 03s" and rv.duration(3900) == "1h 05m"
    )
    assert rv.duration(0) == "0s" and rv.duration(-5) == "0s"
    assert rv.duration(None) == "unknown" and rv.duration("x") == "unknown"


def test_downtime_timer() -> None:
    assert rv.downtime({"downtime_started_at": None}) is None
    running = rv.downtime(
        {"downtime_started_at": (NOW - timedelta(minutes=5)).isoformat(), "max_window_duration_seconds": 3600, "worst_case_window_seconds": 1800}, NOW
    )  # fmt: skip
    assert (
        running
        and running["running"]
        and running["elapsed"] == 300
        and running["remaining"] == 3300
    )
    assert not running["over"] and running["percent"] == 8
    over = rv.downtime(
        {
            "downtime_started_at": (NOW - timedelta(hours=2)).isoformat(),
            "max_window_duration_seconds": 3600,
        },
        NOW,
    )
    assert over and over["over"] and over["remaining"] == -3600 and over["percent"] == 100
    ended = rv.downtime(
        {"downtime_started_at": (NOW - timedelta(minutes=9)).isoformat(), "downtime_ended_at": (NOW - timedelta(minutes=4)).isoformat(),
         "max_window_duration_seconds": 3600}, NOW,
    )  # fmt: skip
    assert ended and not ended["running"] and ended["elapsed"] == 300 and ended["remaining"] is None


def _resolved(*, auto: bool, snapshot: bool) -> dict[str, object]:
    return {"auto_restore_in_window": auto, "data_volume": {"snapshot_before_handoff": snapshot}}


def test_restore_table_follows_the_policy_switch_and_the_snapshot_decision_d1() -> None:
    no_snap = rv.restore_table(_resolved(auto=True, snapshot=False))
    by = {r["trigger"]: r for r in no_snap["rows"]}
    assert (
        by["W7 service start fails on the new VM"]["outcome"] == "no: stops and pages an operator"
    )
    assert by["W3 detach is rolled back by OpenStack"]["restores"] is True
    assert by["W1 quiesce the old VM fails"]["restores"] is False
    snap = rv.restore_table(_resolved(auto=True, snapshot=True))
    assert {r["trigger"]: r for r in snap["rows"]}["W7 service start fails on the new VM"][
        "restores"
    ] is True
    off = rv.restore_table(_resolved(auto=False, snapshot=True))
    assert not off["enabled"] and not any(r["restores"] for r in off["rows"])
    assert all("API unreachable" not in r["trigger"] or not r["restores"] for r in snap["rows"])


def test_hash_inputs_extracts_what_the_approver_must_see() -> None:
    approval = {
        "bound_hash": "h" * 64,
        "hash_inputs": {
            "resolved": {
                "profile_version": {"id": "pv", "number": 3, "spec_hash": "s"}, "automation": {"repo": "https://r.invalid/x.git", "sha": "a" * 40},
                "blue": {"name": "app", "server_id": "id1"}, "data_volume": {"volume_id": "vol"}, "security_groups": ["default"],
                "floating_ip": {"id": "f", "address": "192.0.2.1"}, "image": {"id": "i", "owner": "o"},
            },
            "policy": {"version": 7, "auto_restore_in_window": True},
            "automation_diff": {"previous_approved_sha": None, "sha": "a" * 40, "summary": "first approval of this repo"},
        },
    }  # fmt: skip
    got = rv.hash_inputs(approval)
    assert (
        got["profile"]["number"] == 3
        and got["automation"]["sha"] == "a" * 40
        and got["data_volume"]["volume_id"] == "vol"
    )
    assert got["diff"]["summary"] == "first approval of this repo" and got["policy"]["version"] == 7
    assert rv.hash_inputs({})["profile"] == {}  # tolerant of an approval without inputs
    rows = dict(rv.policy_rows({"version": 7, "approvals": {"plan": True, "cutover": False}, "max_window_duration_seconds": 3600,
                                "auto_restore_in_window": False, "windows": [{"weekdays": ["sat"], "start": "01:00", "end": "05:00", "timezone": "UTC"}]}))  # fmt: skip
    assert rows["approvals required"] == "plan" and rows["automatic restore in the window"] == "off"
    assert (
        rows["maximum window duration"] == "1h 00m"
        and "sat 01:00-05:00 UTC" in rows["allowed windows"]
    )


def test_typed_target_splits_the_name_from_the_id_tail() -> None:
    assert rv.typed_target("app01-prod 3f9c2a") == {"name": "app01-prod", "tail": "3f9c2a"}
    assert rv.typed_target("name with spaces abc123") == {
        "name": "name with spaces",
        "tail": "abc123",
    }


def test_truth_sections_group_by_resource_and_tolerate_junk() -> None:
    got = rv.truth_sections(
        {"probed": "ok", "volume": {"status": "in-use", "attached_to": "green"}, "fip": {}}
    )
    assert got[0][0] == "general" and got[1][0] == "volume"
    assert ("attached to", "green") in got[1][1]
    assert (
        rv.truth_sections(None) == []
        and rv.truth_sections("text") == []
        and rv.truth_sections({}) == []
    )


def test_blockers_and_quota_from_an_assessment() -> None:
    a = {"checks": [
        {"key": "data.separate_volume", "severity": "blocker", "result": "fail", "recommendation": "Move the data"},
        {"key": "vm.state_supported", "severity": "blocker", "result": "pass"},
        {"key": "network.floating_ip", "severity": "blocker", "result": "unknown"},
        {"key": "platform.quota_headroom", "severity": "warning", "result": "unknown", "recommendation": "Check quota"},
    ]}  # fmt: skip
    assert [b["key"] for b in blockers(a)] == ["data.separate_volume", "network.floating_ip"]
    q = quota_check(a)
    assert q and q["result"] == "unknown" and q["recommendation"] == "Check quota"
    assert (
        blockers(None) == [] and quota_check(None) is None and quota_check({"checks": []}) is None
    )
