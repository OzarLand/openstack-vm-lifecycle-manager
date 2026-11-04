"""Section 5.1 (SEC-R-34, SRE-R-26; WF-23, WF-24): self-resolution of ``needs_human(api_unreachable)``."""

from __future__ import annotations

from ovlm.openstack.errors import ServerError
from ovlm.renewal.reprobe import REPROBE_KIND, REPROBE_STRATEGY
from ovlm.workflow.requests import request_run
from tests.integration.renewal.conftest import World, explain, to_cutover


def _outage_during_w3(w: World) -> None:
    """The W3 detach is sent, then the API goes away until the step gives up: needs_human(api_unreachable)."""
    to_cutover(w)
    w.drive(until="detach_volume")
    w.engine.run_once()  # type: ignore[union-attr] # act: detach sent, verify -> Wait
    assert w.cloud.calls.count("detach_volume") == 1
    w.cloud.fail("get_volume", ServerError("unreachable", status=503), times=1000)
    w.cloud.fail("get_server", ServerError("unreachable", status=503), times=1000)
    w.drive(tick=30)
    r = w.run()
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "api_unreachable", explain(w)
    assert not r["auto_restore_used"]
    w.cloud._rules.clear()  # noqa: SLF001 - the API is back; the detach landed meanwhile


def _reprobe_job(w: World) -> None:
    """The scheduler's periodic job inserts the system probe signal for parked api_unreachable runs."""
    with w.api.begin() as c:
        request_run(c, kind=REPROBE_KIND, strategy=REPROBE_STRATEGY, strategy_version="1")
    for _ in range(4):
        w.engine.run_once()  # type: ignore[union-attr]
    sigs = w.q("SELECT * FROM run_signal WHERE run_id = :r AND kind = 'probe'", r=w.run_id)
    assert (
        sigs and sigs[0]["actor_id"] is None and sigs[0]["payload"] == {"auto": "api_unreachable"}
    )


def test_rule1_exact_expected_post_state_continues_forward_without_resending(world: World) -> None:
    w = world
    _outage_during_w3(w)
    _reprobe_job(w)
    r = w.drive(until="await_retirement")
    assert r["state"] == "running" and w.run()["phase"] == "retained", explain(w)
    assert w.cloud.calls.count("detach_volume") == 1  # nothing re-sent for the failed step
    assert not w.run()["auto_restore_used"]
    rules = [
        r["after"]["rule"]
        for r in w.q("SELECT after FROM audit_event WHERE action = 'resume.auto'")
    ]
    assert rules and rules[0].startswith("rule 1")


def test_rule0_past_the_budget_stays_needs_human(world: World) -> None:
    w = world
    _outage_during_w3(w)
    w.x(
        "UPDATE workflow_run SET downtime_started_at = now() - interval '5 hours' WHERE id = :r",
        r=w.run_id,
    )
    _reprobe_job(w)
    w.drive(max_passes=5)
    r = w.run()
    assert r["state"] == "needs_human" and r["needs_human_reason"] == "api_unreachable"
    rules = [
        r["after"]["rule"]
        for r in w.q("SELECT after FROM audit_event WHERE action = 'resume.auto'")
    ]
    assert rules and rules[0].startswith("rule 0")
    assert (
        r["current_truth"]["api_reachable"] is True
    )  # the panel is refreshed even when nothing moves


def test_probe_signal_from_operator_refreshes_truth_only(world: World) -> None:
    w = world
    _outage_during_w3(w)
    w.signal("probe")
    w.drive(max_passes=3)
    r = w.run()
    assert r["state"] == "needs_human" and r["current_truth"]["volume"]["status"] == "available"
