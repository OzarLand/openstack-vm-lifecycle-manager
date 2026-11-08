"""Defect AB end to end: the data marker reported as ``facts.marker_sha256`` (automation-contract 3.7, the reference
roles, and now the fake guest) is recorded by W1, passed to and compared by W6 and W8, and its absence or a
different value stops the run instead of being skipped."""

from __future__ import annotations

from typing import Any

from tests.integration.renewal.conftest import World, explain, to_cutover


def _step(w: World, key: str) -> Any:
    return next(s for s in reversed(w.steps()) if s["step_key"] == key)


def test_w1_records_the_marker_and_w6_w8_compare_it(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="await_retirement")
    marker = w.guest.marker
    w1 = _step(w, "quiesce_old")
    assert w1["state"] == "succeeded" and w1["evidence"]["marker_checksum"] == marker, explain(w)
    for key in ("data_attach_green", "healthcheck_green"):
        st = _step(w, key)
        assert st["state"] == "succeeded", (key, explain(w))
        assert st["evidence"]["marker_comparison"] == "equal", key
    # the playbooks were told what to compare against (contract 3.3, 3.6)
    asked = dict((p, m) for p, m in w.guest.expected_markers if p in ("data_attach", "healthcheck"))
    assert asked == {"data_attach": marker, "healthcheck": marker}


def test_w8_fails_on_green_with_a_different_marker(world: World) -> None:
    """A healthy service on green that reports another marker than W1 recorded is not a successful renewal."""
    w = world
    w.guest.hooks["healthcheck"] = lambda: setattr(w.guest, "marker", "marker-tampered")
    to_cutover(w)
    w.drive()
    r = w.run()
    assert r["state"] == "needs_human", explain(w)
    assert r["needs_human_reason"] == "post_start_failure"
    hc = _step(w, "healthcheck_green")
    assert hc["state"] != "succeeded", explain(w)
    err = hc["error"]
    assert err["reason"] == "healthcheck_exhausted" and err["phase_reason"] == "healthy"
    assert err["marker_comparison"] == "differs"
    assert w.fip_port() == w.ids["blue_port"]  # the FIP never moved to green


def test_w1_without_a_marker_parks_and_rollback_restores_blue(world: World) -> None:
    """A repository whose quiesce omits the marker: W1 parks (contract 3.4 requires it), nothing further runs."""
    w = world
    w.guest.hooks["quiesce"] = lambda: setattr(w.guest, "marker", None)
    to_cutover(w)
    w.drive()
    r = w.run()
    assert r["state"] == "needs_human", explain(w)
    assert r["needs_human_reason"] == "quiesce_no_marker"
    assert not r["auto_restore_used"] and r["downtime_started_at"] is not None
    keys = w.keys()
    assert "stop_old" not in keys
    assert w.attached() == [w.ids["blue"]]
    w.guest.marker = "marker-v1"  # (the volume's content is unchanged; only the report lacked it)
    w.signal("rollback", tc=w.blue_tc())
    w.drive()
    assert w.attached() == [w.ids["blue"]] and w.fip_port() == w.ids["blue_port"]
    assert w.guest.state[w.ids["blue"]].mounted and w.guest.state[w.ids["blue"]].units, explain(w)
    assert w.open_step()["step_key"] == "await_discard", explain(w)
