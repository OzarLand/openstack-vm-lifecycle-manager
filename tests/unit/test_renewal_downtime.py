"""Unit tests of the run's downtime summary (``ovlm.renewal.downtime``, roadmap P0-3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ovlm.renewal import downtime

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


def _iv(kind: str, start: datetime, end: datetime | None) -> dict[str, object]:
    return {"kind": kind, "started_at": start, "started_by_step": "quiesce_old", "ended_at": end,
            "ended_by_step": None if end is None else "verify_external", "ongoing": end is None,
            "seconds": ((end or NOW) - start).total_seconds()}  # fmt: skip


def test_total_is_the_sum_of_every_interval() -> None:
    a = _iv("window", NOW - timedelta(hours=1), NOW - timedelta(hours=1) + timedelta(seconds=40.6))
    b = _iv(
        "restore", NOW - timedelta(minutes=5), NOW - timedelta(minutes=5) + timedelta(seconds=218.4)
    )
    out = downtime.summary([a, b], terminal=False)
    assert out["measured"] and out["complete"] and not out["ongoing"]
    assert out["total_seconds"] == 259.0 and len(out["intervals"]) == 2


def test_no_interval_is_not_measured_never_zero() -> None:
    out = downtime.summary([], terminal=True)
    assert out == {
        "measured": False,
        "intervals": [],
        "total_seconds": None,
        "ongoing": False,
        "complete": False,
    }


def test_open_interval_is_ongoing_while_the_run_lives() -> None:
    out = downtime.summary([_iv("restore", NOW - timedelta(seconds=30), None)], terminal=False)
    assert out["ongoing"] and out["intervals"][0]["ongoing"] and out["total_seconds"] == 30.0


def test_open_interval_of_a_finished_run_has_an_unmeasured_end() -> None:
    a = _iv("window", NOW - timedelta(hours=1), NOW - timedelta(minutes=59))
    b = _iv("restore", NOW - timedelta(seconds=30), None)
    out = downtime.summary([a, b], terminal=True)
    assert not out["ongoing"] and not out["complete"]
    assert out["intervals"][1]["seconds"] is None and out["intervals"][1]["end_measured"] is False
    assert out["total_seconds"] == 60.0  # only what was measured


def test_run_columns_read_as_the_first_window_interval() -> None:
    run = {
        "downtime_started_at": NOW - timedelta(seconds=50),
        "downtime_ended_at": NOW - timedelta(seconds=8),
    }
    (only,) = downtime.from_run_columns(run, NOW)
    assert only["kind"] == "window" and only["seconds"] == 42.0 and not only["ongoing"]
    assert downtime.from_run_columns({"downtime_started_at": None}, NOW) == []
