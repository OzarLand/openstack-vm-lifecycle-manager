"""Pure rules of the policies module: durations, windows, resolution (FR-POL-2/4), deadlines (FR-POL-5), exceptions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from ovlm.policies.deadline import Deadline, ExceptionRef, active_exception, compute_deadline
from ovlm.policies.durations import format_duration, parse_duration
from ovlm.policies.models import PolicyIn
from ovlm.policies.resolve import BindingRef, resolve
from ovlm.policies.windows import WindowRule, next_window, rule_from_dict


def utc(year: int, month: int, day: int, hour: int = 0, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def rule(days: list[str], start: str, end: str, tz: str = "UTC") -> WindowRule:
    return rule_from_dict({"weekdays": days, "start": start, "end": end, "timezone": tz})


# --- durations ------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("P90D", 90 * 86400),
        ("PT6H", 21600),
        ("P1DT12H30M", 131400),
        ("PT90M", 5400),
        ("p2d", 172800),
    ],
)
def test_duration_parses(text: str, seconds: int) -> None:
    assert parse_duration(text) == seconds


@pytest.mark.parametrize(
    "text", ["", "P", "PT", "P1Y", "P1W", "P1M", "90", "PT0M", "P0D", "P1DT", "-P1D", "P1.5D"]
)
def test_duration_refuses_calendar_units_and_zero(text: str) -> None:
    with pytest.raises(ValueError, match="duration"):
        parse_duration(text)


@pytest.mark.parametrize("seconds", [60, 3600, 86400, 131400, 90 * 86400])
def test_duration_round_trips(seconds: int) -> None:
    assert parse_duration(format_duration(seconds)) == seconds


# --- windows --------------------------------------------------------------------------------------------------------


def test_next_window_is_the_anchor_itself_inside_a_window() -> None:
    sat = rule(["sat"], "02:00", "06:00")
    anchor = utc(2027, 1, 2, 3, 30)  # a Saturday
    assert next_window(anchor, [sat]) == (anchor, utc(2027, 1, 2, 6))


def test_next_window_after_the_close_is_next_week() -> None:
    sat = rule(["sat"], "02:00", "06:00")
    assert next_window(utc(2027, 1, 2, 6, 0), [sat]) == (utc(2027, 1, 9, 2), utc(2027, 1, 9, 6))
    assert next_window(utc(2027, 1, 2, 1, 0), [sat]) == (utc(2027, 1, 2, 2), utc(2027, 1, 2, 6))


def test_the_earliest_of_several_windows_wins() -> None:
    rules = [rule(["sun"], "01:00", "03:00"), rule(["tue", "thu"], "22:00", "23:30")]
    assert next_window(utc(2027, 1, 4, 12), rules) == (
        utc(2027, 1, 5, 22),
        utc(2027, 1, 5, 23, 30),
    )  # Mon noon -> Tue


def test_windows_follow_the_zone_and_daylight_saving() -> None:
    zrh = rule(["sat"], "02:00", "04:00", "Europe/Zurich")
    winter = next_window(utc(2027, 1, 1), [zrh])
    summer = next_window(utc(2027, 7, 1), [zrh])
    assert winter == (utc(2027, 1, 2, 1), utc(2027, 1, 2, 3))  # UTC+1
    assert summer == (utc(2027, 7, 3, 0), utc(2027, 7, 3, 2))  # UTC+2


def test_a_nonexistent_local_time_does_not_break_the_search() -> None:
    zrh = rule(["sun"], "02:30", "04:00", "Europe/Zurich")  # 2027-03-28 02:30 does not exist
    start, end = next_window(utc(2027, 3, 27, 12), [zrh]) or (None, None)
    assert (
        start is not None
        and end is not None
        and start < end
        and start.date() == end.date() == utc(2027, 3, 28).date()
    )


def test_no_windows_no_answer() -> None:
    assert next_window(utc(2027, 1, 1), []) is None


# --- effective policy -----------------------------------------------------------------------------------------------


def test_service_binding_beats_group_binding_and_says_why() -> None:
    svc, grp = uuid4(), uuid4()
    b_grp = BindingRef(uuid4(), uuid4(), "service_group", grp)
    b_svc = BindingRef(uuid4(), uuid4(), "service", svc)
    res = resolve(svc, grp, [b_grp, b_svc, BindingRef(uuid4(), uuid4(), "service", uuid4())])
    assert res.winner == b_svc and res.shadowed == (b_grp,) and "most specific" in res.reason
    assert resolve(svc, grp, [b_grp]).winner == b_grp


def test_no_binding_means_no_policy() -> None:
    svc, grp = uuid4(), uuid4()
    other = [
        BindingRef(uuid4(), uuid4(), "service_group", uuid4()),
        BindingRef(uuid4(), uuid4(), "service", uuid4()),
    ]
    res = resolve(svc, grp, other)
    assert res.winner is None and "never due" in res.reason
    assert resolve(svc, None, [BindingRef(uuid4(), uuid4(), "service_group", grp)]).winner is None


# --- deadlines ------------------------------------------------------------------------------------------------------

WEEKEND = [rule(["sat", "sun"], "01:00", "05:00")]
LAUNCH = utc(2027, 1, 4, 9)  # a Monday


def test_without_a_policy_nothing_is_ever_due() -> None:
    d = compute_deadline(
        launched_at=LAUNCH - timedelta(days=5000),
        max_age_seconds=None,
        windows=[],
        now=utc(2030, 1, 1),
    )
    assert (d.status, d.due, d.deadline) == ("no_policy", False, None)


def test_deadline_is_launch_plus_max_age_adjusted_to_the_next_window() -> None:
    d = compute_deadline(
        launched_at=LAUNCH,
        max_age_seconds=parse_duration("P10D"),
        windows=WEEKEND,
        now=utc(2027, 1, 5),
    )
    assert d.deadline == utc(2027, 1, 14, 9)  # Thursday
    assert d.next_window_start == utc(2027, 1, 16, 1) and d.next_window_end == utc(2027, 1, 16, 5)
    assert (d.status, d.due) == ("scheduled", False)


def test_a_deadline_inside_a_window_is_its_own_window_start() -> None:
    d = compute_deadline(
        launched_at=utc(2027, 1, 4, 2),
        max_age_seconds=parse_duration("P5D"),
        windows=WEEKEND,
        now=utc(2027, 1, 4),
    )
    assert d.deadline == utc(2027, 1, 9, 2) == d.next_window_start


def test_due_once_the_deadline_has_passed() -> None:
    d = compute_deadline(
        launched_at=LAUNCH,
        max_age_seconds=parse_duration("P10D"),
        windows=WEEKEND,
        now=utc(2027, 1, 14, 9),
    )
    assert (d.status, d.due) == ("due", True)


def test_a_live_exception_waives_and_an_expired_one_does_not() -> None:
    now = utc(2027, 2, 1)
    live = ExceptionRef("x1", now - timedelta(days=1), now + timedelta(days=3), approved=True)
    old = ExceptionRef("x2", now - timedelta(days=9), now - timedelta(seconds=1), approved=True)
    pending = ExceptionRef("x3", now - timedelta(days=1), now + timedelta(days=3), approved=False)
    future = ExceptionRef("x4", now + timedelta(days=1), now + timedelta(days=3), approved=True)

    def deadline_with(exceptions: list[ExceptionRef]) -> Deadline:
        return compute_deadline(
            launched_at=LAUNCH,
            max_age_seconds=parse_duration("P10D"),
            windows=WEEKEND,
            now=now,
            exceptions=exceptions,
        )

    waived = deadline_with([old, pending, future, live])
    assert (waived.status, waived.due, waived.exception_id, waived.waived_until) == (
        "waived",
        False,
        "x1",
        live.expires_at,
    )
    assert waived.deadline == utc(2027, 1, 14, 9)  # the original deadline is still shown
    for ignored in ([old], [pending], [future]):
        assert deadline_with(ignored).due is True
    assert active_exception([old], now) is None and active_exception([live, pending], now) == live


# --- policy request validation --------------------------------------------------------------------------------------

GOOD = {
    "name": "weekly",
    "max_age": "P90D",
    "renewal_interval": "P60D",
    "windows": [
        {"weekdays": ["sat"], "start": "01:00", "end": "05:00", "timezone": "Europe/Zurich"}
    ],
    "max_window_duration": "PT2H",
}


def test_a_good_policy_validates_with_documented_defaults() -> None:
    p = PolicyIn.model_validate(GOOD)
    assert (
        p.approvals.plan
        and p.approvals.cutover
        and p.auto_restore_in_window
        and p.require_distinct_approvers
    )
    assert p.snapshot_retain_after_restore == "until_next_renewal" and p.retention_period is None


@pytest.mark.parametrize(
    ("patch", "needle"),
    [
        ({"max_window_duration": None}, "max_window_duration"),  # required (SRE-R-6)
        ({"max_window_duration": "PT5H"}, "does not fit"),
        ({"renewal_interval": "P100D"}, "renewal_interval"),
        ({"windows": []}, "windows"),
        (
            {
                "windows": [
                    {"weekdays": ["sat"], "start": "05:00", "end": "01:00", "timezone": "UTC"}
                ]
            },
            "ends later",
        ),
        (
            {
                "windows": [
                    {"weekdays": ["sat"], "start": "01:00", "end": "05:00", "timezone": "Mars/Base"}
                ]
            },
            "time zone",
        ),
        (
            {
                "windows": [
                    {
                        "weekdays": ["sat", "sat"],
                        "start": "01:00",
                        "end": "05:00",
                        "timezone": "UTC",
                    }
                ]
            },
            "repeat",
        ),
        (
            {
                "windows": [
                    {"weekdays": ["someday"], "start": "01:00", "end": "05:00", "timezone": "UTC"}
                ]
            },
            "weekdays",
        ),
        ({"max_age": "P1Y"}, "duration"),
        (
            {"approvals": {"plan": True, "cutover": True, "retirement": False}},
            "retirement",
        ),  # always required
        ({"surprise": 1}, "surprise"),
    ],
)
def test_bad_policies_are_refused(patch: dict[str, object], needle: str) -> None:
    body = {**GOOD, **patch}
    with pytest.raises(ValidationError, match=needle):
        PolicyIn.model_validate({k: v for k, v in body.items() if v is not None})
