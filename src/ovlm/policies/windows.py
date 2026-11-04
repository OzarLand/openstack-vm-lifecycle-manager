"""Allowed renewal windows: weekday + time range + IANA time zone (data-model.md section 6).

A window does not cross midnight (``end`` is later than ``start`` on the same local day); a night window is written
as two windows. Times are local wall-clock times of the window's zone, so a window follows daylight saving time.
A local time that does not exist (spring forward) is read with the offset in force before the change; one that
occurs twice (fall back) is the first occurrence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

Weekday = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
WEEKDAYS: tuple[str, ...] = (
    "mon",
    "tue",
    "wed",
    "thu",
    "fri",
    "sat",
    "sun",
)  # index = date.weekday()
_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


def parse_hhmm(value: str) -> time:
    m = _HHMM.match(value)
    if not m:
        raise ValueError("expected a 24-hour time HH:MM")
    return time(int(m.group(1)), int(m.group(2)))


def load_zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ValueError(f"unknown IANA time zone {name!r}") from None


@dataclass(frozen=True)
class WindowRule:
    weekdays: frozenset[int]  # date.weekday() values
    start: time
    end: time
    zone: ZoneInfo

    @property
    def length_seconds(self) -> int:
        return (
            self.end.hour * 60 + self.end.minute - self.start.hour * 60 - self.start.minute
        ) * 60


def rule_from_dict(raw: dict[str, object]) -> WindowRule:
    days = raw["weekdays"]
    if not isinstance(days, list):
        raise ValueError("weekdays must be a list")
    return WindowRule(
        frozenset(WEEKDAYS.index(str(d)) for d in days),
        parse_hhmm(str(raw["start"])),
        parse_hhmm(str(raw["end"])),
        load_zone(str(raw["timezone"])),
    )


def _at(day: date, clock: time, zone: ZoneInfo) -> datetime:
    return datetime.combine(day, clock, tzinfo=zone).astimezone(UTC)


def next_window(anchor: datetime, rules: list[WindowRule]) -> tuple[datetime, datetime] | None:
    """The first moment at or after ``anchor`` at which a window is open, and when that window closes (both UTC).

    ``anchor`` itself when it lies inside a window. ``None`` only when there are no usable windows.
    """
    anchor = anchor.astimezone(UTC)
    best: tuple[datetime, datetime] | None = None
    for rule in rules:
        first = anchor.astimezone(rule.zone).date() - timedelta(days=1)
        for offset in range(
            9
        ):  # a weekly pattern repeats within 7 days; one extra day each side covers zone shifts
            day = first + timedelta(days=offset)
            if day.weekday() not in rule.weekdays:
                continue
            start, end = _at(day, rule.start, rule.zone), _at(day, rule.end, rule.zone)
            if end <= anchor:
                continue
            candidate = (max(start, anchor), end)
            if best is None or candidate[0] < best[0]:
                best = candidate
    return best
