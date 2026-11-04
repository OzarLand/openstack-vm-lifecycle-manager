"""ISO 8601 durations restricted to days, hours, minutes (``P90D``, ``PT6H``, ``P1DT12H30M``), stored as seconds.

Years, months and weeks are refused: their length depends on the calendar, and a maximum age must mean one thing.
"""

from __future__ import annotations

import re

_ISO = re.compile(r"^P(?:(\d{1,5})D)?(?:T(?:(\d{1,5})H)?(?:(\d{1,5})M)?)?$")


def parse_duration(text: str) -> int:
    """Seconds, or ``ValueError`` (a zero or empty duration is an error)."""
    m = _ISO.match(text.strip().upper()) if isinstance(text, str) else None
    if not m or not any(m.groups()) or text.strip().upper().endswith("T"):
        raise ValueError(
            "expected an ISO 8601 duration of days, hours and minutes, such as P90D, PT6H or P1DT12H"
        )
    days, hours, minutes = (int(g or 0) for g in m.groups())
    seconds = days * 86400 + hours * 3600 + minutes * 60
    if seconds <= 0:
        raise ValueError("the duration must be longer than zero")
    return seconds


def format_duration(seconds: int) -> str:
    """Canonical form: ``P90D``, ``PT6H``, ``P1DT12H30M``."""
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    out = "P" + (f"{days}D" if days else "")
    if hours or minutes:
        out += "T" + (f"{hours}H" if hours else "") + (f"{minutes}M" if minutes else "")
    return out if out != "P" else "PT0M"
