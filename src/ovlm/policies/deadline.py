"""Renewal deadline of a managed VM (FR-POL-5): launch time + maximum age, adjusted to the next allowed window.

* No policy: no deadline, never due (FR-POL-4).
* Launch time is the server's ``launched_at``, falling back to ``created`` (openstack-integration.md); the caller
  passes whichever it has.
* ``deadline`` is launch + ``max_age``. ``next_window_start`` is the first moment at or after the deadline at which a
  window is open (the deadline itself when it falls inside one). Both are UTC.
* An approved, started and not yet expired exception waives the policy: the VM is not due and ``waived_until`` says
  when the waiver ends. After that the policy applies again, with the original deadline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ovlm.policies.windows import WindowRule, next_window


@dataclass(frozen=True)
class ExceptionRef:
    id: str
    starts_at: datetime
    expires_at: datetime
    approved: bool


@dataclass(frozen=True)
class Deadline:
    status: str  # no_policy | scheduled | due | waived
    deadline: datetime | None
    next_window_start: datetime | None
    next_window_end: datetime | None
    due: bool
    waived_until: datetime | None = None
    exception_id: str | None = None


def active_exception(exceptions: list[ExceptionRef], now: datetime) -> ExceptionRef | None:
    """Approved and inside ``[starts_at, expires_at)``; an expired one is ignored (FR-POL-3). Latest expiry wins."""
    live = [e for e in exceptions if e.approved and e.starts_at <= now < e.expires_at]
    return max(live, key=lambda e: e.expires_at) if live else None


def compute_deadline(
    *,
    launched_at: datetime | None,
    max_age_seconds: int | None,
    windows: list[WindowRule],
    now: datetime,
    exceptions: list[ExceptionRef] | None = None,
) -> Deadline:
    """``max_age_seconds`` is ``None`` when the service has no policy."""
    if max_age_seconds is None or launched_at is None:
        return Deadline(
            "no_policy" if max_age_seconds is None else "no_launch_time", None, None, None, False
        )
    deadline = launched_at.astimezone(UTC) + timedelta(seconds=max_age_seconds)
    window = next_window(deadline, windows)
    start, end = window if window else (None, None)
    waiver = active_exception(exceptions or [], now)
    if waiver is not None:
        return Deadline("waived", deadline, start, end, False, waiver.expires_at, waiver.id)
    due = now >= deadline
    return Deadline("due" if due else "scheduled", deadline, start, end, due)
