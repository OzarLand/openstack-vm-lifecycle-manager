"""Local clocks used by the fence gate.

Safety argument (ADR-0003 "Fence gate"): the fence deadline is computed and checked on a *local monotonic* clock and
is never compared with a DB timestamp, so wall-clock skew between worker and database cannot extend a lease. All
lease and timer arithmetic that is persisted uses the database's ``now()`` (WF-20).

``SystemClock`` uses ``CLOCK_BOOTTIME`` on Linux: like ``CLOCK_MONOTONIC`` it never goes backwards and ignores wall
clock changes, but it also keeps counting while the host or VM is suspended. ``CLOCK_MONOTONIC`` stops during a
suspend, so a worker on a suspended-then-resumed VM would believe its fence deadline is still in the future while
the DB lease has long expired. This is a stricter reading of "monotonic" in ADR-0003 (reported in the summary).
"""

from __future__ import annotations

import threading
import time
from typing import Protocol

_CLOCK_ID = getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC)


class Clock(Protocol):
    def monotonic(self) -> float:
        """Seconds on a clock that never goes backwards and counts suspended time."""

    def sleep(self, seconds: float, interrupt: threading.Event | None = None) -> bool:
        """Sleep; return True if ``interrupt`` was set before the time elapsed."""


class SystemClock:
    def monotonic(self) -> float:
        return time.clock_gettime(_CLOCK_ID)

    def sleep(self, seconds: float, interrupt: threading.Event | None = None) -> bool:
        if seconds <= 0:
            return bool(interrupt and interrupt.is_set())
        if interrupt is None:
            threading.Event().wait(seconds)
            return False
        return interrupt.wait(seconds)


class FakeClock:
    """Deterministic clock for tests: time moves only through ``advance`` and ``sleep``."""

    def __init__(self, start: float = 1000.0) -> None:
        self._now = start
        self._lock = threading.Lock()
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        with self._lock:
            return self._now

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._now += seconds

    def sleep(self, seconds: float, interrupt: threading.Event | None = None) -> bool:
        self.sleeps.append(seconds)
        if interrupt is not None and interrupt.is_set():
            return True
        self.advance(max(seconds, 0.0))
        return bool(interrupt and interrupt.is_set())
