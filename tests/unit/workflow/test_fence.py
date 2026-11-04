"""Fence gate (ADR-0003, SRE-R-2): deadline from the send time, 0-row revoke, unknown ownership, callbacks."""

from __future__ import annotations

import threading

import pytest

from ovlm.workflow.clock import FakeClock, SystemClock
from ovlm.workflow.fence import Fence, FencedCommitRejected, FenceLost, OwnershipLost


def make(clock: FakeClock, verify: bool | None = None) -> Fence:
    return Fence(
        clock=clock,
        lease_duration=60,
        fence_margin=10,
        t_send=clock.monotonic(),
        verify_ownership=(lambda: bool(verify)) if verify is not None else None,
    )


def test_deadline_is_send_time_plus_lease_minus_margin() -> None:
    clock = FakeClock()
    f = make(clock)
    assert f.remaining() == 50
    clock.advance(49.9)
    f.check("openstack:POST /servers")
    clock.advance(0.1)
    with pytest.raises(FenceLost) as exc:
        f.check("openstack:POST /servers")
    assert exc.value.reason == "local fence deadline passed"


def test_heartbeat_extends_from_its_own_send_time_never_backwards() -> None:
    clock = FakeClock()
    f = make(clock)
    clock.advance(30)
    f.extend(clock.monotonic() - 5)  # heartbeat sent 5 s ago, answered now
    assert f.remaining() == pytest.approx(45)
    f.extend(clock.monotonic() - 40)  # an older send time never shortens... nor lengthens
    assert f.remaining() == pytest.approx(45)


def test_zero_row_heartbeat_revokes_at_once_and_fires_callbacks() -> None:
    f = make(FakeClock())
    seen: list[str] = []
    f.add_revoke_callback(seen.append)
    f.revoke("heartbeat matched 0 rows")
    assert seen == ["heartbeat matched 0 rows"]
    assert f.stopped.is_set()
    with pytest.raises(FenceLost):
        f.check("spawn:ansible")
    f.extend(f._clock.monotonic())  # noqa: SLF001 - a late heartbeat cannot revive a revoked attempt
    with pytest.raises(FenceLost):
        f.check("commit")


def test_deadline_passing_is_permanent_and_fires_callbacks_once() -> None:
    clock = FakeClock()
    f = make(clock)
    seen: list[str] = []
    f.add_revoke_callback(seen.append)
    clock.advance(51)
    f.poll_deadline()
    f.poll_deadline()
    assert seen == ["local fence deadline passed"]
    f.extend(clock.monotonic())  # a successful but late heartbeat must not revive it
    with pytest.raises(FenceLost):
        f.check("commit")


def test_callback_registered_after_stop_fires_immediately_and_can_be_removed() -> None:
    f = make(FakeClock())
    seen: list[str] = []
    remove = f.add_revoke_callback(seen.append)
    remove()
    f.revoke("x")
    assert seen == []
    f.add_revoke_callback(seen.append)
    assert seen == ["x"]


def test_unknown_ownership_needs_a_guarded_heartbeat_before_mutating() -> None:
    clock = FakeClock()
    refused = make(clock, verify=False)
    refused.mark_unknown()
    with pytest.raises(FenceLost) as exc:
        refused.check("openstack:DELETE")
    assert "unknown" in exc.value.reason
    refused.ensure_alive("sleep")  # a bounded wait is not interrupted by unknown ownership alone

    confirmed = make(clock, verify=True)
    confirmed.mark_unknown()
    confirmed.check("openstack:DELETE")  # the synchronous heartbeat confirmed ownership


def test_ownership_exceptions_cannot_be_swallowed_by_except_exception() -> None:
    assert not issubclass(FenceLost, Exception)
    assert not issubclass(FencedCommitRejected, Exception)
    assert issubclass(FenceLost, OwnershipLost) and issubclass(FencedCommitRejected, OwnershipLost)

    def step_code(f: Fence) -> None:
        try:
            f.check("act")
        except Exception:  # noqa: BLE001 - what careless step code would do
            pytest.fail("ownership loss swallowed")

    f = make(FakeClock())
    f.revoke("lost")
    with pytest.raises(FenceLost):
        step_code(f)


def test_system_clock_is_monotonic_and_sleep_is_interruptible() -> None:
    c = SystemClock()
    a = c.monotonic()
    ev = threading.Event()
    ev.set()
    assert c.sleep(10, ev) is True
    assert c.monotonic() >= a


def test_fake_clock_modes() -> None:
    c = FakeClock()
    c.sleep(5)
    assert c.monotonic() == 1005 and c.sleeps == [5]
    still = FakeClock(sleep_advances=False)
    ev = threading.Event()
    ev.set()
    assert still.sleep(5, ev) is True and still.monotonic() == 1000
