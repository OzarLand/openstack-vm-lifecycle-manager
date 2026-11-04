"""Fence gate: local self-fencing of a step attempt (ADR-0003, SRE-R-2, SEC-R-26).

Safety argument
---------------
The DB lease of a running step ends at ``lease_expires_at = now_db(claim or heartbeat) + lease_duration``. The
worker keeps a local deadline ``t_send + lease_duration - fence_margin`` where ``t_send`` is read from the local
monotonic clock *before* the claim/heartbeat request is sent. Because the request reaches the DB after ``t_send``,
``now_db`` is later than the DB-clock instant corresponding to ``t_send``; so the local deadline always falls at
least ``fence_margin`` before the DB expiry, whatever the network delay, and regardless of wall-clock skew (the two
clocks are never compared).

Every mutating OpenStack call (WriteClient session hook), every subprocess spawn (automation) and every fenced
commit calls :meth:`Fence.check` first. Past the deadline, after a 0-row heartbeat, or while ownership is unknown
after a DB error, the check raises :class:`FenceLost`. A paused process (SIGSTOP, VM freeze) fails its first check
on resume because the monotonic clock kept running.

What it cannot do: a request *sent* before the deadline may still land after another worker took over. That is the
documented limit of fencing; the takeover delay and the probe-first step contract cover it.

Revocation callbacks let long-running actions (an Ansible process group) be stopped at once on revoke or deadline,
rather than at the next check. The heartbeat thread fires them when it observes the deadline has passed.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from ovlm.workflow.clock import Clock
from ovlm.workflow.metrics import FENCE_REFUSALS

log = logging.getLogger("ovlm.workflow.fence")


class OwnershipLost(BaseException):  # noqa: N818
    """Base of the ownership exceptions.

    A ``BaseException`` on purpose: step code that catches ``Exception`` broadly must not be able to swallow the
    loss of ownership and carry on mutating. Only the engine catches it.
    """


class FenceLost(OwnershipLost):
    def __init__(self, action: str, reason: str) -> None:
        super().__init__(f"fence refused {action}: {reason}")
        self.action = action
        self.reason = reason


class FencedCommitRejected(OwnershipLost):
    """A fenced write matched 0 rows: another attempt owns the step (or it left ``running``)."""


class Fence:
    def __init__(
        self,
        *,
        clock: Clock,
        lease_duration: float,
        fence_margin: float,
        t_send: float,
        verify_ownership: Callable[[], bool] | None = None,
    ) -> None:
        self._clock = clock
        self._lease = lease_duration
        self._margin = fence_margin
        self._deadline = t_send + lease_duration - fence_margin
        self._lock = threading.RLock()
        self._revoked: str | None = None
        self._unknown = False
        self._verify = verify_ownership
        self._callbacks: list[Callable[[str], None]] = []
        self._fired = False
        #: Set when the fence stops being valid (revoked or deadline seen passed); ``ctx.sleep`` waits on it.
        self.stopped = threading.Event()
        #: Mirrors ``workflow_run.abort_requested`` as last read by a heartbeat.
        self.abort_requested = False

    # ---- state changes (heartbeat thread) ---------------------------------------------------------------

    def extend(self, t_send: float) -> None:
        """A heartbeat sent at ``t_send`` matched 1 row: ownership confirmed, deadline moves forward."""
        with self._lock:
            if self._revoked is not None:
                return
            self._unknown = False
            self._deadline = max(self._deadline, t_send + self._lease - self._margin)

    def mark_unknown(self) -> None:
        """A DB error: ownership is unknown until a guarded heartbeat returns 1 row (ADR-0003)."""
        with self._lock:
            self._unknown = True

    def revoke(self, reason: str) -> None:
        with self._lock:
            if self._revoked is None:
                self._revoked = reason
        self._fire(reason)

    def poll_deadline(self) -> None:
        """Called periodically by the heartbeat thread: fire revoke callbacks once the deadline is past."""
        if self.remaining() <= 0:
            self._fire("local fence deadline passed")

    def _fire(self, reason: str) -> None:
        with self._lock:
            if self._fired:
                return
            self._fired = True
            # Once stopped, the attempt is dead for good: a late 1-row heartbeat must not revive it after its
            # revoke callbacks (e.g. the Ansible kill) already ran.
            if self._revoked is None:
                self._revoked = reason
            callbacks = list(self._callbacks)
        self.stopped.set()
        for cb in callbacks:
            try:
                cb(reason)
            except Exception:
                log.exception("fence revoke callback failed")

    # ---- queries / gate (step thread) -------------------------------------------------------------------

    def add_revoke_callback(self, cb: Callable[[str], None]) -> Callable[[], None]:
        """Register ``cb(reason)``; returns a function that unregisters it. Fires at once if already stopped."""
        with self._lock:
            fired = self._fired
            if not fired:
                self._callbacks.append(cb)
        if fired:
            cb(self._revoked or "local fence deadline passed")

        def remove() -> None:
            with self._lock:
                if cb in self._callbacks:
                    self._callbacks.remove(cb)

        return remove

    def remaining(self) -> float:
        with self._lock:
            return self._deadline - self._clock.monotonic()

    @property
    def revoked(self) -> str | None:
        return self._revoked

    def check(self, action: str) -> None:
        """Gate: raise :class:`FenceLost` unless this attempt still provably owns the step."""
        with self._lock:
            revoked, unknown = self._revoked, self._unknown
        if revoked is not None:
            self._refuse(action, "revoked", revoked)
        # Unknown ownership: re-confirm synchronously with a guarded heartbeat instead of failing on a blip.
        if unknown and (self._verify is None or not self._verify()):
            self._refuse(action, "ownership_unknown", "ownership unknown after a DB error")
        if self.remaining() <= 0:
            self._fire("local fence deadline passed")
            self._refuse(action, "deadline", "local fence deadline passed")

    def ensure_alive(self, action: str) -> None:
        """Weaker check for non-mutating waits: only revocation and the deadline stop them. Unknown ownership
        after a DB error blocks *new* mutating actions (:meth:`check`) but does not interrupt an ongoing
        bounded wait or subprocess before the deadline (ADR-0003 "DB outage")."""
        with self._lock:
            revoked = self._revoked
        if revoked is not None:
            self._refuse(action, "revoked", revoked)
        if self.remaining() <= 0:
            self._fire("local fence deadline passed")
            self._refuse(action, "deadline", "local fence deadline passed")

    def _refuse(self, action: str, label: str, reason: str) -> None:
        FENCE_REFUSALS.labels(action.split(":", 1)[0], label).inc()
        log.warning("fence gate refused an action", extra={"action": action, "reason": reason})
        raise FenceLost(action, reason)
