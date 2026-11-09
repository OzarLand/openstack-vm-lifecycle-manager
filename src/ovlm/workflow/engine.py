"""Durable step executor on PostgreSQL (ADR-0003).

Safety arguments (for the SRE review)
-------------------------------------
**S1 - one owner per step attempt.** A step is claimed in one short transaction with ``FOR UPDATE SKIP LOCKED``;
the claim sets ``state='running'``, ``lease_owner`` (this process's UUID), ``lease_expires_at = now() + lease``
(DB clock) and a fresh ``fencing_token`` from ``fencing_seq``. Two workers can never claim the same row at once:
the row lock serialises them and the second one skips it; after the first commits the row is ``running`` with a
live lease and no longer matches the claim predicate. The partial unique index allows one ``running`` step per
run (and one *open* step per run).

**S2 - a stale attempt can never commit.** Every write of an attempt (intent, evidence, outcome, transition) is
guarded by ``id = :id AND fencing_token = :tok AND lease_owner = :owner AND state = 'running'`` and fails with
:class:`FencedCommitRejected` on 0 rows. A takeover changes the token *and* the owner, so the guard fails for the
old attempt even if a DB failover re-issued a sequence value (SRE-R-4). The outcome commit locks the run row
first, then the guarded step row (same order as signal transactions: no deadlock between them).

**S3 - a stale attempt stops acting.** The local fence (:mod:`ovlm.workflow.fence`) refuses any mutating call,
subprocess spawn or commit after ``t_send + lease - fence_margin`` on a monotonic clock, immediately after a
0-row heartbeat, and while ownership is unknown after a DB error. Ownership loss is a ``BaseException`` so step
code cannot swallow it.

**S4 - in-flight requests from a stale attempt.** A takeover of a destructive step, or of any step while the run
is in phase ``window`` or ``restore``, first waits ``worker.takeover_delay`` (heartbeating), then probes, then acts
(SRE-R-27). Every attempt starts with ``probe``.

**S5 - crash anywhere is recoverable.** Nothing is committed in ``finally`` blocks or exception handlers that
could run after a crash; a crash leaves the step ``running`` with a lease that expires, after which another claim
(attempt + 1, new token) re-probes. An attempt that leaves ``execute`` (returned or raised) has closed its fence
and joined its heartbeat first, so no extension of its lease lands afterwards. Admission, transitions, lock
acquisition/release, signal consumption and their audit events each commit in a single transaction.

**S6 - signals.** ``run_signal.consumed_at``/``outcome`` are written in the same transaction as the effect
(SRE-R-24). Signals needing a step boundary are left pending while a step runs and applied afterwards.

**S7 - time.** Leases, ``not_before`` and ``deadline_at`` are computed with the DB's ``now()`` only; the worker
never sends a timestamp (WF-20).

**S8 - deadlines (SRE-C-3).** The claim returns whether ``deadline_at`` has passed (DB clock) and how long is left;
the local view of the remaining time is ``t_send + remaining`` on the monotonic clock, which is never later than the
real deadline (``t_send`` precedes the DB's ``now()``). An attempt past its deadline still probes (``Done`` stays
allowed) but never acts: ``Act`` becomes ``needs_human(deadline_exceeded)``.

**S9 - needs_human always has a target (SRE-C-1).** A run in ``needs_human`` has exactly one open step, itself in
``needs_human``. A transition that hits a lock conflict (outcome commit *or* signal) is rolled back to a savepoint
and the step is kept open in ``needs_human``; ``mark_resolved`` re-queues the step so the engine re-probes before
continuing (SRE-C-2).
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, Engine, RowMapping, text
from sqlalchemy.exc import SQLAlchemyError

from ovlm.config import Settings
from ovlm.workflow import metrics as m
from ovlm.workflow.audit import AuditEvent, AuditSink, LogAuditSink
from ovlm.workflow.clock import Clock, SystemClock
from ovlm.workflow.contract import (
    OPEN_STEP_STATES,
    TERMINAL_RUN_STATES,
    AcceptStep,
    Defer,
    Done,
    ErrorClass,
    Fail,
    LockSpec,
    Outcome,
    Reject,
    RunView,
    SignalView,
    Step,
    StepSpec,
    StepView,
    Transition,
    TxContext,
    Wait,
    Wake,
    WorkflowDefinition,
)
from ovlm.workflow.crashpoint import crashpoint
from ovlm.workflow.fence import Fence, FencedCommitRejected, FenceLost
from ovlm.workflow.ids import new_id
from ovlm.workflow.registry import Registry
from ovlm.workflow.requests import request_run
from ovlm.workflow.workers import LIVE_WORKER_BEATS, count_live_workers

log = logging.getLogger("ovlm.workflow.engine")

#: pg advisory lock keys ("ovlm" + n).
ADMISSION_LOCK_KEY = 0x6F766C6D0001
SCHEDULER_LOCK_KEY = 0x6F766C6D0002

#: Phases in which any takeover waits before probing (ADR-0003, SRE-R-27).
TAKEOVER_DELAY_PHASES = frozenset({"window", "restore"})

_STEP_COLS = (
    "s.id, s.run_id, s.seq, s.step_key, s.state, s.attempt, s.fencing_token, s.lease_owner, s.params, "
    "s.intent, s.evidence, s.destructive, s.timeout_seconds, s.retry_floor"
)
_RUN_COLS = (
    "r.id, r.kind, r.strategy, r.strategy_version, r.state, r.phase, r.subject, r.service_id, "
    "r.renewal_plan_id, r.abort_requested, r.needs_human_reason, r.started_by"
)


@dataclass(frozen=True)
class EngineConfig:
    lease_duration: float = 60.0
    heartbeat_interval: float = 5.0
    fence_margin: float = 10.0
    takeover_delay: float = 45.0
    poll_initial: float = 5.0
    poll_max: float = 300.0
    retry_max_attempts: int = 3
    retry_per_step: Mapping[str, int] | None = None
    retry_backoff_initial: float = 10.0
    retry_backoff_max: float = 300.0
    admission_alert_after: float = 300.0
    signal_alert_after: float = 300.0
    #: Upper bound (real seconds) between two watchdog checks of a step's fence; near the deadline the watchdog
    #: polls at ``remaining / 2`` with a 50 ms floor (SRE-C-9). Tests with a fake clock set it low.
    watchdog_interval: float = 1.0

    @classmethod
    def from_settings(cls, s: Settings) -> EngineConfig:
        return cls(
            lease_duration=s.worker.lease_duration,
            heartbeat_interval=s.worker.heartbeat_interval,
            fence_margin=s.worker.fence_margin,
            takeover_delay=s.worker.takeover_delay,
            poll_initial=s.poll.initial_interval,
            poll_max=s.poll.max_interval,
            retry_max_attempts=s.retry.max_attempts,
            retry_per_step=dict(s.retry.max_attempts_per_step),
            retry_backoff_initial=s.retry.backoff_initial,
            retry_backoff_max=s.retry.backoff_max,
            admission_alert_after=s.admission.after,
            signal_alert_after=s.signal.after,
        )

    def max_attempts(self, step_key: str) -> int:
        return (self.retry_per_step or {}).get(step_key, self.retry_max_attempts)


@dataclass(frozen=True)
class Claim:
    run: RunView
    step: StepView
    fencing_token: int
    lease_owner: str
    t_send: float
    takeover: bool
    timeout_seconds: float | None
    retry_floor: int
    #: ``deadline_at <= now()`` at claim time (DB clock), SRE-C-3.
    late: bool = False
    #: Seconds from the claim's DB ``now()`` to ``deadline_at``; None without a deadline.
    deadline_in: float | None = None


class LockConflict(Exception):
    def __init__(self, lock: LockSpec, holder: str) -> None:
        super().__init__(f"{lock.resource_type}/{lock.resource_key} is held by run {holder}")
        self.lock = lock
        self.holder = holder


class _LeavePending(Exception):
    """Roll back a signal transaction and leave the signal unconsumed (applied on a later pass)."""


def _j(value: Mapping[str, Any] | None) -> str | None:
    return None if value is None else json.dumps(dict(value), default=str, sort_keys=True)


def _run_view(r: RowMapping) -> RunView:
    return RunView(
        id=str(r["id"]),
        kind=r["kind"],
        strategy=r["strategy"],
        strategy_version=r["strategy_version"],
        state=r["state"],
        phase=r["phase"],
        subject=r["subject"] or {},
        service_id=str(r["service_id"]) if r["service_id"] else None,
        renewal_plan_id=str(r["renewal_plan_id"]) if r["renewal_plan_id"] else None,
        abort_requested=bool(r["abort_requested"]),
        needs_human_reason=r["needs_human_reason"],
        started_by=str(r["started_by"]) if r["started_by"] else None,
    )


def _step_view(r: RowMapping) -> StepView:
    return StepView(
        id=str(r["id"]),
        run_id=str(r["run_id"]),
        seq=r["seq"],
        step_key=r["step_key"],
        state=r["state"],
        attempt=r["attempt"],
        params=r["params"] or {},
        intent=r["intent"],
        evidence=r["evidence"],
        destructive=bool(r["destructive"]),
    )


# ---- per-attempt context ----------------------------------------------------------------------------------


class _StepContext:
    """Implements :class:`ovlm.workflow.contract.StepContext` for one attempt."""

    def __init__(
        self, engine: WorkflowEngine, claim: Claim, fence: Fence, stopping: threading.Event
    ) -> None:
        self._engine = engine
        self._claim = claim
        self.run = claim.run
        self.step = claim.step
        self.attempt = claim.step.attempt
        self.takeover = claim.takeover
        self.fence = fence
        self._stopping = stopping
        #: Set when this attempt persisted an intent (decided to act): resets the poll backoff (SRE-C-5).
        self.acted = False

    @property
    def deadline_passed(self) -> bool:
        """True when ``deadline_at`` had passed at claim time (DB clock), or has passed since on the local
        monotonic clock (conservative: the local view of the deadline is never later than the DB's)."""
        c = self._claim
        if c.late:
            return True
        return (
            c.deadline_in is not None and self._engine.clock.monotonic() >= c.t_send + c.deadline_in
        )

    @property
    def params(self) -> Mapping[str, Any]:
        return self.step.params

    @property
    def previous_intent(self) -> Mapping[str, Any] | None:
        return self.step.intent

    @property
    def previous_evidence(self) -> Mapping[str, Any] | None:
        return self.step.evidence

    @property
    def abort_requested(self) -> bool:
        return self.run.abort_requested or self.fence.abort_requested

    @property
    def stopping(self) -> bool:
        return self._stopping.is_set()

    def gate(self, action: str) -> None:
        self.fence.check(action)

    def crashpoint(self, phase: str) -> None:
        crashpoint(f"{self.step.step_key}.{phase}")

    def sleep(self, seconds: float) -> None:
        self._engine.clock.sleep(seconds, self.fence.stopped)
        self.fence.ensure_alive("sleep")

    @contextmanager
    def read(self) -> Iterator[Connection]:
        """A pooled connection for short reads. Never hold it across network I/O: the pool is sized for the
        worker's slots and heartbeats wait on it at most ``pool_timeout`` (SRE-C-4)."""
        with self._engine.db.connect() as conn:
            yield conn

    def persist_intent(self, intent: Mapping[str, Any]) -> None:
        self.checkpoint(intent=intent)
        self.acted = True

    def checkpoint(
        self, *, intent: Mapping[str, Any] | None = None, evidence: Mapping[str, Any] | None = None
    ) -> None:
        self.fence.check("commit:checkpoint")
        c = self._claim
        with self._engine.db.begin() as conn:
            n = conn.execute(
                text(
                    "UPDATE workflow_step SET "
                    "intent = COALESCE(CAST(:intent AS jsonb), intent), "
                    "evidence = CASE WHEN CAST(:ev AS jsonb) IS NULL THEN evidence "
                    "  ELSE COALESCE(evidence, '{}'::jsonb) || CAST(:ev AS jsonb) END, "
                    "updated_at = now() "
                    "WHERE id = :id AND fencing_token = :tok AND lease_owner = :owner AND state = 'running'"
                ),
                {
                    "intent": _j(intent),
                    "ev": _j(evidence),
                    "id": c.step.id,
                    "tok": c.fencing_token,
                    "owner": c.lease_owner,
                },
            ).rowcount
            if n != 1:
                m.FENCED_COMMIT_REJECTED.inc()
                raise FencedCommitRejected(f"checkpoint of step {c.step.id} matched {n} rows")


# ---- heartbeat and watchdog threads -----------------------------------------------------------------------


class _LateBeat(Exception):  # noqa: N818 - control flow only, never escapes ``WorkflowEngine.heartbeat``
    """Rolls back a lease extension whose attempt ended while the UPDATE was in flight."""


class _Heartbeater:
    """Extends the lease every ``heartbeat_interval``; a 0-row result revokes the fence at once.

    A separate watchdog thread fires the fence's revoke callbacks (e.g. kill an Ansible process group) as soon
    as the local deadline passes, even when the heartbeat thread is blocked on a hung DB connection.
    """

    def __init__(self, engine: WorkflowEngine, claim: Claim, fence: Fence) -> None:
        self._engine = engine
        self._claim = claim
        self._fence = fence
        self._stop = threading.Event()
        name = f"ovlm-hb-{claim.step.step_key}"
        self._hb = threading.Thread(target=self._beat_loop, name=name, daemon=True)
        self._wd = threading.Thread(target=self._watch_loop, name=name + "-wd", daemon=True)

    def start(self) -> None:
        self._hb.start()
        self._wd.start()

    def stop(self) -> None:
        """Stop and fence the heartbeat before the attempt leaves ``execute``, however it leaves it.

        Setting the stop event alone is not enough: a beat already past its interval wait would still go out and
        extend the lease of an attempt that has ended (returned ``commit_unknown``, or raised: a bug outside the
        step contract that the worker loop logs, an interrupt, a simulated crash), delaying the takeover by up to
        one lease. So the fence is closed first (a beat not yet sent is refused by
        :meth:`WorkflowEngine.heartbeat`), then both threads are joined: a beat in flight lands before the attempt
        is gone, never after. The join is bounded by the worst case of one beat (pool checkout,
        ``statement_timeout``). No DB write here: this runs in ``finally`` (S5).
        """
        self._fence.close("attempt ended")
        self._stop.set()
        cfg = self._engine.config
        bound = cfg.fence_margin + max(cfg.heartbeat_interval, 1.0)
        for t in (self._hb, self._wd):
            if t.is_alive() and t is not threading.current_thread():
                t.join(bound)
                if t.is_alive():
                    log.warning(
                        "heartbeat thread still running after the attempt ended",
                        extra={"step_id": self._claim.step.id, "thread": t.name},
                    )

    def _beat_loop(self) -> None:
        interval = self._engine.config.heartbeat_interval
        while not self._stop.wait(interval):
            if self._fence.revoked is not None:
                return
            try:
                crashpoint("lease.heartbeat")
            except BaseException:  # in-process crash of the heartbeat thread = heartbeat stops
                log.warning("heartbeat thread crashed (simulated)")
                return
            if self._engine.heartbeat(self._claim, self._fence) is False:
                return

    def _watch_loop(self) -> None:
        cap = self._engine.config.watchdog_interval
        while not self._stop.is_set():
            self._fence.poll_deadline()
            if self._fence.stopped.is_set():
                return
            # Real time on purpose. Far from the deadline: every ``watchdog_interval``; close to it: half the
            # remaining time, with a 50 ms floor (SRE-C-9: no 20 Hz polling per running step).
            self._stop.wait(min(cap, max(self._fence.remaining() / 2, 0.05)))


# ---- engine -----------------------------------------------------------------------------------------------


class WorkflowEngine:
    def __init__(
        self,
        db: Engine,
        registry: Registry,
        config: EngineConfig,
        *,
        worker_id: str | None = None,
        clock: Clock | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        self.db = db
        self.registry = registry
        self.config = config
        #: ``lease_owner``: new UUID per process start (SRE-R-4); never reused.
        self.worker_id = worker_id or new_id()
        self.clock: Clock = clock or SystemClock()
        self.audit: AuditSink = audit or LogAuditSink()
        self.stopping = threading.Event()
        self._version = "unknown"

    # ---- worker registration ---------------------------------------------------------------------------

    def register_worker(self, version: str) -> None:
        self._version = version
        self.beat_worker()

    def beat_worker(self, draining: bool = False) -> None:
        """Upsert: a worker whose row was swept (e.g. paused for long) re-creates it on its next beat."""
        with self.db.begin() as c:
            c.execute(
                text(
                    "INSERT INTO worker_heartbeat (worker_id, hostname, version, draining) "
                    "VALUES (:w, :h, :v, :d) "
                    "ON CONFLICT (worker_id) DO UPDATE SET last_seen_at = now(), draining = :d"
                ),
                {"w": self.worker_id, "h": socket.gethostname(), "v": self._version, "d": draining},
            )

    def sweep_worker_rows(self, older_than: float) -> int:
        """Delete ``worker_heartbeat`` rows not seen for ``older_than`` seconds (DB clock), never our own
        (SRE-C-10). Liveness is read from recent rows only: :func:`ovlm.workflow.workers.count_live_workers`."""
        with self.db.begin() as c:
            return c.execute(
                text(
                    "DELETE FROM worker_heartbeat WHERE worker_id <> :w "
                    "AND last_seen_at < now() - make_interval(secs => :age)"
                ),
                {"w": self.worker_id, "age": older_than},
            ).rowcount

    # ---- claims ----------------------------------------------------------------------------------------

    def claim(self, limit: int = 1) -> list[Claim]:
        """Claim up to ``limit`` claimable steps (S1). Execute each with :meth:`execute` outside any txn."""
        known = self.registry.known()
        if not known or limit <= 0:
            return []
        kinds, strategies, versions = (list(x) for x in zip(*known, strict=True))
        t_send = self.clock.monotonic()  # read *before* the request is sent (fence safety argument)
        with self.db.begin() as c:
            rows = (
                c.execute(
                    text(
                        f"""
                WITH c AS (
                  SELECT s.id, s.state AS prev_state, s.lease_owner AS prev_owner
                  FROM workflow_step s JOIN workflow_run r ON r.id = s.run_id
                  WHERE r.state = 'running'
                    AND (r.kind, r.strategy, r.strategy_version) IN (
                      SELECT * FROM unnest(CAST(:kinds AS text[]), CAST(:strats AS text[]),
                                           CAST(:vers AS text[])))
                    AND ((s.state IN ('ready', 'waiting') AND s.not_before IS NOT NULL
                          AND s.not_before <= now())
                         OR (s.state = 'running' AND s.lease_expires_at < now()))
                  ORDER BY s.not_before NULLS FIRST, s.id
                  LIMIT :n
                  FOR UPDATE OF s SKIP LOCKED
                )
                UPDATE workflow_step s SET
                  state = 'running', lease_owner = :owner,
                  lease_expires_at = now() + make_interval(secs => :lease),
                  heartbeat_at = now(), attempt = s.attempt + 1,
                  fencing_token = nextval('fencing_seq'), updated_at = now()
                FROM c WHERE s.id = c.id
                RETURNING {_STEP_COLS}, c.prev_state, c.prev_owner,
                  (s.deadline_at IS NOT NULL AND s.deadline_at <= now()) AS late,
                  EXTRACT(EPOCH FROM s.deadline_at - now()) AS deadline_in
                """
                    ),
                    {
                        "kinds": kinds,
                        "strats": strategies,
                        "vers": versions,
                        "n": limit,
                        "owner": self.worker_id,
                        "lease": self.config.lease_duration,
                    },
                )
                .mappings()
                .all()
            )
            claims: list[Claim] = []
            for r in rows:
                takeover = r["prev_state"] == "running"
                run = _run_view(
                    c.execute(
                        text(f"SELECT {_RUN_COLS} FROM workflow_run r WHERE r.id = :id"),
                        {"id": r["run_id"]},
                    )
                    .mappings()
                    .one()
                )
                step = _step_view(r)
                if takeover:
                    m.LEASE_TAKEOVERS.inc()
                    c.execute(
                        text(
                            "UPDATE workflow_step_attempt SET ended_at = now(), outcome = 'lost' "
                            "WHERE step_id = :sid AND ended_at IS NULL"
                        ),
                        {"sid": step.id},
                    )
                c.execute(
                    text(
                        "INSERT INTO workflow_step_attempt (id, step_id, attempt, fencing_token, worker_id, "
                        "takeover) VALUES (:id, :sid, :att, :tok, :w, :tk)"
                    ),
                    {
                        "id": new_id(),
                        "sid": step.id,
                        "att": step.attempt,
                        "tok": r["fencing_token"],
                        "w": self.worker_id,
                        "tk": takeover,
                    },
                )
                self.audit.record(
                    c,
                    AuditEvent(
                        action="step.takeover" if takeover else "step.claim",
                        target_type="workflow_step",
                        target_id=step.id,
                        run_id=run.id,
                        step_id=step.id,
                        after={
                            "step_key": step.step_key,
                            "attempt": step.attempt,
                            "fencing_token": r["fencing_token"],
                            "worker_id": self.worker_id,
                            "previous_owner": r["prev_owner"] if takeover else None,
                        },
                    ),
                )
                claims.append(
                    Claim(
                        run=run,
                        step=step,
                        fencing_token=int(r["fencing_token"]),
                        lease_owner=self.worker_id,
                        t_send=t_send,
                        takeover=takeover,
                        timeout_seconds=r["timeout_seconds"],
                        retry_floor=r["retry_floor"],
                        late=bool(r["late"]),
                        deadline_in=(
                            float(r["deadline_in"]) if r["deadline_in"] is not None else None
                        ),
                    )
                )
        return claims

    def heartbeat(self, claim: Claim, fence: Fence) -> bool | None:
        """Guarded lease extension. True: extended; False: 0 rows (fence revoked); None: DB error."""
        t_send = self.clock.monotonic()
        try:
            with self.db.begin() as c:
                timeout_ms = int(max(self.config.heartbeat_interval, 1.0) * 1000)
                c.execute(text(f"SET LOCAL statement_timeout = {timeout_ms}"))
                if fence.revoked is not None:
                    # A heartbeat that was stuck on the connection while the attempt fenced itself (local deadline
                    # passed) must not extend the lease once the DB is back: the attempt has stopped, and a late
                    # extension would only delay the takeover by one lease (lab flake in WF-07).
                    return False
                row = c.execute(
                    text(
                        "UPDATE workflow_step s SET lease_expires_at = now() + make_interval(secs => :lease), "
                        "heartbeat_at = now() "
                        "WHERE s.id = :id AND s.fencing_token = :tok AND s.lease_owner = :owner "
                        "AND s.state = 'running' "
                        "RETURNING (SELECT abort_requested FROM workflow_run WHERE id = s.run_id)"
                    ),
                    {
                        "lease": fence.lease_duration,
                        "id": claim.step.id,
                        "tok": claim.fencing_token,
                        "owner": claim.lease_owner,
                    },
                ).first()
                if row is not None and fence.revoked is not None:
                    # The attempt ended (or fenced itself) while the UPDATE was on its way: roll it back. Normally
                    # ``_Heartbeater.stop`` waits for this beat; this covers a beat that outlived that bounded wait.
                    raise _LateBeat
        except _LateBeat:
            return False
        except SQLAlchemyError:
            log.warning(
                "step heartbeat failed; ownership unknown", extra={"step_id": claim.step.id}
            )
            fence.mark_unknown()
            return None
        if row is None:
            m.HEARTBEAT_LOST.inc()
            log.warning(
                "step heartbeat matched 0 rows; stopping the step", extra={"step_id": claim.step.id}
            )
            fence.revoke("heartbeat matched 0 rows (ownership lost)")
            return False
        fence.abort_requested = bool(row[0])
        fence.extend(t_send)
        return True

    # ---- execution -------------------------------------------------------------------------------------

    def execute(self, claim: Claim) -> str:
        """Run one claimed attempt: probe -> decide -> act -> verify, then the fenced outcome commit.

        Returns a label for logs/tests: the attempt outcome, ``fence_lost``, ``commit_rejected`` or
        ``commit_unknown``.
        """
        key = claim.step.step_key
        defn = self.registry.resolve(claim.run.kind, claim.run.strategy, claim.run.strategy_version)
        step_impl: Step | None = defn.steps.get(key) if defn else None
        fence_ref: list[Fence] = []
        fence = Fence(
            clock=self.clock,
            lease_duration=self.config.lease_duration,
            fence_margin=self.config.fence_margin,
            t_send=claim.t_send,
            verify_ownership=lambda: self.heartbeat(claim, fence_ref[0]) is True,
        )
        fence_ref.append(fence)
        hb = _Heartbeater(self, claim, fence)
        hb.start()
        ctx = _StepContext(self, claim, fence, self.stopping)
        started = time.monotonic()
        try:
            ctx.crashpoint("after_claim")
            outcome: Outcome
            if defn is None or step_impl is None:
                outcome = Fail(
                    ErrorClass.NEEDS_HUMAN,
                    f"no handler for step {key!r} in this release",
                    needs_human_reason="unknown_step",
                )
            else:
                step_lease = step_impl.lease_for(claim.step.params)
                if step_lease is not None and step_lease != fence.lease_duration:
                    # ADR-0003: a step running a bounded subprocess holds a lease covering its hard timeout
                    # + kill grace + margin, so no takeover starts while an orphan could still run. Set by a
                    # guarded heartbeat before anything is probed or spawned.
                    fence.set_lease(step_lease)
                    if self.heartbeat(claim, fence) is not True:
                        # 0 rows: revoked. DB error: ownership unknown, re-confirmed (or refused) by the
                        # check's synchronous heartbeat. Either way nothing is probed or spawned before the
                        # DB holds the step lease (SRE-C-8).
                        fence.check("lease")
                if claim.takeover and (
                    claim.step.destructive or claim.run.phase in TAKEOVER_DELAY_PHASES
                ):
                    # S4: let a stale in-flight request land or time out before we read state.
                    log.info("takeover delay before probe", extra={"step_id": claim.step.id})
                    ctx.sleep(self.config.takeover_delay)
                try:
                    outcome = step_impl.run_contract(ctx, ctx.persist_intent)
                except (
                    Exception
                ) as exc:  # step code only; OwnershipLost / SimulatedCrash pass through
                    log.warning(
                        "step raised; classifying",
                        extra={"step_key": key, "error": type(exc).__name__},
                    )
                    outcome = step_impl.classify(ctx, exc)
            ctx.crashpoint("after_verify_before_commit")
            label = self._commit_outcome(claim, fence, defn, outcome, acted=ctx.acted)
            ctx.crashpoint("after_commit")
            return label
        except FenceLost as exc:
            log.warning(
                "attempt stopped by the fence; result discarded",
                extra={"step_id": claim.step.id, "reason": exc.reason},
            )
            return "fence_lost"
        except FencedCommitRejected:
            log.warning(
                "fenced commit matched 0 rows; result discarded", extra={"step_id": claim.step.id}
            )
            return "commit_rejected"
        except SQLAlchemyError:
            # The commit may or may not have happened. Either way it is safe: if it committed, the step left
            # 'running'; if not, the lease expires and the next attempt re-probes (S5).
            log.exception(
                "outcome commit failed; outcome unknown", extra={"step_id": claim.step.id}
            )
            fence.mark_unknown()
            return "commit_unknown"
        finally:
            hb.stop()
            m.STEP_DURATION.labels(key).observe(time.monotonic() - started)

    # ---- outcome commit --------------------------------------------------------------------------------

    def _commit_outcome(
        self,
        claim: Claim,
        fence: Fence,
        defn: WorkflowDefinition | None,
        outcome: Outcome,
        *,
        acted: bool = False,
    ) -> str:
        fence.check("commit:outcome")
        with self.db.begin() as c:
            run_row = (
                c.execute(
                    text(f"SELECT {_RUN_COLS} FROM workflow_run r WHERE r.id = :id FOR UPDATE"),
                    {"id": claim.run.id},
                )
                .mappings()
                .one()
            )
            guard = {"id": claim.step.id, "tok": claim.fencing_token, "owner": claim.lease_owner}
            row = (
                c.execute(
                    text(
                        f"SELECT {_STEP_COLS}, (s.deadline_at IS NOT NULL AND s.deadline_at <= now()) AS late, "
                        "EXTRACT(EPOCH FROM s.deadline_at - now()) AS deadline_in "
                        "FROM workflow_step s WHERE s.id = :id AND s.fencing_token = :tok "
                        "AND s.lease_owner = :owner AND s.state = 'running' FOR UPDATE"
                    ),
                    guard,
                )
                .mappings()
                .first()
            )
            if row is None:
                m.FENCED_COMMIT_REJECTED.inc()
                raise FencedCommitRejected(f"outcome commit of step {claim.step.id} matched 0 rows")
            run = _run_view(run_row)
            step = _step_view(row)
            late = bool(row["late"])
            remaining = float(row["deadline_in"]) if row["deadline_in"] is not None else None
            tctx = TxContext(conn=c, run=run, step=step)
            outcome = self._normalise(c, claim, outcome, late)

            step_state: str
            transition: Transition | None = None
            attempt_outcome: str

            if run.abort_requested and defn is not None:
                transition = defn.on_abort(tctx, outcome)
            if transition is not None:
                step_state = {Done: "succeeded", Wait: "cancelled"}.get(type(outcome), "failed")
                if isinstance(outcome, Fail) and outcome.error_class == ErrorClass.RETRYABLE:
                    step_state = "cancelled"
                attempt_outcome = "aborted"
            elif isinstance(outcome, Done):
                step_state, attempt_outcome = "succeeded", "succeeded"
                if defn is None:  # unreachable: unknown definitions yield Fail above
                    raise RuntimeError("no definition for a Done outcome")
                transition = defn.next(tctx, outcome)
            elif isinstance(outcome, Wait):
                step_state, attempt_outcome = "waiting", "waiting"
            elif outcome.error_class == ErrorClass.RETRYABLE:
                step_state, attempt_outcome = "ready", "retryable"
            else:
                attempt_outcome = (
                    "needs_human" if outcome.error_class == ErrorClass.NEEDS_HUMAN else "failed"
                )
                transition = defn.on_failure(tctx, outcome) if defn is not None else None
                if transition is None:
                    if outcome.error_class == ErrorClass.FATAL:
                        step_state = "failed"
                        transition = Transition(run_state="failed")
                    else:
                        step_state = "needs_human"
                        transition = Transition(
                            park_reason=outcome.needs_human_reason or outcome.reason[:120]
                        )
                else:
                    step_state = "needs_human" if transition.park_reason else "failed"

            fail = outcome if isinstance(outcome, Fail) else None
            evidence = (
                outcome.evidence
                if isinstance(outcome, Done)
                else (outcome.evidence if isinstance(outcome, Wait) else None)
            )
            not_before_sql = "not_before"
            params: dict[str, Any] = {
                **guard,
                "state": step_state,
                "ev": _j(evidence),
                "ecls": fail.error_class.value if fail else None,
                "err": _j({"reason": fail.reason, **dict(fail.detail)}) if fail else None,
                "delay": None,
            }
            if step_state == "waiting" and isinstance(outcome, Wait):
                if outcome.until_signal:
                    not_before_sql = "NULL"
                else:
                    waits = 0 if acted else self._consecutive_waits(c, claim)
                    params["delay"] = self._poll_delay(outcome, waits, remaining)
                    not_before_sql = "now() + make_interval(secs => :delay)"
            elif step_state == "ready":
                params["delay"] = _clamp(self._retry_delay(c, claim), remaining)
                not_before_sql = "now() + make_interval(secs => :delay)"

            n = c.execute(
                text(
                    f"""
                UPDATE workflow_step SET state = :state,
                  evidence = CASE WHEN CAST(:ev AS jsonb) IS NULL THEN evidence
                                  ELSE COALESCE(evidence, '{{}}'::jsonb) || CAST(:ev AS jsonb) END,
                  error_class = CAST(:ecls AS text), error = CAST(:err AS jsonb),
                  not_before = {not_before_sql},
                  lease_owner = NULL, lease_expires_at = NULL,
                  finished_at = CASE WHEN :state IN ('succeeded', 'failed', 'cancelled', 'skipped')
                                     THEN now() END,
                  updated_at = now()
                WHERE id = :id AND fencing_token = :tok AND lease_owner = :owner AND state = 'running'
                """
                ),
                params,
            ).rowcount
            if n != 1:  # cannot happen while we hold the row lock; asserted for the reviewer
                raise FencedCommitRejected(f"outcome update matched {n} rows")
            c.execute(
                text(
                    "UPDATE workflow_step_attempt SET ended_at = now(), outcome = :o, error_class = :e, "
                    "evidence = CAST(:ev AS jsonb) WHERE step_id = :sid AND attempt = :att"
                ),
                {
                    "o": attempt_outcome,
                    "e": params["ecls"],
                    "ev": _j(evidence) if evidence is not None else params["err"],
                    "sid": claim.step.id,
                    "att": claim.step.attempt,
                },
            )
            self.audit.record(
                c,
                AuditEvent(
                    action="step.outcome",
                    target_type="workflow_step",
                    target_id=step.id,
                    run_id=run.id,
                    step_id=step.id,
                    result=attempt_outcome,
                    after={
                        "step_key": step.step_key,
                        "attempt": step.attempt,
                        "state": step_state,
                        "error_class": params["ecls"],
                    },
                ),
            )
            if transition is not None and self._apply_transition_safely(
                c, run, step, transition, defn, attempt=claim.step.attempt
            ):
                attempt_outcome = "parked"
            # Everything written, COMMIT not yet sent (a lost COMMIT is tested here, SRE-C-8).
            crashpoint("outcome.before_commit")
        m.STEP_ATTEMPTS.labels(step.step_key, attempt_outcome, params["ecls"] or "none").inc()
        return attempt_outcome

    def _normalise(self, c: Connection, claim: Claim, outcome: Outcome, late: bool) -> Outcome:
        """Deadline and retry budget (WF-14, WF-18): a timed wait or a retry past ``deadline_at`` and an
        exhausted retry budget become needs_human (state unknown), never fatal."""
        if isinstance(outcome, Wait) and not outcome.until_signal and late:
            return Fail(
                ErrorClass.NEEDS_HUMAN,
                "step deadline reached while waiting",
                {"waited_evidence": dict(outcome.evidence or {})},
                needs_human_reason="deadline_exceeded",
            )
        if isinstance(outcome, Fail) and outcome.error_class == ErrorClass.RETRYABLE:
            if late:
                return Fail(
                    ErrorClass.NEEDS_HUMAN,
                    f"step deadline reached: {outcome.reason}",
                    outcome.detail,
                    needs_human_reason=outcome.needs_human_reason or "deadline_exceeded",
                )
            failures = 1 + int(
                c.execute(
                    text(
                        "SELECT count(*) FROM workflow_step_attempt WHERE step_id = :sid "
                        "AND attempt > :floor AND attempt < :att AND outcome = 'retryable'"
                    ),
                    {"sid": claim.step.id, "floor": claim.retry_floor, "att": claim.step.attempt},
                ).scalar_one()
            )
            if failures >= self.config.max_attempts(claim.step.step_key):
                return Fail(
                    ErrorClass.NEEDS_HUMAN,
                    f"retries exhausted ({failures}): {outcome.reason}",
                    outcome.detail,
                    needs_human_reason=outcome.needs_human_reason or "retries_exhausted",
                )
        return outcome

    def _poll_delay(self, wait: Wait, consecutive_waits: int, remaining: float | None) -> float:
        """Backoff by the number of *consecutive* waits before this attempt (an attempt that acted resets it;
        takeovers and retries do not advance it), clamped to the time left before ``deadline_at`` so the step
        is re-probed at its deadline rather than after it (SRE-C-5)."""
        if wait.poll_after is not None:
            delay = max(0.0, wait.poll_after)
        else:
            exp = min(max(consecutive_waits, 0), 30)
            delay = float(min(self.config.poll_max, self.config.poll_initial * (2**exp)))
        return _clamp(delay, remaining)

    def _consecutive_waits(self, c: Connection, claim: Claim) -> int:
        """Earlier attempts of this step that ended ``waiting``, since the last attempt that ended otherwise
        (``lost`` attempts, i.e. takeovers, are transparent)."""
        return int(
            c.execute(
                text(
                    "SELECT count(*) FROM workflow_step_attempt WHERE step_id = :sid AND attempt < :att "
                    "AND outcome = 'waiting' AND attempt > COALESCE((SELECT max(attempt) "
                    "  FROM workflow_step_attempt WHERE step_id = :sid AND attempt < :att "
                    "  AND outcome IS DISTINCT FROM 'waiting' AND outcome IS DISTINCT FROM 'lost'), 0)"
                ),
                {"sid": claim.step.id, "att": claim.step.attempt},
            ).scalar_one()
        )

    def _retry_delay(self, c: Connection, claim: Claim) -> float:
        n = int(
            c.execute(
                text(
                    "SELECT count(*) FROM workflow_step_attempt WHERE step_id = :sid AND attempt > :floor "
                    "AND attempt < :att AND outcome = 'retryable'"
                ),
                {"sid": claim.step.id, "floor": claim.retry_floor, "att": claim.step.attempt},
            ).scalar_one()
        )
        return float(
            min(
                self.config.retry_backoff_max, self.config.retry_backoff_initial * (2 ** min(n, 30))
            )
        )

    # ---- transitions -----------------------------------------------------------------------------------

    def _apply_transition_safely(
        self,
        c: Connection,
        run: RunView,
        step: StepView | None,
        t: Transition,
        defn: WorkflowDefinition | None,
        *,
        attempt: int | None = None,
    ) -> bool:
        """Apply ``t`` after an outcome commit; on a lock conflict keep the step open in needs_human and park
        the run instead. Returns True when parked on a conflict."""
        try:
            with c.begin_nested():
                self._apply_transition(c, run, t, defn)
        except LockConflict as exc:
            self._park_on_conflict(c, run, step, exc, defn, attempt=attempt)
            return True
        return False

    def _close_and_transition(
        self,
        c: Connection,
        run: RunView,
        step: StepView | None,
        close_state: str,
        t: Transition,
        defn: WorkflowDefinition | None,
    ) -> bool:
        """Signal-driven transition (abort, strategy kinds), atomic with its lock acquisition (SRE-C-1).

        Closing the open step and applying ``t`` share one savepoint: on a lock conflict both roll back, the
        step stays open in ``needs_human`` and the run is parked, so retry-step, mark-resolved and re-sending
        the signal keep working. A parking transition keeps the step open in ``needs_human`` (S9)."""
        try:
            with c.begin_nested():
                if t.park_reason is not None:
                    self._step_needs_human(c, step, {"reason": f"parked: {t.park_reason}"})
                else:
                    self._close_open_step(c, step, close_state)
                self._apply_transition(c, run, t, defn)
        except LockConflict as exc:
            self._park_on_conflict(c, run, step, exc, defn)
            return True
        return False

    def _step_needs_human(
        self, c: Connection, step: StepView | None, error: Mapping[str, Any]
    ) -> None:
        if step is None:
            return
        n = c.execute(
            text(
                "UPDATE workflow_step SET state = 'needs_human', finished_at = NULL, not_before = NULL, "
                "lease_owner = NULL, lease_expires_at = NULL, error_class = 'needs_human', "
                "error = CAST(:e AS jsonb), updated_at = now() WHERE id = :id AND state <> 'running'"
            ),
            {"id": step.id, "e": _j(error)},
        ).rowcount
        if n != 1:
            raise _LeavePending  # cannot happen: the step row is locked and not running

    def _park_on_conflict(
        self,
        c: Connection,
        run: RunView,
        step: StepView | None,
        exc: LockConflict,
        defn: WorkflowDefinition | None,
        *,
        attempt: int | None = None,
    ) -> None:
        lock = f"{exc.lock.resource_type}/{exc.lock.resource_key}"
        log.warning(
            "lock conflict in transition; step kept open, run parked",
            extra={"run_id": run.id, "lock": lock},
        )
        if step is not None:
            self._step_needs_human(
                c, step, {"reason": str(exc), "lock": lock, "holder": exc.holder}
            )
            if attempt is not None:
                c.execute(
                    text(
                        "UPDATE workflow_step_attempt SET outcome = 'parked' "
                        "WHERE step_id = :sid AND attempt = :att"
                    ),
                    {"sid": step.id, "att": attempt},
                )
            self.audit.record(
                c,
                AuditEvent(
                    action="step.parked",
                    target_type="workflow_step",
                    target_id=step.id,
                    run_id=run.id,
                    step_id=step.id,
                    result="lock_conflict",
                    after={
                        "step_key": step.step_key,
                        "attempt": attempt,
                        "lock": lock,
                        "holder_run_id": exc.holder,
                    },
                ),
            )
        self._apply_transition(c, run, Transition(park_reason="lock_conflict"), defn)

    def _apply_transition(
        self, c: Connection, run: RunView, t: Transition, defn: WorkflowDefinition | None
    ) -> None:
        if t.acquire_locks:
            self._acquire_locks(c, run.id, t.acquire_locks)
        phase_sql = ", phase = :phase" if t.phase is not None else ""
        if t.next_step is not None:
            self._insert_step(c, run.id, t.next_step, defn)
            c.execute(
                text(
                    "UPDATE workflow_run SET state = 'running', needs_human_reason = NULL, "
                    f"updated_at = now(), version = version + 1{phase_sql} WHERE id = :id"
                ),
                {"id": run.id, "phase": t.phase},
            )
        elif t.park_reason is not None:
            c.execute(
                text(
                    "UPDATE workflow_run SET state = 'needs_human', needs_human_reason = :r, "
                    f"updated_at = now(), version = version + 1{phase_sql} WHERE id = :id"
                ),
                {"id": run.id, "r": t.park_reason, "phase": t.phase},
            )
            self.audit.record(
                c,
                AuditEvent(
                    action="run.needs_human",
                    target_type="workflow_run",
                    target_id=run.id,
                    run_id=run.id,
                    after={"reason": t.park_reason},
                ),
            )
        else:
            self._finish_run(c, run.id, t.run_state or "failed", phase=t.phase)

    def _finish_run(
        self,
        c: Connection,
        run_id: str,
        state: str,
        *,
        phase: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Terminal transition: cancel any open step, release every lock of the run, same transaction."""
        c.execute(
            text(
                "UPDATE workflow_step SET state = 'cancelled', lease_owner = NULL, lease_expires_at = NULL, "
                "finished_at = now(), updated_at = now() "
                "WHERE run_id = :id AND state IN ('ready', 'waiting', 'needs_human')"
            ),
            {"id": run_id},
        )
        crashpoint("lease.release")
        released = c.execute(
            text("DELETE FROM resource_lock WHERE holder_run_id = :id"), {"id": run_id}
        ).rowcount
        c.execute(
            text(
                "UPDATE workflow_run SET state = :s, finished_at = now(), needs_human_reason = NULL, "
                "end_reason = COALESCE(:reason, end_reason), phase = COALESCE(:phase, phase), "
                "updated_at = now(), version = version + 1 WHERE id = :id"
            ),
            {"id": run_id, "s": state, "phase": phase, "reason": reason},
        )
        self.audit.record(
            c,
            AuditEvent(
                action=f"run.{state}",
                target_type="workflow_run",
                target_id=run_id,
                run_id=run_id,
                after={"locks_released": released, "reason": reason},
            ),
        )

    def _insert_step(
        self, c: Connection, run_id: str, spec: StepSpec, defn: WorkflowDefinition | None
    ) -> str:
        destructive = spec.destructive
        if destructive is None:
            impl = defn.steps.get(spec.step_key) if defn else None
            destructive = bool(impl and impl.destructive)
        step_id = new_id()
        c.execute(
            text(
                "INSERT INTO workflow_step (id, run_id, seq, step_key, state, not_before, deadline_at, "
                "destructive, params, timeout_seconds) VALUES (:id, :run, "
                "(SELECT COALESCE(max(seq), 0) + 1 FROM workflow_step WHERE run_id = :run), :key, 'ready', "
                "now() + make_interval(secs => :delay), "
                "CASE WHEN CAST(:timeout AS double precision) IS NULL THEN NULL "
                "     ELSE now() + make_interval(secs => :delay + CAST(:timeout AS double precision)) END, "
                ":destructive, CAST(:params AS jsonb), CAST(:timeout AS double precision))"
            ),
            {
                "id": step_id,
                "run": run_id,
                "key": spec.step_key,
                "delay": float(spec.delay or 0.0),
                "timeout": spec.timeout,
                "destructive": destructive,
                "params": _j(spec.params) or "{}",
            },
        )
        return step_id

    def _acquire_locks(self, c: Connection, run_id: str, locks: Sequence[LockSpec]) -> None:
        """All-or-nothing in sorted order (no deadlock between crossed lock sets, WF-11). Re-acquiring a lock
        the run already holds is a no-op. The caller's transaction (or savepoint) makes it atomic."""
        for lock in sorted(set(locks), key=lambda x: (x.resource_type, x.resource_key)):
            got = c.execute(
                text(
                    "INSERT INTO resource_lock (resource_type, resource_key, holder_run_id, reason) "
                    "VALUES (:t, :k, :run, :reason) ON CONFLICT (resource_type, resource_key) DO NOTHING "
                    "RETURNING holder_run_id"
                ),
                {
                    "t": lock.resource_type,
                    "k": lock.resource_key,
                    "run": run_id,
                    "reason": lock.reason,
                },
            ).first()
            if got is None:
                holder = c.execute(
                    text(
                        "SELECT holder_run_id FROM resource_lock WHERE resource_type = :t AND resource_key = :k"
                    ),
                    {"t": lock.resource_type, "k": lock.resource_key},
                ).scalar()
                if holder is None or str(holder) != run_id:
                    raise LockConflict(lock, str(holder))

    # ---- admission -------------------------------------------------------------------------------------

    def admit_pending(self, limit: int = 20) -> int:
        with self.db.connect() as c:
            ids = [
                str(x)
                for x in c.execute(
                    text(
                        "SELECT id FROM workflow_run WHERE state = 'requested' ORDER BY created_at LIMIT :n"
                    ),
                    {"n": limit},
                ).scalars()
            ]
        return sum(1 for rid in ids if self._admit(rid))

    def _admit(self, run_id: str) -> bool:
        with self.db.connect() as c:
            row = (
                c.execute(
                    text(f"SELECT {_RUN_COLS} FROM workflow_run r WHERE r.id = :id"), {"id": run_id}
                )
                .mappings()
                .first()
            )
        if row is None or row["state"] != "requested":
            return False
        pre = _run_view(row)
        defn = self.registry.resolve(pre.kind, pre.strategy, pre.strategy_version)
        current = defn is not None and self.registry.is_current(
            pre.kind, pre.strategy, pre.strategy_version
        )
        prepared = defn.prepare_admission(pre) if defn is not None and current else None
        with self.db.begin() as c:
            # Serialises admissions: the concurrency cap and lock-set acquisition are race-free.
            c.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": ADMISSION_LOCK_KEY})
            row = (
                c.execute(
                    text(
                        f"SELECT {_RUN_COLS} FROM workflow_run r WHERE r.id = :id AND r.state = 'requested' "
                        "FOR UPDATE SKIP LOCKED"
                    ),
                    {"id": run_id},
                )
                .mappings()
                .first()
            )
            if row is None:
                return False
            run = _run_view(row)
            if defn is None or not current:
                versions = self.registry.current_versions(run.kind, run.strategy)
                self._finish_run(
                    c,
                    run.id,
                    "rejected",
                    reason=(
                        f"unknown strategy {run.kind}/{run.strategy} version {run.strategy_version}; "
                        f"this release starts: {', '.join(versions) or 'none'}"
                    ),
                )
                return True
            cap = defn.concurrency_cap()
            if cap is not None:
                active = c.execute(
                    text(
                        "SELECT count(*) FROM workflow_run WHERE kind = :k "
                        "AND state IN ('running', 'needs_human')"
                    ),
                    {"k": run.kind},
                ).scalar_one()
                if active >= cap:
                    log.info("admission deferred: concurrency cap", extra={"run_id": run.id})
                    return False
            res = defn.admit(TxContext(conn=c, run=run, prepared=prepared))
            if isinstance(res, Defer):
                log.info("admission deferred", extra={"run_id": run.id, "reason": res.reason})
                return False
            if isinstance(res, Reject):
                self._finish_run(c, run.id, "rejected", reason=res.reason)
                return True
            try:
                with c.begin_nested():
                    self._acquire_locks(c, run.id, res.locks)
            except LockConflict as exc:
                self._finish_run(c, run.id, "rejected", reason=f"resource locked: {exc}")
                return True
            crashpoint("run.create")
            self._insert_step(c, run.id, res.first_step, defn)
            c.execute(
                text(
                    "UPDATE workflow_run SET state = 'running', admitted_at = now(), phase = :phase, "
                    "updated_at = now(), version = version + 1 WHERE id = :id"
                ),
                {"id": run.id, "phase": res.phase},
            )
            self.audit.record(
                c,
                AuditEvent(
                    action="run.admitted",
                    target_type="workflow_run",
                    target_id=run.id,
                    run_id=run.id,
                    after={
                        "locks": [f"{x.resource_type}/{x.resource_key}" for x in res.locks],
                        "first_step": res.first_step.step_key,
                    },
                ),
            )
        return True

    # ---- signals ---------------------------------------------------------------------------------------

    def process_signals(self, limit: int = 50) -> int:
        with self.db.connect() as c:
            ids = [
                str(x)
                for x in c.execute(
                    text(
                        "SELECT id FROM run_signal WHERE consumed_at IS NULL ORDER BY created_at, id LIMIT :n"
                    ),
                    {"n": limit},
                ).scalars()
            ]
        return sum(1 for sid in ids if self._apply_signal(sid))

    def _apply_signal(self, signal_id: str) -> bool:
        with self.db.connect() as c:
            srow = (
                c.execute(
                    text(
                        "SELECT g.id AS sig_id, g.run_id AS sig_run_id, g.kind AS sig_kind, g.actor_id, "
                        "g.approval_id, g.payload AS sig_payload, "
                        f"{_RUN_COLS} FROM run_signal g JOIN workflow_run r ON r.id = g.run_id "
                        "WHERE g.id = :id AND g.consumed_at IS NULL"
                    ),
                    {"id": signal_id},
                )
                .mappings()
                .first()
            )
        if srow is None:
            return False
        pre_run = _run_view(srow)
        defn = self.registry.resolve(pre_run.kind, pre_run.strategy, pre_run.strategy_version)
        if (
            defn is None
            and pre_run.state != "requested"
            and pre_run.state not in TERMINAL_RUN_STATES
        ):
            return False  # another worker release may know this run; leave the signal pending
        sig = SignalView(
            id=str(srow["sig_id"]),
            run_id=str(srow["sig_run_id"]),
            kind=srow["sig_kind"],
            actor_id=str(srow["actor_id"]) if srow["actor_id"] else None,
            approval_id=str(srow["approval_id"]) if srow["approval_id"] else None,
            payload=srow["sig_payload"] or {},
        )
        prepared = defn.prepare_signal(pre_run, sig) if defn is not None else None
        try:
            with self.db.begin() as c:
                locked = c.execute(
                    text(
                        "SELECT id FROM run_signal WHERE id = :id AND consumed_at IS NULL "
                        "FOR UPDATE SKIP LOCKED"
                    ),
                    {"id": signal_id},
                ).first()
                if locked is None:
                    return False
                run = _run_view(
                    c.execute(
                        text(f"SELECT {_RUN_COLS} FROM workflow_run r WHERE r.id = :id FOR UPDATE"),
                        {"id": sig.run_id},
                    )
                    .mappings()
                    .one()
                )
                srow2 = (
                    c.execute(
                        text(
                            f"SELECT {_STEP_COLS} FROM workflow_step s WHERE s.run_id = :id "
                            "AND s.state IN ('ready', 'running', 'waiting', 'needs_human') FOR UPDATE"
                        ),
                        {"id": run.id},
                    )
                    .mappings()
                    .first()
                )
                open_step = _step_view(srow2) if srow2 else None
                tctx = TxContext(conn=c, run=run, step=open_step, signal=sig, prepared=prepared)
                outcome, effect = self._signal_effect(c, defn, tctx)
                crashpoint("signal.apply")  # effect written, consumption not yet: both or neither
                c.execute(
                    text(
                        "UPDATE run_signal SET consumed_at = now(), outcome = :o WHERE id = :id "
                        "AND consumed_at IS NULL"
                    ),
                    {"id": sig.id, "o": outcome[:500]},
                )
                if effect:
                    self.audit.record(
                        c,
                        AuditEvent(
                            action=f"signal.{sig.kind}",
                            target_type="workflow_run",
                            target_id=run.id,
                            run_id=run.id,
                            step_id=open_step.id if open_step else None,
                            actor_id=sig.actor_id,
                            principal_type="user" if sig.actor_id else "system",
                            result="refused" if outcome.startswith("refused") else "ok",
                            after={"signal_id": sig.id, "outcome": outcome[:200]},
                        ),
                    )
        except _LeavePending:
            return False
        return True

    def _signal_effect(
        self, c: Connection, defn: WorkflowDefinition | None, ctx: TxContext
    ) -> tuple[str, bool]:
        """Returns (outcome, had_effect). Raises _LeavePending to keep the signal for a later pass."""
        run, step, sig = ctx.run, ctx.step, ctx.signal
        if sig is None:
            raise RuntimeError("signal context without a signal")
        if run.state in TERMINAL_RUN_STATES:
            return f"ignored: run is {run.state}", False
        if run.state == "requested" and sig.kind == "abort":
            if defn is not None:
                refusal = defn.validate_signal(ctx)
                if refusal:
                    return f"refused: {refusal}", True
            self._finish_run(c, run.id, "cancelled", reason="aborted before admission")
            return "cancelled before admission", True
        if run.state == "requested":
            raise _LeavePending  # applied after admission
        if defn is None:
            raise _LeavePending
        refusal = defn.validate_signal(ctx)
        if refusal:
            return f"refused: {refusal}", True

        if sig.kind == "abort":
            if run.abort_requested:
                return "duplicate: abort already requested", False
            c.execute(
                text(
                    "UPDATE workflow_run SET abort_requested = true, abort_requested_by = :a, "
                    "updated_at = now(), version = version + 1 WHERE id = :id"
                ),
                {"id": run.id, "a": sig.actor_id},
            )
            if step is not None and step.state == "running":
                return "abort requested; applies at the step boundary", True
            run2 = _replace_run(run, abort_requested=True)
            t = defn.on_abort(TxContext(conn=c, run=run2, step=step, signal=sig), None)
            if t is None:
                return "abort requested; deferred by the strategy", True
            if self._close_and_transition(c, run2, step, "cancelled", t, defn):
                return "abort: lock conflict in the abort transition; run parked", True
            return "aborted at boundary", True

        if sig.kind in ("retry_step", "mark_resolved", "reprepare_automation"):
            if run.state != "needs_human" or step is None or step.state != "needs_human":
                return "rejected: no step in needs_human", False
            recorded: str | None = None
            if sig.kind == "reprepare_automation":
                # The strategy records the one-shot authorization (its own rows, this transaction); then the
                # parked step is re-queued exactly as retry-step does.
                res = defn.on_signal(ctx)
                if not isinstance(res, str):
                    return f"unsupported signal {sig.kind} for this strategy", False
                if res.startswith("refused"):
                    return res, True
                recorded = res
            # Both re-queue the step with a fresh retry budget and deadline. mark_resolved records the
            # operator's attestation as evidence but does not close the step: the next attempt probes and
            # must reach Done by itself ("the engine re-probes before continuing", renewal-workflow.md
            # section 6; SRE-C-2).
            evidence: dict[str, Any] | None = None
            if sig.kind == "mark_resolved":
                evidence = {
                    "mark_resolved": {"actor_id": sig.actor_id, "payload": dict(sig.payload)}
                }
            elif sig.kind == "reprepare_automation":
                evidence = {"reprepare_automation": {"actor_id": sig.actor_id, "signal_id": sig.id}}
            c.execute(
                text(
                    "UPDATE workflow_step SET state = 'ready', not_before = now(), error_class = NULL, "
                    "error = NULL, retry_floor = attempt, "
                    "evidence = CASE WHEN CAST(:ev AS jsonb) IS NULL THEN evidence "
                    "  ELSE COALESCE(evidence, '{}'::jsonb) || CAST(:ev AS jsonb) END, "
                    "deadline_at = CASE WHEN timeout_seconds IS NULL THEN NULL "
                    "  ELSE now() + make_interval(secs => timeout_seconds) END, updated_at = now() "
                    "WHERE id = :id AND state = 'needs_human'"
                ),
                {"id": step.id, "ev": _j(evidence)},
            )
            c.execute(
                text(
                    "UPDATE workflow_run SET state = 'running', needs_human_reason = NULL, "
                    "updated_at = now(), version = version + 1 WHERE id = :id"
                ),
                {"id": run.id},
            )
            if sig.kind == "retry_step":
                return f"step {step.step_key} re-queued", True
            if recorded is not None:
                return f"{recorded}; step {step.step_key} re-queued", True
            return f"step {step.step_key} re-queued for verification (mark_resolved)", True

        if sig.kind == "accept_step":
            return self._accept_step(c, defn, ctx)

        # Strategy-specific kinds and wake-ups need a step boundary.
        if step is not None and step.state == "running":
            raise _LeavePending
        res = defn.on_signal(ctx)
        if res is None or isinstance(res, AcceptStep):
            return f"unsupported signal {sig.kind} for this strategy", False
        if isinstance(res, str):
            return res, True
        if isinstance(res, Wake):
            if step is None or step.state != "waiting":
                return "nothing to wake", False
            c.execute(
                text(
                    "UPDATE workflow_step SET state = 'ready', not_before = now(), updated_at = now() "
                    "WHERE id = :id AND state = 'waiting'"
                ),
                {"id": step.id},
            )
            return f"step {step.step_key} woken", True
        if self._close_and_transition(c, run, step, "cancelled", res, defn):
            return f"{sig.kind}: lock conflict; step kept open, run parked", True
        return f"{sig.kind} applied", True

    def _accept_step(
        self, c: Connection, defn: WorkflowDefinition, ctx: TxContext
    ) -> tuple[str, bool]:
        """``accept_step`` (ADR-0008): the parked step is closed ``succeeded`` with ``resolution = accepted``
        **without being run**, and the run moves on. The strategy has re-validated the signal and records its own
        rows in this transaction (:meth:`WorkflowDefinition.on_signal` returns :class:`AcceptStep`). The close is a
        compare-and-set on ``(state = needs_human, attempt)``; it also retires the parked attempt's fencing token (a
        fresh ``fencing_seq`` value), so a late outcome or heartbeat of that attempt, or of any older one, matches 0
        rows and is discarded (S2). No lease is taken: no attempt runs while the step is parked."""
        run, step = ctx.run, ctx.step
        if run.state != "needs_human" or step is None or step.state != "needs_human":
            return "refused: no step in needs_human", True
        res = defn.on_signal(ctx)
        if isinstance(res, str):
            return res, True
        if not isinstance(res, AcceptStep):
            return "unsupported signal accept_step for this strategy", False
        try:
            with c.begin_nested():
                n = c.execute(
                    text(
                        "UPDATE workflow_step SET state = 'succeeded', resolution = 'accepted', "
                        "fencing_token = nextval('fencing_seq'), lease_owner = NULL, lease_expires_at = NULL, "
                        "not_before = NULL, finished_at = now(), updated_at = now(), "
                        "evidence = COALESCE(evidence, '{}'::jsonb) || CAST(:ev AS jsonb) "
                        "WHERE id = :id AND state = 'needs_human' AND attempt = :att"
                    ),
                    {"id": step.id, "att": res.attempt, "ev": _j(res.evidence) or "{}"},
                ).rowcount
                if n != 1:
                    raise _LeavePending  # the step moved under us: re-validated (and refused) on a later pass
                self._apply_transition(c, run, res.transition, defn)
        except LockConflict as exc:
            # Nothing of the accept may stay half-applied (its rows are outside the savepoint): retry later.
            raise _LeavePending from exc
        return f"step {step.step_key} accepted without running it", True

    def _close_open_step(
        self,
        c: Connection,
        step: StepView | None,
        state: str,
        evidence: Mapping[str, Any] | None = None,
    ) -> None:
        if step is None:
            return
        n = c.execute(
            text(
                "UPDATE workflow_step SET state = :s, finished_at = now(), updated_at = now(), "
                "evidence = CASE WHEN CAST(:ev AS jsonb) IS NULL THEN evidence "
                "  ELSE COALESCE(evidence, '{}'::jsonb) || CAST(:ev AS jsonb) END "
                "WHERE id = :id AND state = :prev"
            ),
            {"id": step.id, "s": state, "prev": step.state, "ev": _j(evidence)},
        ).rowcount
        if n != 1:
            raise _LeavePending  # the step moved under us; retry the signal later

    # ---- scheduler -------------------------------------------------------------------------------------

    def run_scheduler(self) -> int:
        """Create due periodic single-step runs. Only the holder of the scheduler advisory lock acts."""
        if not self.registry.periodic:
            return 0
        created = 0
        with self.db.begin() as c:
            if not c.execute(
                text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": SCHEDULER_LOCK_KEY}
            ).scalar_one():
                return 0
            for job in self.registry.periodic:
                busy = c.execute(
                    text(
                        "SELECT 1 FROM workflow_run WHERE kind = :k AND strategy = :s AND "
                        "(finished_at IS NULL OR finished_at > now() - make_interval(secs => :i)) LIMIT 1"
                    ),
                    {"k": job.kind, "s": job.strategy, "i": job.interval},
                ).first()
                if busy is None:
                    request_run(
                        c,
                        kind=job.kind,
                        strategy=job.strategy,
                        strategy_version=job.version,
                        subject=job.subject,
                    )
                    created += 1
        return created

    # ---- metrics ---------------------------------------------------------------------------------------

    def refresh_metrics(self) -> None:
        with self.db.connect() as c:
            runs = c.execute(
                text("SELECT kind, state, count(*) FROM workflow_run GROUP BY 1, 2")
            ).all()
            attention = c.execute(
                text(
                    "SELECT COALESCE(phase, 'none'), COALESCE(needs_human_reason, 'unknown'), count(*) "
                    "FROM workflow_run WHERE state = 'needs_human' GROUP BY 1, 2"
                )
            ).all()
            req = c.execute(
                text(
                    "SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(created_at)), 0), "
                    "count(*) FILTER (WHERE created_at < now() - make_interval(secs => :a)) "
                    "FROM workflow_run WHERE state = 'requested'"
                ),
                {"a": self.config.admission_alert_after},
            ).one()
            sig = c.execute(
                text(
                    "SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(created_at)), 0), "
                    "count(*) FILTER (WHERE created_at < now() - make_interval(secs => :a)) "
                    "FROM run_signal WHERE consumed_at IS NULL"
                ),
                {"a": self.config.signal_alert_after},
            ).one()
            live = count_live_workers(c, LIVE_WORKER_BEATS * self.config.heartbeat_interval)
            hb = c.execute(
                text(
                    "SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(heartbeat_at)), 0), "
                    "count(*) FILTER (WHERE lease_expires_at < now()) "
                    "FROM workflow_step WHERE state = 'running'"
                )
            ).one()
            for refresh in self.registry.metric_refreshers:
                try:
                    with c.begin_nested():
                        refresh(c)
                except Exception:
                    log.exception("metrics refresher failed")
        m.RUNS.clear()
        for kind, state, n in runs:
            m.RUNS.labels(kind, state).set(n)
        m.RUNS_NEEDING_ATTENTION.clear()
        for phase, reason, n in attention:
            m.RUNS_NEEDING_ATTENTION.labels(phase, reason).set(n)
        m.REQUESTED_OLDEST.set(float(req[0]))
        m.REQUESTED_OVERDUE.set(req[1])
        m.SIGNALS_PENDING_OLDEST.set(float(sig[0]))
        m.SIGNALS_PENDING_OVERDUE.set(sig[1])
        m.STEP_HEARTBEAT_AGE.set(float(hb[0]))
        m.EXPIRED_LEASES.set(hb[1])
        m.LIVE_WORKERS.set(live)

    # ---- convenience for a synchronous loop (tests, single-slot) ---------------------------------------

    def run_once(self) -> int:
        """One synchronous pass: signals, admission, then claim and execute at most one step."""
        self.process_signals()
        self.admit_pending()
        claims = self.claim(1)
        for cl in claims:
            self.execute(cl)
        return len(claims)


def _clamp(delay: float, remaining: float | None) -> float:
    """Never schedule past ``deadline_at``: a timer beyond it is cut to the deadline (SRE-C-5)."""
    if remaining is None:
        return delay
    return max(0.0, min(delay, remaining))


def _replace_run(run: RunView, **kw: Any) -> RunView:
    from dataclasses import replace

    return replace(run, **kw)


__all__ = [
    "OPEN_STEP_STATES",
    "Claim",
    "EngineConfig",
    "LockConflict",
    "WorkflowEngine",
]
