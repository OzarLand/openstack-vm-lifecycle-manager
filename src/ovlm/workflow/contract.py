"""Interfaces strategies plug into: the step contract and the workflow definition (ADR-0003).

Step contract: probe -> decide -> act -> verify
------------------------------------------------
The engine (not the step) drives every attempt through :meth:`Step.run_contract`:

1. ``probe(ctx)`` reads real state (OpenStack, guest, ledger). Read-only; never gated.
2. ``decide(ctx, observed)`` returns :class:`Done` (goal already reached: record evidence, no action),
   :class:`Act` (with the intent to persist), :class:`Wait` (nothing to do yet) or :class:`Fail` (unexpected
   state, classified).
3. For :class:`Act`, the engine persists ``intent`` in a fenced commit **before** acting (crash point
   ``after_intent``), so a later attempt knows what may have been sent.
4. ``act(ctx, intent)`` performs the action **once**. Every mutating call goes through ``ctx.gate(...)`` (the
   WriteClient and the automation runner call it for you via ``ctx.fence``).
5. ``verify(ctx, intent)`` returns :class:`Done`, :class:`Wait` (verify on the next claim, after ``probe``) or
   :class:`Fail`.

An attempt past the step's ``deadline_at`` (at claim, or since on the local clock) never acts: an :class:`Act`
decision becomes ``Fail(NEEDS_HUMAN, needs_human_reason="deadline_exceeded")`` before the intent is persisted
(ADR-0003 "deadline reached -> needs_human"; SRE-C-3). ``Done`` stays allowed.

Every attempt, including a re-claim after ``Wait`` and a takeover after a crash, starts again at ``probe``. A
step therefore never relies on in-memory state from a previous attempt; ``ctx.previous_intent`` and
``ctx.previous_evidence`` are what the DB holds.

Exceptions raised by step code (``Exception`` subclasses) are classified by :meth:`Step.classify` (default:
retryable). Ownership loss (:class:`~ovlm.workflow.fence.OwnershipLost`) and simulated crashes are
``BaseException`` and are never seen by ``classify``.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

from sqlalchemy import Connection

if TYPE_CHECKING:
    from ovlm.workflow.fence import Fence


class ErrorClass(enum.StrEnum):
    RETRYABLE = "retryable"
    NEEDS_HUMAN = "needs_human"
    FATAL = "fatal"


TERMINAL_RUN_STATES = frozenset({"rejected", "cancelled", "failed", "completed", "rolled_back"})
OPEN_STEP_STATES = ("ready", "running", "waiting", "needs_human")
LOCK_TYPES = frozenset({"service", "server", "volume", "floating_ip", "port"})


# ---- results ----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Done:
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Act:
    intent: Mapping[str, Any]


@dataclass(frozen=True)
class Wait:
    """Not finished: release the lease and re-claim later.

    ``poll_after`` seconds (DB time) or, when None, the engine's backoff from ``poll.initial_interval`` to
    ``poll.max_interval``. ``until_signal=True`` parks the step with no timer (human waits): only a signal
    (via the definition's ``on_signal``) moves it. ``deadline_at`` still applies to timed waits.
    """

    poll_after: float | None = None
    until_signal: bool = False
    evidence: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class Fail:
    error_class: ErrorClass
    reason: str
    detail: Mapping[str, Any] = field(default_factory=dict)
    #: ``workflow_run.needs_human_reason`` when this ends in needs_human (default: derived from ``reason``).
    needs_human_reason: str | None = None


Decision = Done | Act | Wait | Fail
Outcome = Done | Wait | Fail


# ---- step specs and transitions ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StepSpec:
    step_key: str
    params: Mapping[str, Any] = field(default_factory=dict)
    #: Takeover of this step waits ``worker.takeover_delay`` before probing (SEC-R-26). Defaults to the
    #: ``destructive`` attribute of the registered :class:`Step`.
    destructive: bool | None = None
    #: Seconds until ``deadline_at`` (step timeout key), from the moment the step becomes ready.
    timeout: float | None = None
    #: Start delay (DB time); ``None`` = immediately.
    delay: float | None = None


@dataclass(frozen=True)
class LockSpec:
    resource_type: str
    resource_key: str
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.resource_type not in LOCK_TYPES:
            raise ValueError(f"unknown lock type {self.resource_type!r}")


@dataclass(frozen=True)
class Transition:
    """What happens to the run after a step boundary or a signal.

    Exactly one of ``next_step`` / ``run_state`` / ``park_reason`` is expected:
    a next step (run stays/becomes ``running``), a terminal run state (locks released in the same transaction),
    or parking the run in ``needs_human`` with that reason.
    """

    next_step: StepSpec | None = None
    run_state: str | None = None
    park_reason: str | None = None
    phase: str | None = None
    #: Acquired in the same fenced transaction, sorted, all-or-nothing (e.g. green's server and port at B4).
    acquire_locks: Sequence[LockSpec] = ()

    def __post_init__(self) -> None:
        chosen = [x is not None for x in (self.next_step, self.run_state, self.park_reason)]
        if sum(chosen) != 1:
            raise ValueError("a Transition needs exactly one of next_step, run_state, park_reason")
        if self.run_state is not None and self.run_state not in TERMINAL_RUN_STATES:
            raise ValueError(f"run_state must be terminal, got {self.run_state!r}")


@dataclass(frozen=True)
class Wake:
    """``on_signal`` result: make the run's waiting step ready now, so it re-probes (consumes the signal)."""


@dataclass(frozen=True)
class Admission:
    first_step: StepSpec
    locks: Sequence[LockSpec] = ()
    phase: str | None = None


@dataclass(frozen=True)
class Reject:
    reason: str


@dataclass(frozen=True)
class Defer:
    """Leave the run in ``requested`` for now (e.g. a precondition not yet met)."""

    reason: str


# ---- read-only views passed to strategies -----------------------------------------------------------------


@dataclass(frozen=True)
class RunView:
    id: str
    kind: str
    strategy: str
    strategy_version: str
    state: str
    phase: str | None
    subject: Mapping[str, Any]
    service_id: str | None
    renewal_plan_id: str | None
    abort_requested: bool
    needs_human_reason: str | None
    started_by: str | None


@dataclass(frozen=True)
class StepView:
    id: str
    run_id: str
    seq: int
    step_key: str
    state: str
    attempt: int
    params: Mapping[str, Any]
    intent: Mapping[str, Any] | None
    evidence: Mapping[str, Any] | None
    destructive: bool


@dataclass(frozen=True)
class SignalView:
    id: str
    run_id: str
    kind: str
    actor_id: str | None
    approval_id: str | None
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class TxContext:
    """Passed to definition hooks that run *inside* an engine transaction.

    ``conn`` may be used for reads and for the strategy's own rows that must commit atomically with the
    transition (ledger, audit). Never do network I/O here (SRE-R-28 b): prepare it before, in ``prepare_*``.
    """

    conn: Connection
    run: RunView
    step: StepView | None = None
    signal: SignalView | None = None
    prepared: Any = None


class StepContext(Protocol):
    """What a step sees during one attempt (implemented by the engine)."""

    run: RunView
    step: StepView
    attempt: int
    takeover: bool
    fence: Fence

    @property
    def params(self) -> Mapping[str, Any]: ...
    @property
    def previous_intent(self) -> Mapping[str, Any] | None: ...
    @property
    def previous_evidence(self) -> Mapping[str, Any] | None: ...
    @property
    def abort_requested(self) -> bool: ...
    @property
    def stopping(self) -> bool: ...
    @property
    def deadline_passed(self) -> bool:
        """The step's ``deadline_at`` has passed: the attempt may probe and report Done, never act."""
        ...

    def gate(self, action: str) -> None:
        """Fence gate: call immediately before any mutating call / subprocess spawn."""

    def checkpoint(
        self, *, intent: Mapping[str, Any] | None = None, evidence: Mapping[str, Any] | None = None
    ) -> None:
        """Fenced write of intent and/or evidence of the running attempt (raises on ownership loss)."""

    def sleep(self, seconds: float) -> None:
        """Interruptible sleep; raises ``FenceLost`` if the fence stops meanwhile."""

    def read(self) -> AbstractContextManager[Connection]:
        """A short read-only connection (ledger lookups during probe). Release it before any network I/O:
        it comes from the worker's pool, which heartbeats share (SRE-C-4)."""

    def crashpoint(self, phase: str) -> None: ...


# ---- the step ---------------------------------------------------------------------------------------------


class Step(ABC):
    """Abstract base for every step handler. Subclasses set ``key`` and implement the four phases."""

    key: ClassVar[str]
    #: Destructive steps: a takeover waits ``worker.takeover_delay`` before probing (SEC-R-26, SRE-R-27).
    destructive: ClassVar[bool] = False

    @abstractmethod
    def probe(self, ctx: StepContext) -> Any:
        """Read real state. Read-only."""

    @abstractmethod
    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        """Goal reached -> Done; action needed -> Act(intent); not yet -> Wait; unexpected -> Fail."""

    @abstractmethod
    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        """Perform the action once. Mutating calls pass ``ctx.gate``."""

    @abstractmethod
    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        """Check the effect: Done, Wait (verify again after the next probe) or Fail."""

    def lease_for(self, params: Mapping[str, Any]) -> float | None:
        """Lease (seconds) for an attempt of this step; ``None`` = ``worker.lease_duration``. A step that
        spawns a bounded subprocess returns its hard timeout + kill grace + ``worker.fence_margin``."""
        return None

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        """Map an unexpected exception from step code to an error class. Default: retryable."""
        return Fail(ErrorClass.RETRYABLE, f"{type(exc).__name__}: {exc}"[:500])

    def run_contract(
        self,
        ctx: StepContext,
        persist_intent: Callable[[Mapping[str, Any]], None],
    ) -> Outcome:
        """Template method; the engine calls it. Not meant to be overridden."""
        observed = self.probe(ctx)
        ctx.crashpoint("after_probe")
        decision = self.decide(ctx, observed)
        if not isinstance(decision, Act):
            return decision
        if ctx.deadline_passed:
            return Fail(
                ErrorClass.NEEDS_HUMAN,
                "step deadline passed before acting; nothing was sent",
                {"intent_not_sent": dict(decision.intent)},
                needs_human_reason="deadline_exceeded",
            )
        persist_intent(decision.intent)
        ctx.crashpoint("after_intent")
        ctx.gate(f"act:{self.key}")
        self.act(ctx, decision.intent)
        ctx.crashpoint("after_act")
        return self.verify(ctx, decision.intent)


# ---- the workflow definition ------------------------------------------------------------------------------


class WorkflowDefinition(ABC):
    """A strategy: a set of steps and the transitions between them. The engine knows nothing else about it."""

    kind: ClassVar[str]
    strategy: ClassVar[str]
    version: ClassVar[str]
    #: Older ``strategy_version`` values whose ``ready``/``waiting`` steps this definition resumes (upgrades,
    #: architecture.md section 9). A run of any other unknown version is never claimed by this worker.
    resumes_versions: ClassVar[frozenset[str]] = frozenset()

    @property
    @abstractmethod
    def steps(self) -> Mapping[str, Step]: ...

    def concurrency_cap(self) -> int | None:
        """Max admitted non-terminal runs of this ``kind`` (renewal: ``renewal.max_concurrent_runs``)."""
        return None

    def prepare_admission(self, run: RunView) -> Any:
        """Network I/O needed by ``admit`` (e.g. token pre-warm), done before the transaction opens."""
        return None

    @abstractmethod
    def admit(self, ctx: TxContext) -> Admission | Reject | Defer:
        """Re-validate the request (approval evidence, E5-5) and return the locks and the first step."""

    @abstractmethod
    def next(self, ctx: TxContext, done: Done) -> Transition:
        """Transition after ``ctx.step`` succeeded."""

    def on_failure(self, ctx: TxContext, fail: Fail) -> Transition | None:
        """Transition after a fatal / needs_human failure of ``ctx.step``.

        ``None`` = engine default: fatal -> run ``failed``; needs_human (incl. retry exhaustion and deadline)
        -> step and run parked in ``needs_human``. A strategy returns e.g. a restore step here (closed table).
        """
        return None

    def on_abort(self, ctx: TxContext, outcome: Outcome | None) -> Transition | None:
        """Called at a step boundary while ``abort_requested`` is set (``ctx.step`` is the step at the
        boundary; ``outcome`` is None when no step was running). ``None`` defers the abort to the next
        boundary. Default: cancel the run."""
        return Transition(run_state="cancelled")

    @abstractmethod
    def validate_signal(self, ctx: TxContext) -> str | None:
        """Re-validate actor role, step-up and typed confirmation of ``ctx.signal`` (renewal-workflow.md
        section 3.1). Return a refusal reason, or None to accept. Called for every signal kind."""

    def prepare_signal(self, run: RunView, signal: SignalView) -> Any:
        """Network I/O needed to apply a signal, done before the transaction opens (SRE-R-28 b)."""
        return None

    def on_signal(self, ctx: TxContext) -> Transition | Wake | str | None:
        """Kinds the engine does not apply generically (``rollback``, ``revert``, ``discard``, ``probe``,
        ``admit``). Return a Transition (applied; the open step is cancelled), :class:`Wake` (the waiting step
        becomes ready and re-probes), a string outcome (consumed without a state change) or None
        (``unsupported``)."""
        return None


class StartupSweeper(Protocol):
    """Run once at worker start, before the first claim (e.g. kill orphan Ansible process groups, SRE-R-5)."""

    def __call__(self) -> None: ...
