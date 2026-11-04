"""Dummy strategy and fake "cloud" for engine tests (no OpenStack, no renewal semantics).

The fake cloud lives in two tables of the test database (``fake_resource``, ``fake_effect``) written through a
separate autocommit connection, so it behaves like an external system: its writes are not part of the engine's
transactions and survive a crash of the engine. Every mutating call passes ``ctx.gate`` first, exactly as the
WriteClient hook will.

A run's plan is in ``workflow_run.subject["plan"]``: a list of ``{"key", "params", "timeout", "destructive",
"phase", "acquire_locks"}``. ``next`` walks it; the last step completes the run.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any, ClassVar

from sqlalchemy import Engine, text

from ovlm.workflow.contract import (
    Act,
    Admission,
    Decision,
    Defer,
    Done,
    ErrorClass,
    Fail,
    LockSpec,
    Outcome,
    Reject,
    Step,
    StepContext,
    StepSpec,
    Transition,
    TxContext,
    Wait,
    Wake,
    WorkflowDefinition,
)

FAKE_SCHEMA = """
CREATE TABLE fake_resource (key text PRIMARY KEY, value text NOT NULL, pending_polls int NOT NULL DEFAULT 0);
CREATE TABLE fake_effect (id bigserial PRIMARY KEY, key text NOT NULL, value text NOT NULL,
                          worker_id text NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp());
GRANT SELECT, INSERT, UPDATE ON fake_resource, fake_effect TO ovlm_worker;
GRANT USAGE ON SEQUENCE fake_effect_id_seq TO ovlm_worker;
"""

#: Events that release ``block`` steps, by name (in-process tests only).
BLOCKERS: dict[str, threading.Event] = {}
#: Revoke callbacks observed (stand-in for "kill the Ansible process group").
REVOKED: list[tuple[str, str]] = []


class FakeCloud:
    def __init__(self, db: Engine, worker_id: str) -> None:
        self.db = db
        self.worker_id = worker_id

    def get(self, key: str) -> tuple[str | None, int]:
        with self.db.connect() as c:
            row = c.execute(
                text("SELECT value, pending_polls FROM fake_resource WHERE key = :k"), {"k": key}
            ).first()
        return (row[0], row[1]) if row else (None, 0)

    def put(self, ctx: StepContext, key: str, value: str, pending_polls: int = 0) -> None:
        """A mutating call: fence gate first, then the external write."""
        ctx.gate(f"openstack:PUT {key}")
        with self.db.begin() as c:
            c.execute(
                text(
                    "INSERT INTO fake_resource (key, value, pending_polls) VALUES (:k, :v, :p) "
                    "ON CONFLICT (key) DO UPDATE SET value = :v, pending_polls = :p"
                ),
                {"k": key, "v": value, "p": pending_polls},
            )
            c.execute(
                text("INSERT INTO fake_effect (key, value, worker_id) VALUES (:k, :v, :w)"),
                {"k": key, "v": value, "w": self.worker_id},
            )

    def land(self, key: str, value: str) -> None:
        """The effect of a request already sent (no gate: it is not a new call)."""
        with self.db.begin() as c:
            c.execute(
                text(
                    "INSERT INTO fake_resource (key, value) VALUES (:k, :v) "
                    "ON CONFLICT (key) DO UPDATE SET value = :v"
                ),
                {"k": key, "v": value},
            )
            c.execute(
                text("INSERT INTO fake_effect (key, value, worker_id) VALUES (:k, :v, :w)"),
                {"k": key, "v": value, "w": self.worker_id},
            )

    def progress(self, key: str) -> None:
        """The cloud's own progress on an async operation (not a call of ours: not gated)."""
        with self.db.begin() as c:
            c.execute(
                text(
                    "UPDATE fake_resource SET pending_polls = greatest(pending_polls - 1, 0) WHERE key = :k"
                ),
                {"k": key},
            )


class _CloudStep(Step):
    cloud: FakeCloud

    def __init__(self, cloud: FakeCloud) -> None:
        self.cloud = cloud


class SetStep(_CloudStep):
    """Idempotent set: probe shows whether the target value is already there (e.g. a lost response)."""

    key: ClassVar[str] = "set"

    def probe(self, ctx: StepContext) -> Any:
        return self.cloud.get(ctx.params["res"])[0]

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed == ctx.params["value"]:
            return Done({"already": True, "value": observed})
        return Act({"res": ctx.params["res"], "value": ctx.params["value"]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.cloud.put(ctx, intent["res"], intent["value"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        if self.cloud.get(intent["res"])[0] == intent["value"]:
            return Done({"value": intent["value"]})
        return Fail(ErrorClass.RETRYABLE, "value not visible yet")


class DestructiveSetStep(SetStep):
    key: ClassVar[str] = "set_destructive"
    destructive: ClassVar[bool] = True


class AsyncStep(_CloudStep):
    """Act starts an async operation; verify waits; each re-claim probes until the cloud finished."""

    key: ClassVar[str] = "async"

    def probe(self, ctx: StepContext) -> Any:
        value, pending = self.cloud.get(ctx.params["res"])
        if value == ctx.params["value"] and pending > 0:
            self.cloud.progress(ctx.params["res"])
        return self.cloud.get(ctx.params["res"])

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        value, pending = observed
        if value == ctx.params["value"]:
            return (
                Done({"polls_left": pending})
                if pending == 0
                else Wait(evidence={"pending": pending})
            )
        return Act({"res": ctx.params["res"], "value": ctx.params["value"]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.cloud.put(ctx, intent["res"], intent["value"], int(ctx.params.get("polls", 2)))

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        poll = ctx.params.get("poll_after")
        return Wait(poll_after=poll)


class FlakyStep(_CloudStep):
    """Fails retryably ``fail_times`` times (counted in the fake cloud), then succeeds."""

    key: ClassVar[str] = "flaky"

    def probe(self, ctx: StepContext) -> Any:
        value = self.cloud.get(ctx.params["res"])[0]
        return int(value or 0)

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        return Act({"n": observed + 1})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.cloud.put(ctx, ctx.params["res"], str(intent["n"]))

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        if intent["n"] <= int(ctx.params.get("fail_times", 1)):
            return Fail(ErrorClass.RETRYABLE, f"transient failure {intent['n']}")
        return Done({"tries": intent["n"]})


class FailStep(_CloudStep):
    key: ClassVar[str] = "fail"

    def probe(self, ctx: StepContext) -> Any:
        return None

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        return Fail(
            ErrorClass(ctx.params.get("cls", "fatal")),
            ctx.params.get("msg", "boom"),
            needs_human_reason=ctx.params.get("reason"),
        )

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:  # pragma: no cover
        raise AssertionError("never acts")

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError("never verifies")


class RaiseStep(_CloudStep):
    """Step code raising a plain exception: classified retryable by the default ``classify``."""

    key: ClassVar[str] = "raise"

    def probe(self, ctx: StepContext) -> Any:
        raise ValueError("probe exploded")

    def decide(self, ctx: StepContext, observed: Any) -> Decision:  # pragma: no cover
        raise AssertionError

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:  # pragma: no cover
        raise AssertionError

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError


class BlockStep(_CloudStep):
    """Acts only after ``BLOCKERS[name]`` is set, sleeping through ``ctx.sleep`` (heartbeats keep going).
    Registers a revoke callback, as the automation runner does for its process group."""

    key: ClassVar[str] = "block"

    def lease_for(self, params: Mapping[str, Any]) -> float | None:
        lease = params.get("lease")
        return float(lease) if lease is not None else None

    def probe(self, ctx: StepContext) -> Any:
        return self.cloud.get(ctx.params["res"])[0]

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed == ctx.params["value"]:
            return Done({"already": True})
        return Act({"res": ctx.params["res"], "value": ctx.params["value"]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        name = ctx.params["name"]
        ctx.fence.add_revoke_callback(lambda reason: REVOKED.append((name, reason)))
        ev = BLOCKERS.setdefault(name, threading.Event())
        while not ev.is_set():
            ctx.sleep(0.02)
        self.cloud.put(ctx, intent["res"], intent["value"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Done({"value": intent["value"]})


class InFlightStep(_CloudStep):
    """Destructive set whose request passes the gate, then stays "on the wire" until ``BLOCKERS[name]`` is
    set, and lands without any further check: the documented limit of fencing (WF-06)."""

    key: ClassVar[str] = "inflight"
    destructive: ClassVar[bool] = True

    def probe(self, ctx: StepContext) -> Any:
        return self.cloud.get(ctx.params["res"])[0]

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed == ctx.params["value"]:
            return Done({"already": True})
        return Act({"res": ctx.params["res"], "value": ctx.params["value"]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        ctx.gate(f"openstack:PUT {intent['res']}")  # sent before the deadline...
        BLOCKERS.setdefault(ctx.params["name"], threading.Event()).wait(30)
        self.cloud.land(
            intent["res"], intent["value"]
        )  # ...lands later, whatever happened meanwhile

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Done({"value": intent["value"]})


class HumanWaitStep(_CloudStep):
    """Waits with no timer until the fake resource says ``approved`` (woken by a signal)."""

    key: ClassVar[str] = "human"

    def probe(self, ctx: StepContext) -> Any:
        return self.cloud.get(ctx.params["res"])[0]

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed == "approved":
            return Done({"approved": True})
        return Wait(until_signal=True)

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:  # pragma: no cover
        raise AssertionError

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError


STEP_CLASSES: tuple[type[_CloudStep], ...] = (
    SetStep,
    DestructiveSetStep,
    AsyncStep,
    FlakyStep,
    FailStep,
    RaiseStep,
    BlockStep,
    InFlightStep,
    HumanWaitStep,
)


def plan_step(key: str, **params: Any) -> dict[str, Any]:
    meta: dict[str, Any] = {
        k: params.pop(k)
        for k in ("timeout", "destructive", "phase", "acquire_locks")
        if k in params
    }
    return {"key": key, "params": params, **meta}


def _spec(plan: list[dict[str, Any]], i: int) -> StepSpec:
    entry = plan[i]
    return StepSpec(
        step_key=entry["key"],
        params={**entry.get("params", {}), "_i": i},
        destructive=entry.get("destructive"),
        timeout=entry.get("timeout"),
    )


class DummyDefinition(WorkflowDefinition):
    kind: ClassVar[str] = "probe"  # a generic kind of data-model.md section 8
    strategy: ClassVar[str] = "dummy"
    version: ClassVar[str] = "1"

    def __init__(
        self, db: Engine, worker_id: str, *, cap: int | None = None, version: str | None = None,
        resumes: frozenset[str] = frozenset(),
    ) -> None:  # fmt: skip
        self.cloud = FakeCloud(db, worker_id)
        self._steps = {cls.key: cls(self.cloud) for cls in STEP_CLASSES}
        self._cap = cap
        if version is not None:
            self.version = version  # type: ignore[misc]
        self.resumes_versions = resumes  # type: ignore[misc]
        self.calls: list[str] = []

    @property
    def steps(self) -> Mapping[str, Step]:
        return self._steps

    def concurrency_cap(self) -> int | None:
        return self._cap

    def admit(self, ctx: TxContext) -> Admission | Reject | Defer:
        subject = ctx.run.subject
        if subject.get("reject"):
            return Reject(str(subject["reject"]))
        if subject.get("defer"):
            return Defer("test defer")
        return Admission(
            first_step=_spec(subject["plan"], 0),
            locks=[LockSpec(t, k, "test") for t, k in subject.get("locks", [])],
            phase=subject.get("phase"),
        )

    def next(self, ctx: TxContext, done: Done) -> Transition:
        assert ctx.step is not None
        plan = ctx.run.subject["plan"]
        i = int(ctx.step.params.get("_i", 0)) + 1
        if i >= len(plan):
            return Transition(run_state="completed")
        return Transition(
            next_step=_spec(plan, i),
            phase=plan[i].get("phase"),
            acquire_locks=[LockSpec(t, k, "test") for t, k in plan[i].get("acquire_locks", [])],
        )

    def on_failure(self, ctx: TxContext, fail: Fail) -> Transition | None:
        comp = ctx.run.subject.get("compensate_with")
        if comp and fail.error_class == ErrorClass.FATAL:
            return Transition(
                next_step=StepSpec(comp["key"], {**comp.get("params", {}), "_i": 10_000}),
                phase="restore",
            )
        return None

    def on_abort(self, ctx: TxContext, outcome: Outcome | None) -> Transition | None:
        self.calls.append("on_abort")
        if ctx.run.subject.get("abort_rolls_back"):
            return Transition(run_state="rolled_back")
        return Transition(run_state="cancelled")

    def validate_signal(self, ctx: TxContext) -> str | None:
        assert ctx.signal is not None
        return "denied by the test validator" if ctx.signal.payload.get("deny") else None

    def on_signal(self, ctx: TxContext) -> Transition | Wake | str | None:
        assert ctx.signal is not None
        kind = ctx.signal.kind
        if kind == "probe":
            return "probe recorded"
        if kind == "rollback":
            return Transition(run_state="rolled_back")
        if kind == "admit":
            return Wake()
        return None
