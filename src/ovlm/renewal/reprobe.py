"""The scheduler's re-probe of ``needs_human(api_unreachable)`` renewal runs (renewal-workflow.md 5, 5.1).

A periodic single-step run (every ``poll.max_interval``) inserts one system ``probe`` signal (no actor, payload
``auto=api_unreachable``) for each renewal run parked with ``api_unreachable`` that has no pending probe. The renewal
definition then does the read-only re-probe before its signal transaction (``prepare_signal``) and applies the
section 5.1 rules in the transaction that consumes the signal. This job itself calls no cloud.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from sqlalchemy import Engine, text

from ovlm.renewal.plans import KIND
from ovlm.workflow.contract import (
    Act,
    Admission,
    Decision,
    Defer,
    Done,
    Outcome,
    Reject,
    Step,
    StepContext,
    StepSpec,
    Transition,
    TxContext,
    WorkflowDefinition,
)
from ovlm.workflow.ids import new_id
from ovlm.workflow.registry import PeriodicJob

REPROBE_KIND = "probe"
REPROBE_STRATEGY = "renewal_reprobe"


class _Reprobe(Step):
    key = "renewal_reprobe"

    def __init__(self, db: Engine) -> None:
        self.db = db

    def probe(self, ctx: StepContext) -> Any:
        return None

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        return Act({"reprobe": True})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        ctx.gate("commit:reprobe")
        with self.db.begin() as c:
            rows = c.execute(
                text(
                    "SELECT r.id FROM workflow_run r WHERE r.kind = :k AND r.state = 'needs_human' "
                    "AND r.needs_human_reason = 'api_unreachable' AND NOT EXISTS (SELECT 1 FROM run_signal g "
                    "WHERE g.run_id = r.id AND g.kind = 'probe' AND g.consumed_at IS NULL)"
                ),
                {"k": KIND},
            ).scalars()
            for run_id in rows:
                c.execute(
                    text(
                        "INSERT INTO run_signal (id, run_id, kind, payload) VALUES (:i, :r, 'probe', CAST(:p AS jsonb))"
                    ),
                    {"i": new_id(), "r": run_id, "p": json.dumps({"auto": "api_unreachable"})},
                )

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Done({})


class RenewalReprobe(WorkflowDefinition):
    kind = REPROBE_KIND
    strategy = REPROBE_STRATEGY
    version = "1"

    def __init__(self, db: Engine) -> None:
        self._steps = {"renewal_reprobe": _Reprobe(db)}

    @property
    def steps(self) -> Mapping[str, Step]:
        return self._steps

    def admit(self, ctx: TxContext) -> Admission | Reject | Defer:
        return Admission(first_step=StepSpec("renewal_reprobe"))

    def next(self, ctx: TxContext, done: Done) -> Transition:
        return Transition(run_state="completed")

    def validate_signal(self, ctx: TxContext) -> str | None:
        return "this job takes no signals"


def periodic_job(interval: float) -> PeriodicJob:
    return PeriodicJob(kind=REPROBE_KIND, strategy=REPROBE_STRATEGY, version="1", interval=interval)
