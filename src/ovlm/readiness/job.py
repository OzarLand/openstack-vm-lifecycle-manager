"""The ``readiness`` workflow (worker side): one step that builds the snapshot, runs the checks and stores the result.

It reads the DB inventory only: no OpenStack call, no SSH, no repository code (SEC-R-28). Its single step
follows the step contract, so a crash at any point is safe to retry:

* ``probe``   is there already an assessment for this run? (a previous attempt committed it)
* ``decide``  yes: ``Done``; no: ``Act`` (nothing external is mutated)
* ``act``     build the snapshot, run the checks, insert the assessment and its results **in one transaction**
              (``workflow_run_id`` is UNIQUE, so a replay inserts nothing)
* ``verify``  the assessment row exists

The run itself only needs one step; the engine owns leases, retries and the run's terminal state.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any, ClassVar
from uuid import UUID

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.readiness.model import CheckResult
from ovlm.readiness.runner import run_checks
from ovlm.readiness.service import KIND, STRATEGY, STRATEGY_VERSION
from ovlm.readiness.snapshot import build_snapshot
from ovlm.workflow.contract import (
    Act,
    Admission,
    Decision,
    Defer,
    Done,
    ErrorClass,
    Fail,
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

log = logging.getLogger("ovlm.readiness.job")

ASSESS = "assess"


def store_assessment(
    engine: Engine, run_id: str, managed_vm_id: UUID, requested_by: str | None
) -> dict[str, Any] | None:
    """Build, evaluate and store in one transaction. Returns the stored summary, or ``None`` when the VM is gone."""
    with Session(engine) as session:
        snapshot = build_snapshot(session, managed_vm_id)
        if snapshot is None:
            return None
        level, summary, results = run_checks(snapshot)
        profile = snapshot["profile"]
        server = snapshot["server"]
        assessment_id = new_id()
        inserted = session.execute(
            text(
                "INSERT INTO readiness_assessment (id, managed_vm_id, profile_version_id, "
                "observed_server_revision_id, input_snapshot, level, summary, requested_by, workflow_run_id) "
                "VALUES (:id, :vm, :pv, :rev, CAST(:snap AS jsonb), :level, CAST(:summary AS jsonb), :by, :run) "
                "ON CONFLICT (workflow_run_id) DO NOTHING RETURNING id"
            ),
            {
                "id": assessment_id, "vm": str(managed_vm_id), "pv": profile["version_id"] if profile else None,
                "rev": server["revision_id"] if server else None, "snap": json.dumps(snapshot),
                "level": level.value, "summary": json.dumps(summary), "by": requested_by, "run": run_id,
            },
        ).first()  # fmt: skip
        if inserted is None:  # a previous attempt already committed it
            session.rollback()
            return {"assessment_id": None, "replayed": True}
        for seq, r in enumerate(results):
            _insert_result(session, assessment_id, seq, r)
        audit.record(
            session, action="readiness.assessment.complete", target_type="readiness_assessment",
            target_id=assessment_id, actor_id=None, principal_type="worker", auth_method="system",
            run_id=UUID(run_id), project_scope=None,
        )  # fmt: skip
        session.commit()
        return {"assessment_id": assessment_id, "level": level.value, "summary": summary["text"]}


def _insert_result(session: Session, assessment_id: str, seq: int, r: CheckResult) -> None:
    session.execute(
        text(
            "INSERT INTO check_result (id, assessment_id, check_key, check_version, category, result, severity, "
            "evidence, recommendation, seq) VALUES (:id, :a, :key, :ver, :cat, :res, :sev, CAST(:ev AS jsonb), "
            ":rec, :seq)"
        ),
        {
            "id": new_id(), "a": assessment_id, "key": r.key, "ver": r.version, "cat": r.category.value,
            "res": r.result.value, "sev": r.severity.value, "ev": json.dumps(r.evidence),
            "rec": r.recommendation, "seq": seq,
        },
    )  # fmt: skip


class AssessStep(Step):
    key: ClassVar[str] = ASSESS

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def probe(self, ctx: StepContext) -> Any:
        with ctx.read() as conn:
            row = conn.execute(
                text("SELECT id, level FROM readiness_assessment WHERE workflow_run_id = :r"),
                {"r": ctx.run.id},
            ).first()
        return {"assessment_id": str(row.id), "level": row.level} if row else None

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed is not None:
            return Done({**observed, "already": True})
        if not ctx.run.subject.get("managed_vm_id"):
            return Fail(ErrorClass.FATAL, "the run names no managed VM")
        return Act({"managed_vm_id": ctx.run.subject["managed_vm_id"]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        # Nothing outside the database is touched, so there is no fence gate to pass beyond the engine's own.
        stored = store_assessment(
            self.engine, ctx.run.id, UUID(intent["managed_vm_id"]), ctx.run.started_by
        )
        if stored is None:
            raise _VmGone(intent["managed_vm_id"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        found = self.probe(ctx)
        if found is None:
            return Fail(ErrorClass.RETRYABLE, "the assessment is not visible yet")
        return Done(found)

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        if isinstance(exc, _VmGone):
            return Fail(ErrorClass.FATAL, "the managed VM no longer exists")
        return super().classify(ctx, exc)


class _VmGone(Exception):
    pass


class ReadinessDefinition(WorkflowDefinition):
    kind: ClassVar[str] = KIND
    strategy: ClassVar[str] = STRATEGY
    version: ClassVar[str] = STRATEGY_VERSION

    def __init__(self, engine: Engine) -> None:
        self._steps = {ASSESS: AssessStep(engine)}

    @property
    def steps(self) -> Mapping[str, Step]:
        return self._steps

    def admit(self, ctx: TxContext) -> Admission | Reject | Defer:
        if not ctx.run.subject.get("managed_vm_id"):
            return Reject("the run names no managed VM")
        if ctx.run.subject.get("run_repo_code_on_live_vm"):
            return Reject("running repository code on the live VM is not available in this release")
        return Admission(StepSpec(ASSESS, timeout=300.0))

    def next(self, ctx: TxContext, done: Done) -> Transition:
        return Transition(run_state="completed")

    def validate_signal(self, ctx: TxContext) -> str | None:
        return "readiness runs accept no signals"
