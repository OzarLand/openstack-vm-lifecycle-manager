"""Unit checks for the SRE engine review fixes that need no PostgreSQL (SRE-C-3, -4, -6, -9)."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import pytest
from sqlalchemy import create_engine, text

from ovlm.config import Settings
from ovlm.db.engine import pool_options
from ovlm.workflow.audit import AuditEvent, LogAuditSink
from ovlm.workflow.contract import Act, Decision, Done, ErrorClass, Fail, Outcome, Step, StepContext
from ovlm.workflow.engine import EngineConfig


class _LateCtx:
    def __init__(self, late: bool) -> None:
        self.deadline_passed = late
        self.log: list[str] = []
        self.params: Mapping[str, Any] = {}

    def gate(self, action: str) -> None:
        self.log.append(f"gate:{action}")

    def crashpoint(self, phase: str) -> None:
        self.log.append(f"cp:{phase}")


class _Acting(Step):
    key = "acting"

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        self.acted = False

    def probe(self, ctx: StepContext) -> Any:
        return None

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        return self.decision

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.acted = True

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Done()


def test_sre_c3_contract_never_acts_past_the_deadline() -> None:
    step = _Acting(Act({"x": 1}))
    persisted: list[Mapping[str, Any]] = []
    ctx = _LateCtx(late=True)
    out = step.run_contract(ctx, persisted.append)  # type: ignore[arg-type]
    assert isinstance(out, Fail) and out.error_class == ErrorClass.NEEDS_HUMAN
    assert out.needs_human_reason == "deadline_exceeded"
    assert not step.acted and persisted == [] and not any(x.startswith("gate:") for x in ctx.log)


def test_sre_c3_contract_late_but_goal_reached_is_done() -> None:
    out = _Acting(Done({"ok": 1})).run_contract(_LateCtx(late=True), lambda _i: None)  # type: ignore[arg-type]
    assert out == Done({"ok": 1})


@pytest.mark.parametrize("slots", [1, 4, 64])
def test_sre_c4_worker_pool_is_sized_from_slots_and_fails_fast(slots: int) -> None:
    s = Settings(process_role="worker", worker={"slots": slots})
    opts = pool_options(s)
    assert opts["pool_size"] >= 2 * slots + 4
    assert (
        opts["pool_timeout"] < s.worker.fence_margin
    )  # a starved heartbeat fails before the fence


def test_sre_c6_log_audit_is_emitted_only_after_commit(caplog: pytest.LogCaptureFixture) -> None:
    db = create_engine("sqlite://")
    sink = LogAuditSink()
    ev = AuditEvent(action="run.admitted", target_type="workflow_run", target_id="r1")
    caplog.set_level(logging.INFO, logger="ovlm.workflow.audit")
    with pytest.raises(RuntimeError), db.begin() as c:
        sink.record(c, ev)
        c.execute(text("SELECT 1"))
        raise RuntimeError("rolled back")
    assert not [r for r in caplog.records if getattr(r, "action", None) == "run.admitted"]
    with db.begin() as c:
        sink.record(c, ev)
        assert not [r for r in caplog.records if getattr(r, "action", None) == "run.admitted"]
    assert len([r for r in caplog.records if getattr(r, "action", None) == "run.admitted"]) == 1


def test_sre_c9_watchdog_interval_is_configurable_and_bounded_by_default() -> None:
    assert EngineConfig().watchdog_interval == 1.0
