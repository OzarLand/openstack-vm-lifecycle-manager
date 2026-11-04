"""Step contract template, transitions, crash-point harness, configuration and release safety checks."""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ovlm.config import Settings
from ovlm.workflow import crashpoint
from ovlm.workflow.contract import (
    Act,
    Decision,
    Done,
    ErrorClass,
    Fail,
    LockSpec,
    Outcome,
    Step,
    StepContext,
    StepSpec,
    Transition,
    Wait,
)
from ovlm.workflow.crashpoint import CrashPlan, SimulatedCrash
from ovlm.workflow.engine import EngineConfig, WorkflowEngine
from ovlm.workflow.ids import uuid7

ROOT = Path(__file__).parents[3]


class _Ctx:
    def __init__(self) -> None:
        self.log: list[str] = []
        self.params: Mapping[str, Any] = {}
        self.deadline_passed = False

    def gate(self, action: str) -> None:
        self.log.append(f"gate:{action}")

    def crashpoint(self, phase: str) -> None:
        self.log.append(f"cp:{phase}")


class _Recording(Step):
    key = "rec"

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        self.log: list[str] = []

    def probe(self, ctx: StepContext) -> Any:
        ctx.crashpoint  # noqa: B018
        self.log.append("probe")
        return "observed"

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        self.log.append(f"decide:{observed}")
        return self.decision

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.log.append(f"act:{dict(intent)}")

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        self.log.append("verify")
        return Done({"ok": True})


def test_contract_order_probe_decide_intent_gate_act_verify() -> None:
    step = _Recording(Act({"x": 1}))
    ctx = _Ctx()
    persisted: list[Mapping[str, Any]] = []

    def persist(intent: Mapping[str, Any]) -> None:
        persisted.append(intent)
        ctx.log.append("persist")

    out = step.run_contract(ctx, persist)  # type: ignore[arg-type]
    assert out == Done({"ok": True})
    assert step.log == ["probe", "decide:observed", "act:{'x': 1}", "verify"]
    assert ctx.log == [
        "cp:after_probe",
        "persist",
        "cp:after_intent",
        "gate:act:rec",
        "cp:after_act",
    ]
    assert persisted == [{"x": 1}]


@pytest.mark.parametrize(
    "decision",
    [Done({"already": True}), Wait(poll_after=3), Fail(ErrorClass.FATAL, "unexpected state")],
)
def test_goal_reached_or_unexpected_state_never_acts(decision: Decision) -> None:
    step = _Recording(decision)
    ctx = _Ctx()
    assert step.run_contract(ctx, lambda i: pytest.fail("intent persisted")) == decision  # type: ignore[arg-type]
    assert "act" not in " ".join(step.log)


def test_default_classification_is_retryable() -> None:
    fail = _Recording(Done()).classify(_Ctx(), RuntimeError("x"))  # type: ignore[arg-type]
    assert fail.error_class == ErrorClass.RETRYABLE and "RuntimeError" in fail.reason


def test_transition_requires_exactly_one_target_and_terminal_states() -> None:
    Transition(next_step=StepSpec("x"))
    Transition(run_state="completed")
    Transition(park_reason="ambiguous_state")
    with pytest.raises(ValueError):
        Transition()
    with pytest.raises(ValueError):
        Transition(next_step=StepSpec("x"), run_state="completed")
    with pytest.raises(ValueError):
        Transition(run_state="running")
    with pytest.raises(ValueError):
        LockSpec("network", "n1")


def test_crash_plan_parsing_and_occurrences() -> None:
    plan = CrashPlan.parse("set.after_act@2:raise")
    assert (plan.target, plan.occurrence, plan.mode) == ("set.after_act", 2, "raise")
    assert CrashPlan.parse("x").mode == "exit"
    with pytest.raises(ValueError):
        CrashPlan.parse("x:explode")
    crashpoint.install(plan)
    try:
        crashpoint.crashpoint("set.after_act")  # first occurrence: no crash
        crashpoint.crashpoint("other")
        with pytest.raises(SimulatedCrash):
            crashpoint.crashpoint("set.after_act")
        crashpoint.crashpoint("set.after_act")  # fires once only
    finally:
        crashpoint.install(None)
    assert not issubclass(SimulatedCrash, Exception)


def test_crashpoints_are_no_ops_by_default_and_recordable() -> None:
    crashpoint.install(None)
    crashpoint.crashpoint("anything")
    rec: list[str] = []
    crashpoint.record(rec)
    crashpoint.crashpoint("a")
    crashpoint.record(None)
    crashpoint.crashpoint("b")
    assert rec == ["a"]


def test_worker_refuses_to_start_with_a_crash_plan_in_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ovlm.worker import main

    monkeypatch.setenv(crashpoint.ENV_VAR, "set.after_act:exit")
    monkeypatch.setenv("OVLM_CONFIG_FILE", "/nonexistent")
    assert main.run(Settings(process_role="worker")) == 1


def test_release_artefacts_never_set_the_crash_plan_variable() -> None:
    for name in ("Dockerfile", "compose.yaml"):
        assert crashpoint.ENV_VAR not in (ROOT / name).read_text()


def test_worker_settings_validate_the_lease_relationships() -> None:
    Settings(process_role="worker")
    with pytest.raises(ValidationError, match="lease_duration"):
        Settings(process_role="worker", worker={"heartbeat_interval": 30, "lease_duration": 60})
    with pytest.raises(ValidationError, match="fence_margin"):
        Settings(process_role="worker", worker={"fence_margin": 58, "lease_duration": 60})
    with pytest.raises(ValidationError, match="takeover_delay"):
        Settings(process_role="worker", worker={"takeover_delay": 1, "fence_margin": 10})
    cfg = EngineConfig.from_settings(
        Settings(process_role="worker", retry={"max_attempts_per_step": {"detach_volume": 7}})
    )
    assert cfg.max_attempts("detach_volume") == 7 and cfg.max_attempts("other") == 3


def test_backoff_doubles_and_is_capped() -> None:
    eng = WorkflowEngine.__new__(WorkflowEngine)
    eng.config = EngineConfig(poll_initial=5, poll_max=60)
    delays = [eng._poll_delay(Wait(), n, None) for n in (0, 1, 2, 3, 4, 8)]  # noqa: SLF001
    assert delays == [5, 10, 20, 40, 60, 60]
    assert eng._poll_delay(Wait(poll_after=2.5), 9, None) == 2.5  # noqa: SLF001
    # SRE-C-5: never past the deadline
    assert eng._poll_delay(Wait(), 4, 12.0) == 12.0  # noqa: SLF001
    assert eng._poll_delay(Wait(poll_after=30), 0, 7.5) == 7.5  # noqa: SLF001
    assert eng._poll_delay(Wait(), 0, -3.0) == 0.0  # noqa: SLF001


def test_engine_never_computes_time_from_the_worker_wall_clock() -> None:
    """WF-20 (static part): leases and timers are DB-time only; the engine has no wall-clock calls."""
    src = (ROOT / "src/ovlm/workflow/engine.py").read_text()
    tree = ast.parse(src)
    calls = {
        f"{n.func.value.id}.{n.func.attr}"
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
    }
    assert not calls & {"time.time", "datetime.now", "datetime.utcnow", "date.today"}
    assert re.search(r"lease_expires_at = now\(\) \+", src)


def test_uuid7_is_time_ordered_and_versioned() -> None:
    ids = [uuid7() for _ in range(50)]
    assert all(u.version == 7 for u in ids)
    assert [u.int >> 80 for u in ids] == sorted(u.int >> 80 for u in ids)
