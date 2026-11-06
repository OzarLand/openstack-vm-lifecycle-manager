"""AU-1: a full renewal in the fake world, then ``audit.visible_events(run=...)`` shows the whole trail: the API's
``run.start``, the plan's G1 decision, the G2 and G3 decisions, and the engine's step claims and outcomes in order."""

from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.audit.view import visible_events
from ovlm.auth.principal import Principal
from ovlm.workflow.audit import DbAuditSink
from ovlm.workflow.ids import new_id
from tests.integration.renewal.conftest import World, explain


def principal(w: World, role: str, scope: str) -> Principal:
    return Principal(
        user_id=UUID(w.users["op"]), username="viewer-x", principal_type="human", auth_method="password+totp",
        grants=frozenset({(role, scope)}),
    )  # fmt: skip


def api_event(w: World, action: str, target_type: str, target_id: str, **after: str) -> None:
    """What the API records (``ovlm.renewal.service._audit``) when the request comes in; the world's helpers write
    the rows directly, so the test records the audit rows next to them."""
    with Session(w.api) as s:
        audit.record(
            s, action=action, target_type=target_type, target_id=target_id, actor_id=UUID(w.users["op"]),
            auth_method="password+totp", project_scope=w.ids["scope"], after=after or None,
        )  # fmt: skip
        s.commit()


def approval_id(w: World, subject_type: str) -> str:
    return str(
        w.q(
            "SELECT id FROM approval WHERE plan_id = :p AND subject_type = :t",
            p=w.ids["plan"],
            t=subject_type,
        )[0]["id"]
    )


def trail(w: World, who: Principal) -> list[audit.AuditRow]:
    with Session(w.api) as s:
        page = visible_events(s, who, run_id=UUID(w.run_id), limit=200)
    assert page.next_cursor is None
    return sorted(page.items, key=lambda r: r.id)


def test_run_trail_has_start_gates_and_step_claims_and_outcomes_in_order(world: World) -> None:
    w = world
    w.audit = DbAuditSink()  # type: ignore[assignment]  # what the worker wires
    api_event(
        w, "approval.decide", "approval", approval_id(w, "plan"), subject_type="plan"
    )  # G1, before any run
    w.start()
    api_event(w, "run.start", "renewal_run", w.run_id, plan_id=w.ids["plan"])
    w.drive(until="await_cutover")
    w.approve("cutover")
    api_event(w, "approval.decide", "approval", approval_id(w, "cutover"), subject_type="cutover")
    r = w.drive(until="await_retirement")
    assert r["state"] == "running", explain(w)
    w.approve("retirement", decider="ap2")
    api_event(
        w, "approval.decide", "approval", approval_id(w, "retirement"), subject_type="retirement"
    )
    assert w.drive()["state"] == "completed", explain(w)

    rows = trail(w, principal(w, "operator", w.ids["scope"]))
    actions = [r.action for r in rows]
    decisions = [r.target_id for r in rows if r.action == "approval.decide"]
    assert decisions == [approval_id(w, t) for t in ("plan", "cutover", "retirement")]  # G1, G2, G3
    assert (
        actions.index("approval.decide")
        < actions.index("run.start")
        < actions.index("run.admitted")
    )
    assert actions[-1] == "run.completed"

    step_keys = w.keys()
    engine_rows = [
        (r.action, (r.after or {})["step_key"], (r.after or {}).get("state"))
        for r in rows
        if r.action in ("step.claim", "step.outcome")
    ]
    # strictly claim, outcome, claim, outcome ...: one row per claim and one per outcome, never a heartbeat; a waiting
    # step is claimed once per poll attempt, so it may repeat, but the steps run in the engine's order
    assert [a for a, _, _ in engine_rows] == ["step.claim", "step.outcome"] * (
        len(engine_rows) // 2
    )
    assert all(c[1] == o[1] for c, o in zip(engine_rows[::2], engine_rows[1::2], strict=True))
    claimed = [k for a, k, _ in engine_rows if a == "step.claim"]
    assert [k for i, k in enumerate(claimed) if i == 0 or claimed[i - 1] != k] == step_keys
    finals = {k: st for a, k, st in engine_rows if a == "step.outcome"}
    assert set(finals) == set(step_keys) and all(finals[k] == "succeeded" for k in step_keys)
    assert all(
        r.step_id and r.run_id == UUID(w.run_id) and r.principal_type == "worker"
        for r in rows
        if r.action.startswith("step.")
    )
    # the volume stays sane: no heartbeat or polling rows
    assert not [a for a in actions if "heartbeat" in a or "lease" in a]
    # allowlisted fields only, never the fencing token or anything secret-looking
    blob = json.dumps([r.after for r in rows]).lower()
    assert "fencing" not in blob and "password" not in blob and "secret" not in blob

    # scoping: another project sees nothing, a worker row without scope is not leaked
    assert trail(w, principal(w, "viewer", "project:" + new_id())) == []
    # and the recorded rows follow the run's project for a project-scoped viewer
    assert {r.id for r in trail(w, principal(w, "viewer", w.ids["scope"]))} == {r.id for r in rows}
