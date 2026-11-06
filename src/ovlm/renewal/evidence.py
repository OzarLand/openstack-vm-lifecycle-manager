"""Approval evidence re-validation for the worker (renewal-workflow.md 3.1, SEC-R-1, SEC-R-2) - api-safe module.

The worker never trusts an ``approval`` row as a flag. For a gate it finds the latest approved, not voided approval
of the subject and re-derives the seven checks through :func:`ovlm.auth.sod.revalidate_approval_evidence`, giving it
facts recomputed here from the plan, profile version, policy and run (never the row's own ``requester_set`` or
``bound_hash`` as truth).

Operator-confirmed cutover (policy ``approvals.cutover = false``): the G2 "approval" is the operator's cutover request
with TOTP step-up and TC in a human session. It has no approver, so the checks are: bound hash, a human interactive
operator in scope at ``decided_at``, the consumed step-up (``run.cutover`` on the run), and the TC.

Step-up conventions (shared with the api): an approval decision consumes a step-up with action
``approval.decide`` and target the approval id; an operator cutover confirmation ``run.cutover`` on the run id.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, RowMapping, text
from sqlalchemy.orm import Session

from ovlm.auth.sod import (
    INTERACTIVE_AUTH,
    STEPUP_VALIDITY,
    ApprovalRecord,
    CheckOutcome,
    EvidenceResult,
    Gate,
    RecomputedFacts,
    check_waivers,
    revalidate_approval_evidence,
    role_held_at,
)
from ovlm.profiles.waivers import plan_requesters
from ovlm.renewal.plans import PlanFacts, tc_of

APPROVAL_STEPUP_ACTION = "approval.decide"
CUTOVER_STEPUP_ACTION = "run.cutover"

#: Steps whose existence after a G3 decision means a revert happened (SEC-R-8): the restore sequence.
_RESTORE_KEYS = (
    "unlock_old",
    "quiesce_green",
    "stop_green",
    "detach_from_green",
    "attach_to_old",
    "boot_old",
)


@dataclass(frozen=True)
class GateCheck:
    ok: bool
    reason: str
    approval_id: str | None
    evidence: Mapping[str, Any]


def subject_for(gate: Gate, *, plan_id: str, run_id: str) -> str:
    return plan_id if gate is Gate.PLAN else run_id


def latest_approved(conn: Connection, gate: Gate, subject_id: str) -> RowMapping | None:
    return (
        conn.execute(
            text(
                "SELECT * FROM approval WHERE subject_type = :t AND subject_id = :s AND decision = 'approved' "
                "AND void_reason IS NULL ORDER BY decided_at DESC, id DESC LIMIT 1"
            ),
            {"t": gate.value, "s": subject_id},
        )
        .mappings()
        .first()
    )


def _voided_by_run(conn: Connection, run_id: str, approval: Mapping[Any, Any]) -> bool:
    """Voids the worker derives instead of writing (it has no UPDATE on ``approval``): a restore after a G3 decision
    (SEC-R-8) and an X1 precondition mismatch that names this approval."""
    if approval["subject_type"] != Gate.RETIREMENT.value:
        return False
    row = conn.execute(
        text(
            "SELECT 1 FROM workflow_step WHERE run_id = :r AND ("
            "  (step_key = ANY(:keys) AND created_at >= :t) OR (error ->> 'voids_approval') = :a) LIMIT 1"
        ),
        {
            "r": run_id,
            "keys": list(_RESTORE_KEYS),
            "t": approval["decided_at"],
            "a": str(approval["id"]),
        },
    ).first()
    return row is not None


def check_gate(
    conn: Connection,
    gate: Gate,
    facts: PlanFacts,
    *,
    run_id: str,
    run_starter: UUID | None,
    now: datetime,
    check_expiry: bool,
) -> GateCheck:
    """Re-validate the evidence of ``gate`` for this run. ``check_expiry``: G2 at the W1 claim only (an approval
    never expires mid-outage), G1 at B1; G3 always (check 7)."""
    subject = subject_for(gate, plan_id=facts.plan_id, run_id=run_id)
    row = latest_approved(conn, gate, subject)
    if row is None:
        return GateCheck(False, "no_approval", None, {"gate": gate.value, "subject": subject})
    aid = str(row["id"])
    if facts.recomputed_hash is None:
        return GateCheck(False, "plan_sources_missing", aid, {"gate": gate.value})
    if check_expiry and (row["expires_at"] is None or not now < row["expires_at"]):
        return GateCheck(
            False,
            "approval_expired",
            aid,
            {"gate": gate.value, "expires_at": str(row["expires_at"])},
        )
    if _voided_by_run(conn, run_id, row):
        return GateCheck(False, "approval_voided", aid, {"gate": gate.value})
    blue = facts.resolved["blue"]
    expected_tc = None if gate is Gate.PLAN else tc_of(blue["name"], blue["server_id"])
    if row["operator_confirmed"]:
        result = _operator_cutover(conn, row, facts, run_id=run_id, expected_tc=expected_tc or "")
    else:
        prior: set[UUID] = set()
        for earlier in (Gate.PLAN, Gate.CUTOVER) if gate is Gate.RETIREMENT else (Gate.PLAN,):
            if earlier is gate:
                continue
            e = latest_approved(
                conn, earlier, subject_for(earlier, plan_id=facts.plan_id, run_id=run_id)
            )
            if e is not None and e["decided_by"] and not e["operator_confirmed"]:
                prior.add(e["decided_by"])
        record = ApprovalRecord(
            id=row["id"],
            gate=gate,
            scope=row["scope"],
            bound_hash=row["bound_hash"],
            decision=row["decision"],
            decided_by=row["decided_by"],
            decided_at=row["decided_at"],
            auth_method=row["auth_method"] or "",
            stepup_id=row["stepup_id"],
            typed_confirmation=row["typed_confirmation"],
            self_approved=bool(row["self_approved"]),
            expires_at=row["expires_at"],
            void_reason=row["void_reason"],
        )
        recomputed = RecomputedFacts(
            plan_hash=facts.recomputed_hash,
            requester_set=facts.requester_set(
                run_starter=run_starter, approval_requester=row["requested_by"], gate=gate
            ),
            stepup_action=APPROVAL_STEPUP_ACTION,
            stepup_target=aid,
            expected_confirmation=expected_tc,
            prior_gate_deciders=frozenset(prior) if gate is not Gate.PLAN else frozenset(),
            require_distinct_approvers=bool((facts.policy or {}).get("require_distinct_approvers")),
            revert_after_approval=False,  # derived above (_voided_by_run)
            now=now,
            lint_waivers=facts.waiver_records,
            waiver_requesters=plan_requesters(conn, UUID(str(facts.plan["profile_version_id"]))),
        )
        with Session(bind=conn) as session:
            result = revalidate_approval_evidence(session, record, recomputed)
    failures = [f"{c.number}:{c.name}" for c in result.failures()]
    return GateCheck(
        result.ok,
        "ok" if result.ok else "approval_evidence_invalid",
        aid,
        {**result.evidence, "failures": failures},
    )


def _operator_cutover(
    conn: Connection, row: Mapping[Any, Any], facts: PlanFacts, *, run_id: str, expected_tc: str
) -> EvidenceResult:
    import hmac

    at = row["decided_at"]
    checks: list[CheckOutcome] = []
    checks.append(
        CheckOutcome(
            0, "approved_not_voided", row["decision"] == "approved" and not row["void_reason"]
        )
    )
    checks.append(
        CheckOutcome(
            1, "bound_hash", hmac.compare_digest(row["bound_hash"], facts.recomputed_hash or "")
        )
    )
    user = conn.execute(
        text("SELECT disabled_at FROM app_user WHERE id = :u"), {"u": row["decided_by"]}
    ).first()
    active = user is not None and (user.disabled_at is None or user.disabled_at > at)
    with Session(bind=conn) as session:
        operator = role_held_at(session, row["decided_by"], "operator", row["scope"], at)
    checks.append(
        CheckOutcome(
            3, "operator_human", operator and active and row["auth_method"] == INTERACTIVE_AUTH
        )
    )
    step = None
    if row["stepup_id"] is not None:
        step = conn.execute(
            text(
                "SELECT user_id, action, target_id, auth_method, created_at, consumed_at FROM stepup WHERE id = :i"
            ),
            {"i": row["stepup_id"]},
        ).first()
    ok4 = (
        step is not None
        and step.user_id == row["decided_by"]
        and step.action == CUTOVER_STEPUP_ACTION
        and step.target_id == run_id
        and step.auth_method == INTERACTIVE_AUTH
        and step.consumed_at is not None
        and step.created_at <= at <= step.created_at + STEPUP_VALIDITY
    )
    checks.append(CheckOutcome(4, "stepup", ok4))
    typed = " ".join((row["typed_confirmation"] or "").split())
    checks.append(CheckOutcome(5, "typed_confirmation", hmac.compare_digest(typed, expected_tc)))
    with Session(
        bind=conn
    ) as session:  # review SFR-1: the waivers the hash binds were really granted
        bad_waivers = check_waivers(
            session, facts.waiver_records, scope=row["scope"], author=facts.profile_author,
            requesters=plan_requesters(conn, UUID(str(facts.plan["profile_version_id"]))),
        )  # fmt: skip
    checks.append(CheckOutcome(8, "lint_waivers", not bad_waivers))
    ok = all(c.ok for c in checks)
    return EvidenceResult(
        ok,
        tuple(checks),
        {
            "approval_id": str(row["id"]),
            "gate": "cutover",
            "operator_confirmed": True,
            "decided_by": str(row["decided_by"]),
            "decided_at": at.isoformat(),
            "checks": {f"{c.number}:{c.name}": c.ok for c in checks},
            "lint_waivers": bad_waivers,
        },
    )
