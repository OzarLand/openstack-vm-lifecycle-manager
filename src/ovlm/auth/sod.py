"""Separation of duties: requester sets, operator+approver, self-approval, approval-evidence re-validation.

Design: security-model.md 3.2, renewal-workflow.md 3 and 3.1, data-model.md 7 (``approval``), maintainer decision M9.

Two callers, one rule set (:func:`evaluate_eligibility`, pure):

* **The api** (E5-5 approval decision, lint waivers, exceptions) calls :func:`check_approval_eligibility` with the
  live principal and the requester set it computed from its own tables. A refusal is ``403 sod-violation``.
* **The worker** calls :func:`revalidate_approval_evidence` before every destructive step (B1, W1 claim, W2, W3, W5,
  W9, operator-triggered restore, X1). It re-derives the seven checks of renewal-workflow.md 3.1 from database
  facts **as of** ``decided_at`` (role-binding history, the consumed step-up record, the installation-setting
  history), never from the ``approval`` row's flags alone, so a later legitimate change (role revoked, user disabled,
  setting switched off) cannot trip a check during an outage.

What the caller provides: the plan/profile/policy/run tables belong to other modules, so the caller recomputes the
plan hash and the requester set (:class:`RecomputedFacts`) and this module checks them against the approval. This
module reads only auth-owned tables (``app_user``, ``role_binding``, ``stepup``, ``installation_setting``), which the
``ovlm_worker`` role may SELECT (data-model.md 12).

Rules (in force whatever any setting says):

* A requester-set member never approves that gate, unless the installation allows operator+approver
  (``allow_operator_approver``), the gate is G1 or G2, and the approval is then flagged ``self_approved``.
* Holding ``operator`` and ``approver`` in the approval's scope is the same case: refused by default; with the
  setting on, allowed for G1/G2 and flagged ``self_approved``.
* **G3 (retirement) never allows self-approval**: neither a requester-set member nor an operator+approver holder may
  decide it, and its decider differs from every earlier gate's decider of the run (two-person rule). A solo
  installation therefore needs a second human account holding only ``approver``.
"""

from __future__ import annotations

import hmac
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm.auth import installation
from ovlm.auth.authz import authorize, scope_covers
from ovlm.auth.errors import ProblemError
from ovlm.auth.principal import GLOBAL, Principal, canonical_scope

STEPUP_VALIDITY = timedelta(minutes=5)
INTERACTIVE_AUTH = "password+totp"


class Gate(StrEnum):
    PLAN = "plan"  # G1
    CUTOVER = "cutover"  # G2
    RETIREMENT = "retirement"  # G3
    MANUAL_RECOVERY = "manual_recovery"  # mark-resolved when the next step is destructive


#: Gates where an allowed self-approval may happen (flagged ``self_approved``). Never G3. Manual recovery is
#: treated like G2 (safest reading: it re-enters the destructive window the cutover approval covered).
SELF_APPROVAL_GATES = frozenset({Gate.PLAN, Gate.CUTOVER, Gate.MANUAL_RECOVERY})


@dataclass(frozen=True)
class RequesterSet:
    """security-model.md 3.2: the people who asked for, or shaped, what the gate approves. None of them approves it.

    ``None`` means "no such person" (e.g. no run yet at G1). The policy editor is the last editor of the policy
    version in effect.
    """

    profile_version_author: UUID | None = None
    plan_creator: UUID | None = None
    run_starter: UUID | None = None
    policy_editor: UUID | None = None
    approval_requester: UUID | None = None

    def members(self) -> frozenset[UUID]:
        return frozenset(u for u in self._pairs().values() if u is not None)

    def roles_of(self, user_id: UUID) -> tuple[str, ...]:
        """Which requester roles ``user_id`` plays (for error messages and the approval's evidence)."""
        return tuple(name for name, u in self._pairs().items() if u == user_id)

    def _pairs(self) -> dict[str, UUID | None]:
        return {
            "profile_version_author": self.profile_version_author,
            "plan_creator": self.plan_creator,
            "run_starter": self.run_starter,
            "policy_editor": self.policy_editor,
            "approval_requester": self.approval_requester,
        }

    def as_evidence(self) -> dict[str, str | None]:
        return {k: str(v) if v else None for k, v in self._pairs().items()}


@dataclass(frozen=True)
class Violation:
    code: str
    detail: str


@dataclass(frozen=True)
class Eligibility:
    allowed: bool
    #: The approval must be recorded with ``self_approved = true`` (only ever true when ``allowed``).
    self_approved: bool
    violations: tuple[Violation, ...] = ()
    #: Why self-approval applies (requester roles, ``operator_and_approver``), for the audit row and the UI.
    self_approval_reasons: tuple[str, ...] = ()

    def problem(self) -> ProblemError:
        """The 403 to answer when not allowed (``sod-violation`` unless a more basic check failed)."""
        codes = [v.code for v in self.violations]
        detail = " ".join(v.detail for v in self.violations)
        if "human-session-required" in codes:
            return ProblemError(403, "human-session-required", "Forbidden", detail)
        if "not-approver" in codes:
            return ProblemError(403, "forbidden", "Forbidden", detail)
        return ProblemError(
            403,
            "sod-violation",
            "Separation of duties",
            detail,
            next_action="Ask another person holding the approver role in this scope to decide.",
        )


@dataclass(frozen=True)
class DeciderFacts:
    """What is known about the person deciding, at decision time (live for the api, historical for the worker)."""

    user_id: UUID
    #: Human principal with an interactive password+TOTP session (never a token or the system principal).
    human_interactive: bool
    holds_approver: bool
    holds_operator: bool
    #: ``allow_operator_approver`` at decision time.
    allow_operator_approver: bool


def evaluate_eligibility(
    gate: Gate,
    decider: DeciderFacts,
    requester_set: RequesterSet,
    *,
    prior_gate_deciders: Collection[UUID] = (),
    require_distinct_approvers: bool = False,
) -> Eligibility:
    """The SoD rules, pure (shared by the api check and the worker's re-validation).

    ``prior_gate_deciders``: deciders of the run's earlier gates (G1, G2). G3's decider must differ from them
    always; other gates only when the policy's ``require_distinct_approvers`` is on.
    """
    violations: list[Violation] = []
    if not decider.human_interactive:
        violations.append(
            Violation(
                "human-session-required",
                "Approvals need an interactive human session with password and TOTP.",
            )
        )
    if not decider.holds_approver:
        violations.append(Violation("not-approver", "The approver role in this scope is required."))

    reasons = list(requester_set.roles_of(decider.user_id))
    if decider.holds_operator:
        reasons.append("operator_and_approver")
    self_approved = False
    if reasons:
        if gate is Gate.RETIREMENT:
            violations.append(
                Violation(
                    "sod-retirement-self-approval",
                    f"Retirement never allows self-approval ({', '.join(reasons)}); a second human holding only "
                    "the approver role must decide.",
                )
            )
        elif not decider.allow_operator_approver:
            violations.append(
                Violation(
                    "sod-requester"
                    if requester_set.roles_of(decider.user_id)
                    else "sod-operator-approver",
                    f"You may not approve this gate ({', '.join(reasons)}).",
                )
            )
        else:
            self_approved = True

    if decider.user_id in set(prior_gate_deciders) and (
        gate is Gate.RETIREMENT or require_distinct_approvers
    ):
        violations.append(
            Violation(
                "sod-distinct-approvers",
                "This gate needs a different approver from the run's earlier gates (two-person rule).",
            )
        )
    allowed = not violations
    return Eligibility(
        allowed=allowed,
        self_approved=allowed and self_approved,
        violations=tuple(violations),
        self_approval_reasons=tuple(reasons) if allowed and self_approved else (),
    )


def _holds(principal: Principal, role: str, scope: str) -> bool:
    """Direct binding of ``role`` covering ``scope`` (no lattice: operator is not implied by anything)."""
    return any(r == role and scope_covers(s, scope) for r, s in principal.grants)


def check_approval_eligibility(
    db: Session,
    principal: Principal,
    *,
    gate: Gate,
    scope: str,
    requester_set: RequesterSet,
    prior_gate_deciders: Collection[UUID] = (),
    require_distinct_approvers: bool = False,
) -> Eligibility:
    """The api's SoD check for a decision being made now (approval decision, lint waiver, exception grant).

    The caller (E5-5) computes the requester set from its own tables and, when ``allowed``, stores
    ``self_approved`` on the approval in the same transaction as the decision, then audits it. Raise
    ``result.problem()`` when not allowed. ``scope`` is the approval subject's ``project:<id>``.
    """
    facts = DeciderFacts(
        user_id=principal.user_id,
        human_interactive=principal.is_human and principal.auth_method == INTERACTIVE_AUTH,
        holds_approver=authorize(principal, "approver", scope),
        holds_operator=_holds(principal, "operator", scope),
        allow_operator_approver=installation.allow_operator_approver(db),
    )
    return evaluate_eligibility(
        gate,
        facts,
        requester_set,
        prior_gate_deciders=prior_gate_deciders,
        require_distinct_approvers=require_distinct_approvers,
    )


def account_provenance(db: Session, user_id: UUID) -> dict[str, Any]:
    """The decider's account origin for ``approval.account_provenance`` and the G3 page (SEC-R-11): who created the
    account and when, who last reset its credential and when. One person holding two accounts defeats the two-person
    rule; OVLM cannot prevent it, so it records this for an auditor."""
    row = db.execute(
        text(
            """
            SELECT u.created_via, u.created_at, c.username AS created_by, u.credential_reset_at,
                   r.username AS reset_by
            FROM app_user u
            LEFT JOIN app_user c ON c.id = u.created_by
            LEFT JOIN app_user r ON r.id = u.credential_reset_by
            WHERE u.id = :u
            """
        ),
        {"u": user_id},
    ).first()
    if row is None:
        return {}
    return {
        "created_via": row.created_via,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat(),
        "credential_reset_by": row.reset_by,
        "credential_reset_at": row.credential_reset_at.isoformat()
        if row.credential_reset_at
        else None,
    }


# --- role bindings: operator + approver in one scope ------------------------------------------------------------


def _overlap(a: str, b: str) -> bool:
    return GLOBAL in (a, b) or canonical_scope(a) == canonical_scope(b)


def binding_conflicts(existing: Collection[tuple[str, str]], role: str, scope: str) -> list[str]:
    """Scopes of existing bindings that would make the user hold operator and approver in a common scope."""
    other = {"operator": "approver", "approver": "operator"}.get(role)
    if other is None:
        return []
    return sorted({s for r, s in existing if r == other and _overlap(s, scope)})


def check_binding_sod(
    db: Session, existing: Collection[tuple[str, str]], role: str, scope: str
) -> None:
    """Refuse (409 ``sod-binding``) a binding that gives one person operator and approver in the same scope, unless
    the installation allows it (security-model.md 3.2, M9). Global overlaps every project."""
    conflicts = binding_conflicts(existing, role, scope)
    if conflicts and not installation.allow_operator_approver(db):
        raise ProblemError(
            409,
            "sod-binding",
            "Separation of duties",
            f"The user already holds the {'approver' if role == 'operator' else 'operator'} role in "
            f"{', '.join(conflicts)}; one person may not hold operator and approver in the same scope.",
            next_action="Give the role to another person, or have an admin allow operator+approver for the "
            "installation (approvals by such users are then flagged self-approved; retirement still needs a "
            "second person).",
        )


# --- worker: approval evidence re-validation (renewal-workflow.md 3.1) -------------------------------------------


@dataclass(frozen=True)
class ApprovalRecord:
    """The ``approval`` row as stored by the api (E5-5). Only data: none of its flags is trusted alone."""

    id: UUID
    gate: Gate
    scope: str
    bound_hash: str
    decision: str
    decided_by: UUID
    decided_at: datetime
    auth_method: str
    stepup_id: UUID | None
    typed_confirmation: str | None
    self_approved: bool
    expires_at: datetime | None
    void_reason: str | None = None


@dataclass(frozen=True)
class RecomputedFacts:
    """What the worker derives from its own tables (planning, profiles, policies, workflow), never from the row."""

    #: Plan hash recomputed from renewal_plan, profile_version, policy version and resolved ids.
    plan_hash: str
    requester_set: RequesterSet
    #: The step-up the decision must have consumed: action type and target (e.g. ``approval.decide`` + approval id).
    stepup_action: str
    stepup_target: str
    #: Target name + last 6 id characters as they were at ``decided_at``; ``None`` when the gate needs no TC (G1).
    expected_confirmation: str | None
    #: Deciders of the run's earlier gates (G1 for G2/G3, G2 for G3).
    prior_gate_deciders: frozenset[UUID] = frozenset()
    require_distinct_approvers: bool = False
    #: A revert happened after this approval (voids G3, SEC-R-8).
    revert_after_approval: bool = False
    #: The worker's clock, for G3 expiry.
    now: datetime | None = None


@dataclass(frozen=True)
class CheckOutcome:
    number: int
    name: str
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class EvidenceResult:
    ok: bool
    checks: tuple[CheckOutcome, ...]
    #: JSON-serialisable record of the facts used, for the step's ``evidence`` column.
    evidence: dict[str, Any] = field(default_factory=dict)

    def failures(self) -> list[CheckOutcome]:
        return [c for c in self.checks if not c.ok]


def role_held_at(db: Session, user_id: UUID, role: str, scope: str, at: datetime) -> bool:
    """Did ``user_id`` hold a direct binding of ``role`` covering ``scope`` at ``at`` (role-binding history)?"""
    return (
        db.execute(
            text(
                """
                SELECT 1 FROM role_binding
                WHERE user_id = :u AND role = :r AND (scope = 'global' OR scope = :s)
                  AND created_at <= :t AND (revoked_at IS NULL OR revoked_at > :t)
                LIMIT 1
                """
            ),
            {"u": user_id, "r": role, "s": scope, "t": at},
        ).first()
        is not None
    )


def _confirmation_equal(typed: str | None, expected: str) -> bool:
    if typed is None:
        return False
    return hmac.compare_digest(
        " ".join(typed.split()).encode(), " ".join(expected.split()).encode()
    )


def revalidate_approval_evidence(
    db: Session, approval: ApprovalRecord, facts: RecomputedFacts
) -> EvidenceResult:
    """The seven checks of renewal-workflow.md 3.1, evaluated as of ``approval.decided_at``.

    Any failed check means: ``needs_human(reason=approval_evidence_invalid)``, a security audit event, never
    proceed forward (the caller does that). Store ``result.evidence`` in the step evidence.
    """
    at = approval.decided_at
    checks: list[CheckOutcome] = []

    def add(number: int, name: str, ok: bool, detail: str = "") -> None:
        checks.append(CheckOutcome(number, name, ok, "" if ok else detail))

    # Preconditions of every check: an approval, not voided, of the gate the caller expects.
    add(
        0,
        "approved_not_voided",
        approval.decision == "approved" and approval.void_reason is None,
        f"decision={approval.decision!r}, void_reason={approval.void_reason!r}",
    )

    # 1. bound hash
    add(
        1,
        "bound_hash",
        hmac.compare_digest(approval.bound_hash.encode(), facts.plan_hash.encode()),
        "the approval's bound hash differs from the recomputed plan hash",
    )

    # Facts as of decided_at.
    user = db.execute(
        text("SELECT id, disabled_at FROM app_user WHERE id = :u"), {"u": approval.decided_by}
    ).first()
    user_active_then = user is not None and (user.disabled_at is None or user.disabled_at > at)
    held_approver = role_held_at(db, approval.decided_by, "approver", approval.scope, at)
    held_operator = role_held_at(db, approval.decided_by, "operator", approval.scope, at)
    allowed_then = installation.allow_operator_approver(db, at=at)
    decider = DeciderFacts(
        user_id=approval.decided_by,
        human_interactive=user_active_then and approval.auth_method == INTERACTIVE_AUTH,
        holds_approver=held_approver,
        holds_operator=held_operator,
        allow_operator_approver=allowed_then,
    )
    rules = evaluate_eligibility(
        approval.gate,
        decider,
        facts.requester_set,
        prior_gate_deciders=facts.prior_gate_deciders,
        require_distinct_approvers=facts.require_distinct_approvers,
    )
    codes = {v.code for v in rules.violations}
    requester_roles = facts.requester_set.roles_of(approval.decided_by)

    # 2. requester set (recomputed), self-approval only if allowed at decided_at and flagged, G1/G2 only
    ok2 = not requester_roles or (
        approval.gate in SELF_APPROVAL_GATES and allowed_then and approval.self_approved
    )
    add(2, "requester_set", ok2 and "sod-retirement-self-approval" not in codes,
        f"decider is {', '.join(requester_roles) or 'not in the requester set'}; self_approved="
        f"{approval.self_approved}, setting at decided_at={allowed_then}")  # fmt: skip

    # 3. approver in this scope at decided_at, human interactive principal
    add(3, "approver_human", held_approver and decider.human_interactive,
        f"approver at decided_at={held_approver}, interactive human={decider.human_interactive}")  # fmt: skip

    # 4. TOTP step-up: of the decider, bound to the action and target, consumed, issued <= 5 min before decided_at
    step = None
    if approval.stepup_id is not None:
        step = db.execute(
            text(
                "SELECT user_id, action, target_id, auth_method, created_at, expires_at, consumed_at "
                "FROM stepup WHERE id = :id"
            ),
            {"id": approval.stepup_id},
        ).first()
    ok4 = (
        step is not None
        and step.user_id == approval.decided_by
        and step.action == facts.stepup_action
        and step.target_id == facts.stepup_target
        and step.auth_method == INTERACTIVE_AUTH
        and step.consumed_at is not None
        and step.created_at <= at <= step.created_at + STEPUP_VALIDITY
        and step.created_at <= step.consumed_at <= step.expires_at
    )
    add(4, "stepup", ok4, "no consumed password+TOTP step-up of the decider for this action and target "
        "issued at most 5 minutes before the decision")  # fmt: skip

    # 5. typed confirmation as of decided_at
    ok5 = facts.expected_confirmation is None or _confirmation_equal(
        approval.typed_confirmation, facts.expected_confirmation
    )
    add(
        5,
        "typed_confirmation",
        ok5,
        "the typed confirmation does not match the target as of the decision",
    )

    # 6. operator + approver in this scope at decided_at
    ok6 = not held_operator or (
        approval.gate in SELF_APPROVAL_GATES and allowed_then and approval.self_approved
    )
    add(6, "operator_approver", ok6,
        f"decider also held operator in {approval.scope} at decided_at; setting then={allowed_then}, "
        f"self_approved={approval.self_approved}")  # fmt: skip

    # 7. G3: distinct from earlier deciders, never self-approved, no revert since, not expired
    if approval.gate is Gate.RETIREMENT:
        now = facts.now
        expired = approval.expires_at is None or now is None or not (now < approval.expires_at)
        ok7 = (
            "sod-distinct-approvers" not in codes
            and not approval.self_approved
            and not facts.revert_after_approval
            and not expired
        )
        add(7, "retirement", ok7,
            f"distinct={'sod-distinct-approvers' not in codes}, self_approved={approval.self_approved}, "
            f"revert_after={facts.revert_after_approval}, expired={expired}")  # fmt: skip
    else:
        add(7, "distinct_approvers", "sod-distinct-approvers" not in codes,
            "the policy requires a different approver from the earlier gates")  # fmt: skip

    # The self_approved flag may only be set where the setting allowed it at decided_at (data-model.md 7).
    if approval.self_approved and not (allowed_then and approval.gate in SELF_APPROVAL_GATES):
        add(
            2,
            "self_approved_flag",
            False,
            "flagged self_approved but self-approval was not allowed then",
        )

    result_checks = tuple(checks)
    evidence = {
        "approval_id": str(approval.id),
        "gate": approval.gate.value,
        "decided_by": str(approval.decided_by),
        "decided_at": at.isoformat(),
        "scope": approval.scope,
        "requester_set": facts.requester_set.as_evidence(),
        "held_approver": held_approver,
        "held_operator": held_operator,
        "allow_operator_approver_at_decision": allowed_then,
        "self_approved": approval.self_approved,
        "stepup_id": str(approval.stepup_id) if approval.stepup_id else None,
        "checks": {f"{c.number}:{c.name}": c.ok for c in result_checks},
    }
    return EvidenceResult(all(c.ok for c in result_checks), result_checks, evidence)
