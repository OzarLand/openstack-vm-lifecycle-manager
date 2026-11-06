"""Separation of duties rules, pure (security-model.md 3.2 and section 10 items 7, 20, 24)."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest

from ovlm.auth.sod import (
    DeciderFacts,
    Gate,
    RequesterSet,
    binding_conflicts,
    evaluate_eligibility,
)

ME = uuid4()
REQUESTER_ROLES = [
    "profile_version_author",
    "plan_creator",
    "run_starter",
    "policy_editor",
    "approval_requester",
]


def decider(
    *, operator: bool = False, allow: bool = False, human: bool = True, approver: bool = True
) -> DeciderFacts:
    return DeciderFacts(ME, human, approver, operator, allow)


def rset(role: str | None = None, user: UUID = ME) -> RequesterSet:
    others: dict[str, Any] = {r: uuid4() for r in REQUESTER_ROLES}
    if role:
        others[role] = user
    return RequesterSet(**others)


def test_an_unrelated_approver_may_approve_every_gate() -> None:
    for gate in Gate:
        e = evaluate_eligibility(gate, decider(), rset())
        assert e.allowed and not e.self_approved and not e.violations


@pytest.mark.parametrize("role", REQUESTER_ROLES)
@pytest.mark.parametrize("gate", list(Gate))
def test_requester_set_member_is_refused_by_default(role: str, gate: Gate) -> None:
    e = evaluate_eligibility(gate, decider(), rset(role))
    assert not e.allowed and not e.self_approved
    assert e.problem().status_code == 403 and e.problem().code == "sod-violation"
    assert role in e.problem().detail


def test_profile_version_author_approving_the_plan_is_refused() -> None:
    e = evaluate_eligibility(Gate.PLAN, decider(), rset("profile_version_author"))
    assert [v.code for v in e.violations] == ["sod-requester"]


@pytest.mark.parametrize("role", REQUESTER_ROLES)
@pytest.mark.parametrize("gate", [Gate.PLAN, Gate.CUTOVER, Gate.MANUAL_RECOVERY])
def test_with_the_setting_on_g1_g2_self_approval_is_allowed_and_flagged(
    role: str, gate: Gate
) -> None:
    e = evaluate_eligibility(gate, decider(allow=True), rset(role))
    assert e.allowed and e.self_approved and e.self_approval_reasons == (role,)


@pytest.mark.parametrize("role", [*REQUESTER_ROLES, None])
def test_retirement_self_approval_refused_even_with_the_setting_on(role: str | None) -> None:
    e = evaluate_eligibility(
        Gate.RETIREMENT, decider(allow=True, operator=role is None), rset(role)
    )
    assert not e.allowed and not e.self_approved
    assert "sod-retirement-self-approval" in {v.code for v in e.violations}


def test_operator_and_approver_in_scope_refused_by_default_flagged_when_allowed() -> None:
    e = evaluate_eligibility(Gate.PLAN, decider(operator=True), rset())
    assert not e.allowed and [v.code for v in e.violations] == ["sod-operator-approver"]
    e = evaluate_eligibility(Gate.CUTOVER, decider(operator=True, allow=True), rset())
    assert e.allowed and e.self_approved and e.self_approval_reasons == ("operator_and_approver",)


def test_solo_installation_cannot_retire_without_a_second_human() -> None:
    """One person: operator+approver (allowed), author of everything. G1 and G2 pass flagged; G3 never."""
    solo = RequesterSet(ME, ME, ME, ME, ME)
    for gate in (Gate.PLAN, Gate.CUTOVER):
        assert evaluate_eligibility(gate, decider(operator=True, allow=True), solo).self_approved
    g3 = evaluate_eligibility(
        Gate.RETIREMENT, decider(operator=True, allow=True), solo, prior_gate_deciders={ME}
    )
    assert not g3.allowed
    # a second human account holding only approver, not in the requester set and not the G1 decider: allowed
    second = DeciderFacts(uuid4(), True, True, False, True)
    ok = evaluate_eligibility(Gate.RETIREMENT, second, solo, prior_gate_deciders={ME})
    assert ok.allowed and not ok.self_approved


def test_retirement_needs_a_different_approver_than_earlier_gates_always() -> None:
    e = evaluate_eligibility(Gate.RETIREMENT, decider(), rset(), prior_gate_deciders={ME})
    assert [v.code for v in e.violations] == ["sod-distinct-approvers"]
    # plan/cutover: only when the policy asks for distinct approvers
    assert evaluate_eligibility(Gate.CUTOVER, decider(), rset(), prior_gate_deciders={ME}).allowed
    assert not evaluate_eligibility(
        Gate.CUTOVER, decider(), rset(), prior_gate_deciders={ME}, require_distinct_approvers=True
    ).allowed


def test_non_human_or_non_approver_is_refused_with_its_own_code() -> None:
    e = evaluate_eligibility(Gate.PLAN, decider(human=False), rset())
    assert e.problem().code == "human-session-required"
    e = evaluate_eligibility(Gate.PLAN, decider(approver=False), rset())
    assert e.problem().code == "forbidden"


@pytest.mark.parametrize(
    ("existing", "role", "scope", "conflicts"),
    [
        ([("approver", "global")], "operator", "project:a", ["global"]),
        ([("approver", "project:a")], "operator", "global", ["project:a"]),
        ([("approver", "project:a")], "operator", "project:a", ["project:a"]),
        ([("approver", "project:b")], "operator", "project:a", []),
        ([("operator", "project:a")], "approver", "project:a", ["project:a"]),
        ([("viewer", "global"), ("admin", "global")], "operator", "global", []),
        ([("operator", "global")], "viewer", "global", []),
        ([("operator", "global")], "admin", "global", []),
    ],
)
def test_binding_conflicts(
    existing: list[tuple[str, str]], role: str, scope: str, conflicts: list[str]
) -> None:
    assert binding_conflicts(existing, role, scope) == conflicts


@pytest.mark.parametrize(
    "role", ["profile_version_author", "plan_creator", "run_starter", "approval_requester"]
)
@pytest.mark.parametrize("allow", [False, True])
def test_sfr3_a_waiver_granter_who_also_asks_for_the_work_voids_the_gate_whatever_the_setting(
    role: str, allow: bool
) -> None:
    """Review SFR-3: a lint waiver granter is a requester of G1/G2; one who also asked for the work (author, plan
    creator, run starter, approval requester) makes the gate undecidable by anyone, setting on or off."""
    granter = uuid4()
    rs = RequesterSet(**{**{r: uuid4() for r in REQUESTER_ROLES}, role: granter},
                      lint_waiver_granters=frozenset({granter}))  # fmt: skip
    assert rs.waiver_granter_conflicts() == (role,)
    e = evaluate_eligibility(Gate.PLAN, decider(allow=allow), rs)
    assert not e.allowed and "sod-waiver-granter" in [v.code for v in e.violations]
    assert e.problem().code == "sod-violation"


@pytest.mark.parametrize("allow", [False, True])
def test_sfr3_a_waiver_granter_deciding_is_a_requester(allow: bool) -> None:
    rs = RequesterSet(**{r: uuid4() for r in REQUESTER_ROLES}, lint_waiver_granters=frozenset({ME}))
    assert rs.roles_of(ME) == ("lint_waiver_granter",) and ME in rs.members()
    assert rs.waiver_granter_conflicts() == ()
    e = evaluate_eligibility(Gate.PLAN, decider(allow=allow), rs)
    assert e.allowed is allow and e.self_approved is allow  # the usual rule for a requester
    assert not evaluate_eligibility(Gate.RETIREMENT, decider(allow=True), rs).allowed
