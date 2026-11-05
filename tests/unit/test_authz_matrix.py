"""RBAC matrix of security-model.md 3.1 as a table-driven test (section 10 item 5), plus scoping and token rules.

``EXPECTED`` is copied by hand from the design table, independently of ``ovlm.auth.authz.MATRIX``: every
role × every action, allowed and denied.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from ovlm.auth.authz import (
    MATRIX,
    Action,
    ScopeDecision,
    action_scopes,
    authorize_action,
    decide_in_scope,
    project_visible,
    visible_projects,
)
from ovlm.auth.principal import Principal

V, O, AP, AD = "viewer", "operator", "approver", "admin"  # noqa: E741

#: security-model.md 3.1, row by row ("request" and "✓ + TC" count as allowed; V1 rows included).
EXPECTED: dict[Action, set[str]] = {
    Action.INVENTORY_VIEW: {V, O, AP, AD},
    Action.INVENTORY_SYNC: {O, AD},
    Action.REGISTRY_MANAGE: {O},
    Action.HOST_KEY_CONFIRM: {O},  # ADR-0006, security-model.md 3.1
    Action.PROFILE_EDIT: {O},
    Action.AUTOMATION_REPO_MANAGE: {AD},
    Action.POLICY_EDIT: {AD},
    Action.EXCEPTION_REQUEST: {O},
    Action.EXCEPTION_GRANT: {AP},
    Action.READINESS_RUN: {O},
    Action.READINESS_ATTEST: {O, AP},
    Action.PLAN_CREATE: {O},
    Action.APPROVAL_DECIDE: {AP},
    Action.LINT_WAIVER_GRANT: {AP},  # api-design.md 3.3
    Action.RUN_OPERATE: {O},
    Action.RUN_REVERT: {O},
    Action.RUN_MARK_RESOLVED: {O, AP},
    Action.AUTOMATION_ARTEFACT_VIEW: {O, AD},  # security-model.md 5.2
    Action.AUDIT_VIEW: {V, O, AP, AD},
    Action.AUDIT_EXPORT: {AD},
    Action.CREDENTIAL_MANAGE: {AD},
    Action.USER_MANAGE: {AD},
    Action.SETTINGS_MANAGE: {AD},  # api-design.md 3.8
    Action.TOKEN_CREATE_OWN: {V, O, AP, AD},
}
HUMAN_ONLY = {
    Action.APPROVAL_DECIDE, Action.LINT_WAIVER_GRANT, Action.EXCEPTION_GRANT, Action.USER_MANAGE,
    Action.CREDENTIAL_MANAGE, Action.SETTINGS_MANAGE, Action.POLICY_EDIT, Action.AUTOMATION_REPO_MANAGE,
    Action.AUDIT_EXPORT, Action.TOKEN_CREATE_OWN, Action.RUN_REVERT, Action.RUN_MARK_RESOLVED,
    Action.READINESS_ATTEST, Action.HOST_KEY_CONFIRM,
}  # fmt: skip
P1, P2 = uuid4(), uuid4()


def human(*grants: tuple[str, str]) -> Principal:
    return Principal(uuid4(), "u", "human", "password+totp", frozenset(grants))


def token(scopes: set[str], *grants: tuple[str, str]) -> Principal:
    return Principal(
        uuid4(), "t", "token", "token", frozenset(grants), token_scopes=frozenset(scopes)
    )


def test_expected_table_covers_every_action() -> None:
    assert set(EXPECTED) == set(Action) == set(MATRIX)


@pytest.mark.parametrize("action", list(Action), ids=lambda a: a.value)
@pytest.mark.parametrize("role", [V, O, AP, AD])
def test_matrix_cell(role: str, action: Action) -> None:
    allowed = role in EXPECTED[action]
    assert authorize_action(human((role, "global")), action) is allowed
    assert authorize_action(human((role, "global")), action, f"project:{P1}") is allowed


@pytest.mark.parametrize("action", list(Action), ids=lambda a: a.value)
def test_admin_does_not_inherit_operator_or_approver(action: Action) -> None:
    if AD not in EXPECTED[action]:
        assert not authorize_action(human((AD, "global")), action)


def test_project_binding_covers_only_its_project() -> None:
    p = human((O, f"project:{P1}"))
    assert authorize_action(p, Action.REGISTRY_MANAGE, f"project:{P1}")
    assert not authorize_action(p, Action.REGISTRY_MANAGE, f"project:{P2}")
    assert not authorize_action(p, Action.REGISTRY_MANAGE, "global")
    assert authorize_action(p, Action.REGISTRY_MANAGE)  # "in some scope": lists then filter


def test_404_versus_403() -> None:
    p = human((V, f"project:{P1}"), (O, f"project:{P2}"))
    assert decide_in_scope(p, Action.REGISTRY_MANAGE, f"project:{P2}") is ScopeDecision.ALLOWED
    assert decide_in_scope(p, Action.REGISTRY_MANAGE, f"project:{P1}") is ScopeDecision.FORBIDDEN
    assert (
        decide_in_scope(p, Action.REGISTRY_MANAGE, f"project:{uuid4()}") is ScopeDecision.NOT_FOUND
    )


def test_visible_projects_for_list_filtering() -> None:
    assert visible_projects(human((V, "global"), (O, f"project:{P1}"))) is None
    assert visible_projects(human((V, f"project:{P1}"), (AP, f"project:{P2}"))) == frozenset(
        {P1, P2}
    )
    assert visible_projects(human((V, "project:not-a-uuid"))) == frozenset()
    assert visible_projects(human()) == frozenset()
    assert visible_projects(
        human((V, f"project:{P1}"), (O, f"project:{P2}")), Action.REGISTRY_MANAGE
    ) == frozenset({P2})
    assert project_visible(None, P1) and project_visible({P1}, str(P1))
    assert not project_visible({P1}, P2) and not project_visible(set(), P1)
    assert not project_visible({P1}, "garbage")


@pytest.mark.parametrize("action", sorted(HUMAN_ONLY), ids=lambda a: a.value)
def test_tokens_never_do_human_only_actions(action: Action) -> None:
    assert MATRIX[action].human_only
    t = token({"read", "operate", "inventory:sync"}, (V, "global"), (O, "global"))
    assert not authorize_action(t, action)
    assert action_scopes(t, action) == frozenset()


def test_token_scopes() -> None:
    read = token({"read"}, (V, "global"))
    assert authorize_action(read, Action.INVENTORY_VIEW)
    assert not authorize_action(read, Action.REGISTRY_MANAGE)
    sync = token({"inventory:sync"}, (V, "global"), (O, "global"))
    assert authorize_action(sync, Action.INVENTORY_SYNC)
    assert not authorize_action(sync, Action.REGISTRY_MANAGE)  # needs operate
    op = token({"operate"}, (V, "global"), (O, "global"))
    assert authorize_action(op, Action.REGISTRY_MANAGE) and authorize_action(
        op, Action.INVENTORY_SYNC
    )
    assert not authorize_action(op, Action.APPROVAL_DECIDE)


def test_matrix_rule_flags_match_the_design() -> None:
    assert {a for a, r in MATRIX.items() if r.human_only} == HUMAN_ONLY
    assert {a for a, r in MATRIX.items() if r.sod} == {
        Action.APPROVAL_DECIDE,
        Action.LINT_WAIVER_GRANT,
        Action.EXCEPTION_GRANT,
    }
