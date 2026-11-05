"""The single authorization decision point: role lattice, the RBAC matrix per action, project scoping.

Lattice (security-model.md 3.1): ``viewer ⊂ operator``; ``approver`` = viewer + approvals; ``admin`` is
configuration and does **not** inherit ``operator`` or ``approver`` (it may view).

The matrix (:data:`MATRIX`) is the table of security-model.md 3.1, one row per action, written out explicitly per
role rather than derived from the lattice, so a reviewer can compare it line by line with the design. Endpoints use
:func:`ovlm.auth.deps.require_action` (or :func:`ensure_scope` when the resource's project is only known after a
lookup). Separation of duties (requester sets, operator+approver) is not a matrix question; it lives in
:mod:`ovlm.auth.sod`.

Project scoping (security-model.md 3.3): role bindings are ``(role, scope)`` with ``scope = global | project:<id>``,
where ``<id>`` is the OVLM ``project_connection`` id. A resource outside every scope in which the caller may *view*
answers ``404`` (no existence leak); a visible resource on which the caller may not do the action answers ``403``.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from ovlm.auth.principal import GLOBAL, ROLES, Principal, canonical_scope

ROLE_IMPLIES: dict[str, frozenset[str]] = {
    "viewer": frozenset({"viewer"}),
    "operator": frozenset({"operator", "viewer"}),
    "approver": frozenset({"approver", "viewer"}),
    "admin": frozenset({"admin", "viewer"}),
}


class Action(StrEnum):
    """Actions of the RBAC matrix (security-model.md 3.1). The value is the stable name used in audit rows."""

    INVENTORY_VIEW = "inventory.view"
    INVENTORY_SYNC = "inventory.sync"
    REGISTRY_MANAGE = "registry.manage"  # register/unregister VM, create/edit/delete service
    HOST_KEY_CONFIRM = (
        "host_key.confirm"  # confirm a managed VM's scanned SSH host key (ADR-0006), human session
    )
    PROFILE_EDIT = "profile.edit"  # incl. automation ref + SHA, health check
    AUTOMATION_REPO_MANAGE = "automation_repo.manage"
    POLICY_EDIT = "policy.edit"  # incl. approval rules, SoD, retention
    EXCEPTION_REQUEST = "exception.request"  # V1
    EXCEPTION_GRANT = "exception.grant"  # V1, ≠ requester (sod)
    READINESS_RUN = "readiness.run"
    READINESS_ATTEST = "readiness.attest"  # V1
    PLAN_CREATE = "plan.create"  # create plan, request approval (also cutover/retirement requests)
    APPROVAL_DECIDE = (
        "approval.decide"  # plan, cutover, retirement; ≠ requester set (sod), human session
    )
    LINT_WAIVER_GRANT = "lint_waiver.grant"  # api-design 3.3; ≠ version author (sod), human session
    RUN_OPERATE = "run.operate"  # start approved run, resume, abort into rollback, retry, probe
    RUN_REVERT = "run.revert"  # + typed confirmation
    RUN_MARK_RESOLVED = "run.mark_resolved"  # + TC; approver when the next step is destructive
    AUTOMATION_ARTEFACT_VIEW = (
        "automation_artefact.view"  # restricted artefacts, security-model.md 5.2
    )
    AUDIT_VIEW = "audit.view"
    AUDIT_EXPORT = "audit.export"  # V1
    CREDENTIAL_MANAGE = "credential.manage"  # + TC
    USER_MANAGE = "user.manage"  # users, role bindings, revoke any token
    SETTINGS_MANAGE = (
        "settings.manage"  # installation settings (allow_operator_approver), + step-up + TC
    )
    TOKEN_CREATE_OWN = "token.create_own"  # noqa: S105 - an action name; ≤ own scope (tokens module)


@dataclass(frozen=True)
class Rule:
    roles: frozenset[str]
    #: API tokens may never do it (security-model.md 2.2, 7.2), whatever their scope.
    human_only: bool = False
    #: Token scope that, besides ``operate``, allows a token to do this operator action.
    token_scope: str | None = None
    #: Needs a typed confirmation (FR-UI-2), checked by the endpoint. Informational for the matrix.
    typed_confirmation: bool = False
    #: Further SoD conditions apply (:mod:`ovlm.auth.sod`). Informational for the matrix.
    sod: bool = False


def _r(*roles: str, **kw: object) -> Rule:
    return Rule(frozenset(roles), **kw)  # type: ignore[arg-type]


ALL = ("viewer", "operator", "approver", "admin")

#: security-model.md 3.1, row by row. A role absent from a row is denied.
MATRIX: dict[Action, Rule] = {
    Action.INVENTORY_VIEW: _r(*ALL),
    Action.INVENTORY_SYNC: _r("operator", "admin", token_scope="inventory:sync"),  # noqa: S106
    Action.REGISTRY_MANAGE: _r("operator"),
    Action.HOST_KEY_CONFIRM: _r("operator", human_only=True),
    Action.PROFILE_EDIT: _r("operator"),
    Action.AUTOMATION_REPO_MANAGE: _r("admin", human_only=True),
    Action.POLICY_EDIT: _r("admin", human_only=True),
    Action.EXCEPTION_REQUEST: _r("operator"),
    Action.EXCEPTION_GRANT: _r("approver", human_only=True, sod=True),
    Action.READINESS_RUN: _r("operator"),
    Action.READINESS_ATTEST: _r("operator", "approver", human_only=True),
    Action.PLAN_CREATE: _r("operator"),
    Action.APPROVAL_DECIDE: _r("approver", human_only=True, sod=True),
    Action.LINT_WAIVER_GRANT: _r("approver", human_only=True, sod=True),
    Action.RUN_OPERATE: _r("operator"),
    Action.RUN_REVERT: _r("operator", human_only=True, typed_confirmation=True),
    Action.RUN_MARK_RESOLVED: _r("operator", "approver", human_only=True, typed_confirmation=True),
    Action.AUTOMATION_ARTEFACT_VIEW: _r("operator", "admin"),
    Action.AUDIT_VIEW: _r(*ALL),
    Action.AUDIT_EXPORT: _r("admin", human_only=True),
    Action.CREDENTIAL_MANAGE: _r("admin", human_only=True, typed_confirmation=True),
    Action.USER_MANAGE: _r("admin", human_only=True),
    Action.SETTINGS_MANAGE: _r("admin", human_only=True, typed_confirmation=True),
    Action.TOKEN_CREATE_OWN: _r(*ALL, human_only=True),
}

assert set(MATRIX) == set(Action), "every action has a matrix row"  # noqa: S101 - import-time table check
assert all(r.roles <= set(ROLES) for r in MATRIX.values())  # noqa: S101


def scope_covers(granted: str, requested: str | None) -> bool:
    """A global binding covers every scope; a project binding covers only that project.

    ``requested=None`` means "in any scope I hold" (list endpoints then filter by :func:`scopes_for`).
    """
    if requested is None or granted == GLOBAL:
        return True
    return canonical_scope(granted) == canonical_scope(requested)


def authorize(principal: Principal, role: str, scope: str | None = None) -> bool:
    """True if ``principal`` holds ``role`` (directly or by the lattice) covering ``scope``."""
    for granted_role, granted_scope in principal.grants:
        if role in ROLE_IMPLIES.get(granted_role, frozenset()) and scope_covers(
            granted_scope, scope
        ):
            return True
    return False


def scopes_for(principal: Principal, role: str) -> frozenset[str]:
    """Scopes in which the principal holds ``role``; ``{"global"}`` means all (for query filtering)."""
    scopes = {s for r, s in principal.grants if role in ROLE_IMPLIES.get(r, frozenset())}
    return frozenset({GLOBAL}) if GLOBAL in scopes else frozenset(scopes)


def token_may(principal: Principal, action: Action) -> bool:
    """Token restrictions: never ``human_only`` actions; beyond viewing, the ``operate`` scope or the action's own
    token scope is needed. (Token grants are already narrowed to viewer/operator by the tokens module.)"""
    if principal.is_human:
        return True
    rule = MATRIX[action]
    if rule.human_only:
        return False
    if "viewer" in rule.roles:  # read actions: every token scope includes viewing
        return True
    allowed = {"operate"} | ({rule.token_scope} if rule.token_scope else set())
    return bool(allowed & principal.token_scopes)


def role_allows(role: str, action: Action) -> bool:
    """The bare matrix cell: does a binding of ``role`` allow ``action``? (No lattice: rows list roles.)"""
    return role in MATRIX[action].roles


def authorize_action(principal: Principal, action: Action, scope: str | None = None) -> bool:
    """True if one of the principal's grants allows ``action`` in a scope covering ``scope`` (``None``: any), and
    the principal type may do it. SoD conditions are checked separately (:mod:`ovlm.auth.sod`)."""
    if not token_may(principal, action):
        return False
    return any(
        role_allows(role, action) and scope_covers(granted, scope)
        for role, granted in principal.grants
    )


def action_scopes(principal: Principal, action: Action) -> frozenset[str]:
    """Scopes in which the principal may do ``action``; ``{"global"}`` means all."""
    if not token_may(principal, action):
        return frozenset()
    scopes = {s for r, s in principal.grants if role_allows(r, action)}
    return frozenset({GLOBAL}) if GLOBAL in scopes else frozenset(scopes)


def can_read_restricted(grants: Collection[tuple[str, str]], project_scope: str) -> bool:
    """May a holder of ``grants`` (``(role, scope)`` pairs) read the restricted automation artefacts (log, events,
    diff) of a run in ``project_scope``? ``operator`` or ``admin`` in that project or globally; ``viewer`` and
    ``approver`` never (security-model.md 5.2, SEC-R-3). Reads the matrix row, so the rule has one home. Token
    restrictions are not decided here: callers with a :class:`Principal` use :func:`authorize_action`."""
    return any(
        role_allows(role, Action.AUTOMATION_ARTEFACT_VIEW) and scope_covers(granted, project_scope)
        for role, granted in grants
    )


def project_scope_of(project_connection_id: UUID | str) -> str:
    return f"project:{project_connection_id}"


def visible_projects(
    principal: Principal, action: Action = Action.INVENTORY_VIEW
) -> frozenset[UUID] | None:
    """Project connection ids whose resources the principal may see; ``None`` means every project (global).

    Use it to filter list queries (``WHERE project_connection_id = ANY(...)``). A project binding whose id is not
    a UUID matches no project connection, so it is dropped (an empty set filters everything out).
    """
    scopes = action_scopes(principal, action)
    if GLOBAL in scopes:
        return None
    out: set[UUID] = set()
    for s in scopes:
        try:
            out.add(UUID(s.removeprefix("project:")))
        except ValueError:
            continue
    return frozenset(out)


def project_visible(projects: Collection[UUID] | None, project_connection_id: UUID | str) -> bool:
    """Is a resource of this project inside the filter returned by :func:`visible_projects`?"""
    if projects is None:
        return True
    try:
        return UUID(str(project_connection_id)) in projects
    except ValueError:
        return False


class ScopeDecision(StrEnum):
    ALLOWED = "allowed"
    NOT_FOUND = "not_found"  # the caller cannot even see the resource: answer 404
    FORBIDDEN = "forbidden"  # visible, but the action is not allowed there: answer 403


def decide_in_scope(principal: Principal, action: Action, scope: str) -> ScopeDecision:
    """404-versus-403 rule of security-model.md 3.3 for one resource whose scope is known."""
    if authorize_action(principal, action, scope):
        return ScopeDecision.ALLOWED
    if not authorize_action(principal, Action.INVENTORY_VIEW, scope):
        return ScopeDecision.NOT_FOUND
    return ScopeDecision.FORBIDDEN
