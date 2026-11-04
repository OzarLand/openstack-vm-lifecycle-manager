"""The single authorization decision point (E3-2 extends it).

E3-1 implements only the role lattice and scope matching, so ``require_role`` is usable now. E3-2 adds the RBAC
matrix per action, requester sets and separation of duties here (and in the worker's re-validation), without
changing the signature of :func:`authorize` or :func:`ovlm.auth.deps.require_role`.

Lattice (security-model.md 3.1): ``viewer ⊂ operator``; ``approver`` = viewer + approvals; ``admin`` is
configuration and does **not** inherit ``operator`` or ``approver`` (it may view).
"""

from __future__ import annotations

from ovlm.auth.principal import GLOBAL, Principal

ROLE_IMPLIES: dict[str, frozenset[str]] = {
    "viewer": frozenset({"viewer"}),
    "operator": frozenset({"operator", "viewer"}),
    "approver": frozenset({"approver", "viewer"}),
    "admin": frozenset({"admin", "viewer"}),
}


def scope_covers(granted: str, requested: str | None) -> bool:
    """A global binding covers every scope; a project binding covers only that project.

    ``requested=None`` means "in any scope I hold" (list endpoints then filter by :func:`scopes_for`).
    """
    if requested is None or granted == GLOBAL:
        return True
    return granted == requested


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
