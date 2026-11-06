"""The authenticated caller."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID

Role = Literal["viewer", "operator", "approver", "admin"]
ROLES: tuple[Role, ...] = ("viewer", "operator", "approver", "admin")
#: Roles that need a confirmed TOTP second factor (M9, SEC-R-10).
TOTP_ROLES: frozenset[str] = frozenset({"approver", "admin"})
TokenScope = Literal["read", "inventory:sync", "operate"]
TOKEN_SCOPES: tuple[TokenScope, ...] = ("read", "inventory:sync", "operate")
#: Roles a token scope can ever exercise. Tokens never reach approver/admin (security-model.md 2.2, 7.2).
TOKEN_SCOPE_ROLES: dict[str, frozenset[str]] = {
    "read": frozenset({"viewer"}),
    "inventory:sync": frozenset({"viewer", "operator"}),
    "operate": frozenset({"viewer", "operator"}),
}
GLOBAL = "global"
PROJECT_PREFIX = "project:"


def canonical_scope(scope: str) -> str:
    """``project:<uuid>`` in canonical lower-case form; anything else unchanged (SEC-C-8). Used on both sides of
    every scope comparison, so a binding stored before normalisation still compares correctly."""
    if scope.startswith(PROJECT_PREFIX):
        try:
            return PROJECT_PREFIX + str(UUID(scope.removeprefix(PROJECT_PREFIX)))
        except ValueError:
            return scope
    return scope


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    username: str
    principal_type: Literal["human", "token"]
    auth_method: str  # password | password+totp | token
    #: Effective ``(role, scope)`` pairs. Privileged roles are absent while TOTP is missing.
    grants: frozenset[tuple[str, str]]
    source_ip: str | None = None
    session_hash: str | None = None
    csrf_token: str | None = field(default=None, repr=False)
    token_id: UUID | None = None
    token_scopes: frozenset[str] = frozenset()
    totp_confirmed: bool = False
    #: Held bindings that need TOTP while the user has not enrolled it: the user must enrol first.
    totp_enrolment_required: bool = False

    @property
    def is_human(self) -> bool:
        return self.principal_type == "human"

    def signed_in_as(self) -> str:
        """``Signed in as approver-a (approver).`` for refusals: names the account so a wrong login is obvious."""
        names = ", ".join(sorted(self.roles())) or "no roles"
        return f"Signed in as {self.username} ({names})."

    def needs_role_message(self, role: str) -> str:
        return f"{self.signed_in_as()} This action needs the {role} role."

    def roles(self) -> frozenset[str]:
        return frozenset(role for role, _ in self.grants)
