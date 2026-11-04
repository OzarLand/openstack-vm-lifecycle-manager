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

    def roles(self) -> frozenset[str]:
        return frozenset(role for role, _ in self.grants)
