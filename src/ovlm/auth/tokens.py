"""API tokens (security-model.md 2.2): ``ovlm_<id>_<32 random bytes, base32>``, shown once, SHA-256 stored.

A token is scoped (``read``, ``inventory:sync``, ``operate``) and optionally to one project; it can never exceed the
owner's role bindings and never reaches approver/admin. Expiry is mandatory (at most 90 days).
"""

from __future__ import annotations

import base64
import hmac
import os
import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm.auth.authz import ROLE_IMPLIES
from ovlm.auth.dbutil import rowcount
from ovlm.auth.ids import new_id
from ovlm.auth.principal import GLOBAL, TOKEN_SCOPE_ROLES, TOKEN_SCOPES
from ovlm.auth.sessions import sha256_hex

MAX_DAYS = 90
_FORMAT = re.compile(r"^ovlm_([0-9a-f]{32})_([A-Z2-7]{52})$")
#: Role the owner must hold for a scope to be grantable.
SCOPE_REQUIRES = {"read": "viewer", "inventory:sync": "operator", "operate": "operator"}
_DUMMY = sha256_hex("dummy")


class TokenRequestError(ValueError):
    """The requested token would exceed what the owner holds (message safe to show)."""


@dataclass(frozen=True)
class TokenInfo:
    id: UUID
    user_id: UUID
    username: str
    scopes: frozenset[str]
    project_scope: str


def parse_token(raw: str) -> tuple[UUID, str] | None:
    m = _FORMAT.match(raw)
    return (UUID(hex=m.group(1)), m.group(2)) if m else None


def _covers(binding_scope: str, project_scope: str) -> bool:
    return binding_scope in (GLOBAL, project_scope)


def token_grants(
    bindings: Iterable[tuple[str, str]], scopes: Collection[str], project_scope: str
) -> frozenset[tuple[str, str]]:
    """The owner's bindings narrowed to what the token may exercise (subset, never more)."""
    out: set[tuple[str, str]] = set()
    allowed = set().union(*(TOKEN_SCOPE_ROLES[s] for s in scopes)) if scopes else set()
    for bound_role, bound_scope in bindings:
        for role in allowed:
            if role not in ROLE_IMPLIES.get(bound_role, frozenset()):
                continue
            if project_scope == GLOBAL:
                out.add((role, bound_scope))
            elif _covers(bound_scope, project_scope):
                out.add((role, project_scope))
    return frozenset(out)


def validate_request(
    bindings: Iterable[tuple[str, str]],
    scopes: Collection[str],
    project_scope: str,
    days: int,
) -> None:
    if not scopes or any(s not in TOKEN_SCOPES for s in scopes):
        raise TokenRequestError(f"scopes must be a non-empty subset of {list(TOKEN_SCOPES)}")
    if not 1 <= days <= MAX_DAYS:
        raise TokenRequestError(f"expiry must be between 1 and {MAX_DAYS} days")
    held = list(bindings)
    for scope in scopes:
        needed = SCOPE_REQUIRES[scope]
        ok = any(
            needed in ROLE_IMPLIES.get(r, frozenset())
            and (
                project_scope == GLOBAL
                and s == GLOBAL
                or project_scope != GLOBAL
                and _covers(s, project_scope)
            )
            for r, s in held
        )
        if not ok:
            raise TokenRequestError(
                f"scope '{scope}' needs the {needed} role in {project_scope!r}, which you do not hold"
            )


def create_token(
    db: Session,
    *,
    user_id: UUID,
    name: str,
    scopes: Collection[str],
    project_scope: str,
    days: int,
) -> tuple[UUID, str, datetime]:
    """Insert and return ``(id, raw token (shown once), expires_at)``."""
    token_id = new_id()
    secret = base64.b32encode(os.urandom(32)).decode().rstrip("=")
    expires_at = db.execute(
        text(
            """
            INSERT INTO api_token (id, user_id, name, secret_hash, scopes, project_scope, expires_at)
            VALUES (:id, :u, :n, :h, :s, :p, now() + make_interval(days => :d))
            RETURNING expires_at
            """
        ),
        {
            "id": token_id,
            "u": user_id,
            "n": name,
            "h": sha256_hex(secret),
            "s": sorted(scopes),
            "p": project_scope,
            "d": days,
        },
    ).scalar_one()
    return token_id, f"ovlm_{token_id.hex}_{secret}", expires_at


def authenticate_token(db: Session, raw: str) -> TokenInfo | None:
    parsed = parse_token(raw)
    if parsed is None:
        return None
    token_id, secret = parsed
    row = db.execute(
        text(
            """
            SELECT t.id, t.user_id, u.username, t.scopes, t.project_scope, t.secret_hash,
                   (t.last_used_at IS NULL OR t.last_used_at < now() - interval '60 seconds') AS stale
            FROM api_token t JOIN app_user u ON u.id = t.user_id
            WHERE t.id = :id AND t.revoked_at IS NULL AND t.expires_at > now() AND u.state = 'active'
            """
        ),
        {"id": token_id},
    ).one_or_none()
    expected = row.secret_hash if row else _DUMMY
    ok = hmac.compare_digest(sha256_hex(secret).encode(), expected.encode())
    if row is None or not ok:
        return None
    if row.stale:
        db.execute(text("UPDATE api_token SET last_used_at = now() WHERE id = :id"), {"id": row.id})
        db.commit()
    return TokenInfo(row.id, row.user_id, row.username, frozenset(row.scopes), row.project_scope)


def revoke_token(db: Session, token_id: UUID, *, revoked_by: UUID) -> bool:
    return (
        rowcount(
            db.execute(
                text(
                    "UPDATE api_token SET revoked_at = now(), revoked_by = :by "
                    "WHERE id = :id AND revoked_at IS NULL"
                ),
                {"id": token_id, "by": revoked_by},
            )
        )
        == 1
    )
