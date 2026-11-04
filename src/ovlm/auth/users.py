"""Users, one-time enrolment links, role bindings.

**Nobody sets another person's password.** A new user (or a reset) gets a single-use enrolment link; the user
chooses the password in their own browser. Links are stored as SHA-256 and die on use, on expiry, or when a newer
link for the same user is issued.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from uuid import UUID

from argon2 import PasswordHasher
from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm.auth import passwords
from ovlm.auth.dbutil import rowcount
from ovlm.auth.ids import new_id
from ovlm.auth.principal import GLOBAL, PROJECT_PREFIX, ROLES
from ovlm.auth.sessions import delete_user_sessions, sha256_hex
from ovlm.config import Settings

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{2,63}$")


class UserError(ValueError):
    """Invalid request (message safe to show)."""


class ScopeNotFoundError(UserError):
    """The binding names a project connection that does not exist (answered 404)."""


class LinkInvalidError(Exception):
    """Unknown, used, revoked or expired enrolment link (deliberately not distinguished)."""


def normalise_username(value: str) -> str:
    name = value.strip().lower()
    if not USERNAME.match(name):
        raise UserError(
            "username: 3-64 characters of a-z, 0-9, '.', '_', '@', '-', starting with a letter or digit"
        )
    return name


def check_scope(scope: str) -> str:
    """``global`` or ``project:<project connection UUID>``, returned in canonical form (lower case, SEC-C-8).

    Any other string is refused: a binding that matches no project would grant nothing, silently."""
    if scope == GLOBAL:
        return scope
    if scope.startswith(PROJECT_PREFIX):
        raw = scope.removeprefix(PROJECT_PREFIX)
        if len(raw) <= 64:
            try:
                return PROJECT_PREFIX + str(UUID(raw))
            except ValueError:
                pass
    raise UserError("scope must be 'global' or 'project:<project connection id (UUID)>'")


def check_project_exists(db: Session, scope: str) -> None:
    """A project scope must name an existing project connection (:class:`ScopeNotFoundError` otherwise).

    The ``project_connection`` table belongs to the cloud-connection module; until its migration exists the check
    cannot run and only the UUID form is enforced (:func:`check_scope`)."""
    if not scope.startswith(PROJECT_PREFIX):
        return
    table = db.execute(text("SELECT to_regclass('project_connection') IS NOT NULL")).scalar_one()
    if not table:
        return
    found = db.execute(
        text("SELECT 1 FROM project_connection WHERE id = CAST(:id AS uuid)"),
        {"id": scope.removeprefix(PROJECT_PREFIX)},
    ).first()
    if found is None:
        raise ScopeNotFoundError("no such project connection")


def create_user(
    db: Session,
    *,
    username: str,
    display_name: str,
    created_by: UUID | None,
    created_via: str,
    bindings: list[tuple[str, str]] | None = None,
) -> UUID:
    """Insert a user in ``pending_enrolment`` (no password) with optional initial role bindings."""
    name = normalise_username(username)
    user_id = new_id()
    try:
        db.execute(
            text(
                """
                INSERT INTO app_user (id, username, display_name, state, created_via, created_by)
                VALUES (:id, :u, :d, 'pending_enrolment', :via, :by)
                """
            ),
            {
                "id": user_id,
                "u": name,
                "d": display_name.strip()[:200],
                "via": created_via,
                "by": created_by,
            },
        )
    except Exception as exc:
        if "app_user_username_key" in str(exc):
            raise UserError("a user with this username already exists") from exc
        raise
    for role, scope in bindings or []:
        add_binding(db, user_id=user_id, role=role, scope=scope, created_by=created_by)
    return user_id


def issue_link(
    db: Session, settings: Settings, *, user_id: UUID, purpose: str, created_by: UUID | None
) -> tuple[UUID, str]:
    """Revoke earlier unused links of the user and return ``(link id, raw link token)``."""
    db.execute(
        text(
            "UPDATE enrolment_link SET revoked_at = now() "
            "WHERE user_id = :u AND used_at IS NULL AND revoked_at IS NULL"
        ),
        {"u": user_id},
    )
    link_id = new_id()
    secret = secrets.token_urlsafe(32)
    db.execute(
        text(
            """
            INSERT INTO enrolment_link (id, user_id, purpose, secret_hash, created_by, expires_at)
            VALUES (:id, :u, :p, :h, :by, now() + make_interval(hours => :hours))
            """
        ),
        {
            "id": link_id,
            "u": user_id,
            "p": purpose,
            "h": sha256_hex(secret),
            "by": created_by,
            "hours": settings.auth.enrolment_link_hours,
        },
    )
    return link_id, f"{link_id.hex}.{secret}"


def _split(raw: str) -> tuple[UUID, str] | None:
    head, sep, secret = raw.partition(".")
    if not sep or len(head) != 32 or not secret:
        return None
    try:
        return UUID(hex=head), secret
    except ValueError:
        return None


@dataclass(frozen=True)
class LinkInfo:
    id: UUID
    user_id: UUID
    username: str
    purpose: str


def peek_link(db: Session, raw: str) -> LinkInfo | None:
    """Validate without consuming (to render the form). The secret is compared by hash in SQL."""
    parts = _split(raw)
    if parts is None:
        return None
    row = db.execute(
        text(
            """
            SELECT l.id, l.user_id, u.username, l.purpose
            FROM enrolment_link l JOIN app_user u ON u.id = l.user_id
            WHERE l.id = :id AND l.secret_hash = :h AND l.used_at IS NULL AND l.revoked_at IS NULL
              AND l.expires_at > now() AND u.state <> 'disabled'
            """
        ),
        {"id": parts[0], "h": sha256_hex(parts[1])},
    ).one_or_none()
    return LinkInfo(row.id, row.user_id, row.username, row.purpose) if row else None


def redeem_link(
    db: Session, hasher: PasswordHasher, raw: str, password: str
) -> tuple[LinkInfo, UUID | None]:
    """Consume the link and set the user's own password; return ``(link, created_by)``.

    The password policy is checked first, so a rejected password does not burn the link. The consume is one atomic
    ``UPDATE ... WHERE used_at IS NULL``, so a link works exactly once even under concurrent requests.
    A reset also clears TOTP (re-enrolment follows) and ends all sessions of the user.
    """
    parts = _split(raw)
    if parts is None:
        raise LinkInvalidError
    pre = peek_link(db, raw)
    if pre is None:
        raise LinkInvalidError
    passwords.check_policy(password, username=pre.username)  # raises PasswordPolicyError
    row = db.execute(
        text(
            """
            UPDATE enrolment_link SET used_at = now()
            WHERE id = :id AND secret_hash = :h AND used_at IS NULL AND revoked_at IS NULL
              AND expires_at > now()
            RETURNING user_id, purpose, created_by
            """
        ),
        {"id": parts[0], "h": sha256_hex(parts[1])},
    ).one_or_none()
    if row is None:
        raise LinkInvalidError
    reset = row.purpose == "reset"
    updated = db.execute(
        text(
            """
            UPDATE app_user SET
              password_hash = :ph, password_changed_at = now(), updated_at = now(), state = 'active',
              totp_secret_enc = CASE WHEN :reset THEN NULL ELSE totp_secret_enc END,
              totp_confirmed_at = CASE WHEN :reset THEN NULL ELSE totp_confirmed_at END,
              totp_last_step = CASE WHEN :reset THEN NULL ELSE totp_last_step END,
              credential_reset_by = CASE WHEN :reset THEN :by ELSE credential_reset_by END,
              credential_reset_at = CASE WHEN :reset THEN now() ELSE credential_reset_at END
            WHERE id = :u AND state IN ('pending_enrolment','active')
            """
        ),
        {
            "ph": passwords.hash_password(hasher, password),
            "reset": reset,
            "by": row.created_by,
            "u": row.user_id,
        },
    )
    if rowcount(updated) != 1:
        raise LinkInvalidError
    delete_user_sessions(db, row.user_id)
    return LinkInfo(parts[0], row.user_id, pre.username, row.purpose), row.created_by


def load_bindings(db: Session, user_id: UUID) -> list[tuple[str, str]]:
    rows = db.execute(
        text("SELECT role, scope FROM role_binding WHERE user_id = :u AND revoked_at IS NULL"),
        {"u": user_id},
    ).all()
    return [(r.role, r.scope) for r in rows]


@dataclass(frozen=True)
class BindingResult:
    id: UUID
    #: False when an identical active binding already existed: nothing was inserted (and nothing is audited).
    created: bool
    scope: str


def add_binding(
    db: Session, *, user_id: UUID, role: str, scope: str, created_by: UUID | None
) -> BindingResult:
    """Insert an active binding, or return the identical active one that already exists (SEC-C-9).

    The scope is validated and normalised (:func:`check_scope`) and a project scope must exist
    (:func:`check_project_exists`, :class:`ScopeNotFoundError`)."""
    if role not in ROLES:
        raise UserError(f"role must be one of {list(ROLES)}")
    scope = check_scope(scope or GLOBAL)
    check_project_exists(db, scope)
    params = {"u": user_id, "r": role, "s": scope}
    inserted = db.execute(
        text(
            "INSERT INTO role_binding (id, user_id, role, scope, created_by) "
            "VALUES (:id, :u, :r, :s, :by) "
            "ON CONFLICT (user_id, role, scope) WHERE revoked_at IS NULL DO NOTHING RETURNING id"
        ),
        {**params, "id": new_id(), "by": created_by},
    ).scalar_one_or_none()
    if inserted is not None:
        return BindingResult(inserted, True, scope)
    existing = db.execute(
        text(
            "SELECT id FROM role_binding "
            "WHERE user_id = :u AND role = :r AND scope = :s AND revoked_at IS NULL"
        ),
        params,
    ).scalar_one()
    return BindingResult(existing, False, scope)


def revoke_binding(
    db: Session, binding_id: UUID, *, revoked_by: UUID
) -> tuple[UUID, str, str] | None:
    row = db.execute(
        text(
            "UPDATE role_binding SET revoked_at = now(), revoked_by = :by "
            "WHERE id = :id AND revoked_at IS NULL RETURNING user_id, role, scope"
        ),
        {"id": binding_id, "by": revoked_by},
    ).one_or_none()
    return (row.user_id, row.role, row.scope) if row else None


def disable_user(db: Session, user_id: UUID) -> bool:
    """Disable: sessions and tokens stop working at once (both check ``state = 'active'``)."""
    done = (
        rowcount(
            db.execute(
                text(
                    "UPDATE app_user SET state = 'disabled', disabled_at = now(), updated_at = now() "
                    "WHERE id = :u AND state <> 'disabled'"
                ),
                {"u": user_id},
            )
        )
        == 1
    )
    if done:
        delete_user_sessions(db, user_id)
    return done
