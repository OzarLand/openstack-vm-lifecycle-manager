"""Audit allowlists for auth entities and a small recording helper (security-model.md section 8).

Credentials (password hashes, TOTP secrets, token secrets, session ids, link secrets) are never in these lists.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.sessions import sha256_hex

audit.register_entity("auth", ["kind", "reason", "second_factor"])
audit.register_entity("user", ["username", "display_name", "state", "created_via", "roles"])
audit.register_entity("role_binding", ["user_id", "role", "scope"])
audit.register_entity("api_token", ["name", "scopes", "project_scope", "expires_at", "owner_id"])
audit.register_entity("enrolment_link", ["purpose", "user_id", "expires_at"])
audit.register_entity("totp", ["state"])
audit.register_entity("stepup", ["action", "target_id", "expires_at"])
audit.register_entity("session", ["auth_method", "reason"])
audit.register_entity("endpoint", [])


def unknown_user_ref(username: str) -> str:
    """Audit reference for a login attempt on an unknown name. Users sometimes type a password into the username
    field, so the raw text is never stored; a short hash still lets an admin correlate repeated attempts."""
    return "unknown:" + sha256_hex(username.strip().lower())[:12]


def record_independent(db: Session, **kwargs: object) -> None:
    """Record in its own transaction, so the row survives when the caller's transaction is rolled back
    (failed logins, denials)."""
    with Session(db.get_bind()) as own:
        audit.record(own, **kwargs)  # type: ignore[arg-type]
        own.commit()


def actor(user_id: UUID | None) -> dict[str, object]:
    return {"actor_id": user_id}
