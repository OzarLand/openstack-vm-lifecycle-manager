"""Server-side sessions (security-model.md 2.3). Only the SHA-256 of the session id is stored.

Idle timeout and absolute lifetime come from settings (defaults 30 min / 12 h). A new id is issued at login and on
every privilege change (:func:`rotate_session`, :func:`delete_user_sessions`).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm.auth.dbutil import rowcount
from ovlm.config import Settings


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class SessionInfo:
    id_hash: str
    csrf_token: str
    auth_method: str
    user_id: UUID
    username: str
    totp_confirmed: bool


def create_session(
    db: Session, settings: Settings, *, user_id: UUID, auth_method: str, source_ip: str | None
) -> tuple[str, str]:
    """Insert a session; return ``(raw session id for the cookie, csrf token)``."""
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    db.execute(
        text(
            """
            INSERT INTO auth_session (id_hash, user_id, csrf_token, auth_method, source_ip, expires_at)
            VALUES (:h, :u, :c, :m, :ip, now() + make_interval(hours => :hours))
            """
        ),
        {
            "h": sha256_hex(raw),
            "u": user_id,
            "c": csrf,
            "m": auth_method,
            "ip": source_ip,
            "hours": settings.auth.session_absolute_hours,
        },
    )
    db.execute(text("DELETE FROM auth_session WHERE expires_at < now() - interval '1 day'"))
    return raw, csrf


def load_session(db: Session, settings: Settings, raw: str) -> SessionInfo | None:
    row = db.execute(
        text(
            """
            SELECT s.id_hash, s.csrf_token, s.auth_method, s.user_id, u.username,
                   (u.totp_confirmed_at IS NOT NULL) AS totp_confirmed,
                   s.last_seen_at < now() - interval '60 seconds' AS stale
            FROM auth_session s JOIN app_user u ON u.id = s.user_id
            WHERE s.id_hash = :h AND u.state = 'active' AND s.expires_at > now()
              AND s.last_seen_at > now() - make_interval(mins => :idle)
            """
        ),
        {"h": sha256_hex(raw), "idle": settings.auth.session_idle_minutes},
    ).one_or_none()
    if row is None:
        return None
    if row.stale:
        db.execute(
            text("UPDATE auth_session SET last_seen_at = now() WHERE id_hash = :h"),
            {"h": row.id_hash},
        )
        db.commit()
    return SessionInfo(
        row.id_hash, row.csrf_token, row.auth_method, row.user_id, row.username, row.totp_confirmed
    )


def delete_session(db: Session, id_hash: str) -> None:
    db.execute(text("DELETE FROM auth_session WHERE id_hash = :h"), {"h": id_hash})


def delete_user_sessions(db: Session, user_id: UUID) -> int:
    return rowcount(db.execute(text("DELETE FROM auth_session WHERE user_id = :u"), {"u": user_id}))


def rotate_session(
    db: Session,
    settings: Settings,
    old_hash: str,
    *,
    user_id: UUID,
    auth_method: str,
    source_ip: str | None,
) -> tuple[str, str]:
    """New session id and CSRF token for the same user; the old session dies (privilege change)."""
    new = create_session(
        db, settings, user_id=user_id, auth_method=auth_method, source_ip=source_ip
    )
    delete_session(db, old_hash)
    return new
