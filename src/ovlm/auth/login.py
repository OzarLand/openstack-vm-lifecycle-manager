"""Login, re-authentication (step-up), TOTP enrolment: the credential-checking flows.

Rules (security-model.md 2.1, 2.3, 10.1): one generic failure for unknown user / wrong password / wrong or missing
TOTP / disabled / not yet enrolled (and equal work in each case); per-account and per-source-address backoff, never
a hard lockout; each TOTP time step is accepted once; a new session id at login and on privilege change.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from argon2 import PasswordHasher
from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth import passwords, totp
from ovlm.auth.events import record_independent, unknown_user_ref
from ovlm.auth.ids import new_id
from ovlm.auth.principal import TOTP_ROLES, Principal
from ovlm.auth.sessions import create_session, rotate_session
from ovlm.auth.totp import TotpUnavailableError, TotpVault
from ovlm.auth.users import load_bindings, normalise_username
from ovlm.config import Settings

log = logging.getLogger("ovlm.auth")


class AuthFailedError(Exception):
    """Generic authentication failure (the reason is audited, never returned)."""


class RateLimitedError(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__("too many failed attempts")
        self.retry_after = retry_after


class TotpFlowError(Exception):
    """Invalid TOTP enrolment request; ``code`` is a stable slug, the message is safe to show."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LoginResult:
    user_id: UUID
    session_id: str
    csrf_token: str
    auth_method: str
    totp_enrolment_required: bool


def needs_totp(bindings: list[tuple[str, str]]) -> bool:
    return any(role in TOTP_ROLES for role, _ in bindings)


# --- rate limit ----------------------------------------------------------------------------------------------


def _backoff(failures: int, threshold: int) -> int:
    return 0 if failures < threshold else min(2 ** (failures - threshold), 900)


def check_rate_limit(db: Session, settings: Settings, username: str, source_ip: str | None) -> None:
    """Raise :class:`RateLimitedError` while a backoff after recent failures is running.

    * Per account: failures since the last success of that account within the window. The delay doubles per
      further failure up to 15 minutes, so approvers are slowed, never locked out for good. This is the only
      limiter that escalates.
    * Per source address (``source_ip``, the client resolved through the trusted proxies, ``None`` when unknown):
      once the threshold is reached, a **fixed** ``login_ip_delay_seconds`` after the latest failure. It slows a
      password spray from one address, but whoever shares that address with an attacker (or every user, if the
      proxy is not configured as trusted) is held back by seconds only, never by the escalating delay (SEC-C-1).
    """
    auth = settings.auth
    window = auth.login_window_minutes
    by_user = db.execute(
        text(
            """
            SELECT count(*) AS n, extract(epoch FROM now() - max(ts)) AS age FROM login_attempt
            WHERE username = :u AND NOT success AND ts > now() - make_interval(mins => :w)
              AND ts > coalesce((SELECT max(ts) FROM login_attempt WHERE username = :u AND success),
                                '-infinity')
            """
        ),
        {"u": username, "w": window},
    ).one()
    waits = [(_backoff(by_user.n, auth.login_failure_threshold), by_user.age)]
    if source_ip:
        by_ip = db.execute(
            text(
                """
                SELECT count(*) AS n, extract(epoch FROM now() - max(ts)) AS age FROM login_attempt
                WHERE source_ip = :ip AND NOT success AND ts > now() - make_interval(mins => :w)
                """
            ),
            {"ip": source_ip, "w": window},
        ).one()
        if by_ip.n >= auth.login_ip_failure_threshold:
            waits.append((auth.login_ip_delay_seconds, by_ip.age))
    for delay, age in waits:
        if delay and age is not None and float(age) < delay:
            raise RateLimitedError(max(1, math.ceil(delay - float(age))))


def _attempt(db: Session, kind: str, username: str, source_ip: str | None, success: bool) -> None:
    db.execute(
        text(
            "INSERT INTO login_attempt (kind, username, source_ip, success) VALUES (:k, :u, :ip, :s)"
        ),
        {"k": kind, "u": username, "ip": source_ip, "s": success},
    )


def _fail(
    db: Session, kind: str, username: str, user_id: UUID | None, source_ip: str | None, reason: str
) -> AuthFailedError:
    """Persist the failed attempt and its audit row in their own transaction; return the generic error."""
    db.rollback()
    _attempt(db, kind, username, source_ip, False)
    db.commit()
    record_independent(
        db,
        action=f"auth.{kind}.failure",
        target_type="auth",
        target_id=str(user_id) if user_id else unknown_user_ref(username),
        result="failure",
        actor_id=user_id,
        auth_method="password",
        source_ip=source_ip,
        after={"kind": kind, "reason": reason},
    )
    return AuthFailedError()


# --- shared credential check ---------------------------------------------------------------------------------


def _check_second_factor(
    db: Session, vault: TotpVault | None, row: Any, code: str | None
) -> tuple[bool, str]:
    """``(ok, reason)``. The user row is locked (FOR UPDATE) by the caller, so replay protection is race-free."""
    secret_enc = getattr(row, "totp_secret_enc", None)
    if not secret_enc or getattr(row, "totp_confirmed_at", None) is None:
        return True, "none"
    if vault is None:
        raise TotpUnavailableError("TOTP key not configured")
    if not code:
        return False, "totp_missing"
    step = totp.verify_code(
        vault.decrypt(secret_enc), code, last_step=getattr(row, "totp_last_step", None)
    )
    if step is None:
        return False, "bad_totp"
    db.execute(
        text("UPDATE app_user SET totp_last_step = :s WHERE id = :u"),
        {"s": step, "u": row.id},
    )
    return True, "totp"


def _lock_user(db: Session, *, username: str | None = None, user_id: UUID | None = None) -> Any:
    """The user row, locked ``FOR UPDATE`` (serialises TOTP replay checks), by name or by id."""
    cols = "id, username, state, password_hash, totp_secret_enc, totp_confirmed_at, totp_last_step"
    if user_id is not None:
        return db.execute(
            text(f"SELECT {cols} FROM app_user WHERE id = :k FOR UPDATE"),  # noqa: S608
            {"k": user_id},
        ).one_or_none()
    return db.execute(
        text(f"SELECT {cols} FROM app_user WHERE username = :k FOR UPDATE"),  # noqa: S608
        {"k": username},
    ).one_or_none()


# --- login ---------------------------------------------------------------------------------------------------


def login(
    db: Session,
    settings: Settings,
    hasher: PasswordHasher,
    vault: TotpVault | None,
    *,
    username: str,
    password: str,
    totp_code: str | None,
    source_ip: str | None,
) -> LoginResult:
    try:
        name = normalise_username(username)
    except ValueError:
        name = username.strip().lower()[:64]
        passwords.verify_password(hasher, passwords.dummy_hash(), password)
        raise _fail(db, "login", name, None, source_ip, "unknown_user") from None
    check_rate_limit(db, settings, name, source_ip)
    row = _lock_user(db, username=name)
    stored = row.password_hash if row is not None and row.state == "active" else None
    ok, needs_rehash = passwords.verify_password(hasher, stored or passwords.dummy_hash(), password)
    if row is None:
        raise _fail(db, "login", name, None, source_ip, "unknown_user")
    if stored is None or not ok:
        reason = (
            "bad_password"
            if stored
            else ("disabled" if row.state == "disabled" else "not_enrolled")
        )
        raise _fail(db, "login", name, row.id, source_ip, reason)
    good, how = _check_second_factor(db, vault, row, totp_code)
    if not good:
        raise _fail(db, "login", name, row.id, source_ip, how)
    if needs_rehash:
        db.execute(
            text("UPDATE app_user SET password_hash = :h, updated_at = now() WHERE id = :u"),
            {"h": passwords.hash_password(hasher, password), "u": row.id},
        )
    method = "password+totp" if how == "totp" else "password"
    _attempt(db, "login", name, source_ip, True)
    session_id, csrf = create_session(
        db, settings, user_id=row.id, auth_method=method, source_ip=source_ip
    )
    bindings = load_bindings(db, row.id)
    audit.record(
        db,
        action="auth.login.success",
        target_type="auth",
        target_id=str(row.id),
        actor_id=row.id,
        auth_method=method,
        source_ip=source_ip,
        after={"kind": "login", "second_factor": "totp" if how == "totp" else "none"},
    )
    db.commit()
    return LoginResult(
        row.id,
        session_id,
        csrf,
        method,
        needs_totp(bindings) and row.totp_confirmed_at is None,
    )


# --- step-up -------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class StepUp:
    id: UUID
    action: str
    target_id: str
    expires_at: object


def reauth(
    db: Session,
    settings: Settings,
    hasher: PasswordHasher,
    vault: TotpVault | None,
    principal: Principal,
    *,
    password: str,
    totp_code: str | None,
    action: str,
    target_id: str,
) -> StepUp:
    """Issue a single-use step-up bound to this session, one action and one target, valid 5 minutes.

    A code accepted at login cannot be reused here (each step once): the user waits for the next code.
    """
    if not principal.is_human or principal.session_hash is None:
        raise AuthFailedError
    check_rate_limit(db, settings, principal.username, principal.source_ip)
    row = _lock_user(db, user_id=principal.user_id)
    if row is None or row.state != "active" or not row.password_hash:
        raise AuthFailedError
    ok, _ = passwords.verify_password(hasher, row.password_hash, password)
    if not ok:
        raise _fail(db, "reauth", row.username, row.id, principal.source_ip, "bad_password")
    if principal.totp_enrolment_required:
        raise TotpFlowError("totp-enrolment-required", "Enrol TOTP before confirming this action.")
    good, how = _check_second_factor(db, vault, row, totp_code)
    if not good:
        raise _fail(db, "reauth", row.username, row.id, principal.source_ip, how)
    method = "password+totp" if how == "totp" else "password"
    step_id = new_id()
    expires_at = db.execute(
        text(
            """
            INSERT INTO stepup (id, user_id, session_id_hash, action, target_id, auth_method, expires_at)
            VALUES (:id, :u, :s, :a, :t, :m, now() + interval '5 minutes') RETURNING expires_at
            """
        ),
        {
            "id": step_id,
            "u": row.id,
            "s": principal.session_hash,
            "a": action,
            "t": target_id,
            "m": method,
        },
    ).scalar_one()
    _attempt(db, "reauth", row.username, principal.source_ip, True)
    audit.record(
        db,
        action="auth.stepup.issue",
        target_type="stepup",
        target_id=str(step_id),
        actor_id=row.id,
        auth_method=method,
        source_ip=principal.source_ip,
        after={"action": action, "target_id": target_id, "expires_at": expires_at},
    )
    db.commit()
    return StepUp(step_id, action, target_id, expires_at)


# --- TOTP enrolment ------------------------------------------------------------------------------------------


def begin_totp_enrolment(
    db: Session, vault: TotpVault | None, principal: Principal
) -> tuple[str, str]:
    """Create (or replace, while unconfirmed) the user's pending TOTP secret; return ``(secret, otpauth URI)``.

    The secret is shown once, here. A confirmed TOTP can only be replaced through an admin reset link.
    """
    if vault is None:
        raise TotpUnavailableError("TOTP key not configured")
    if not principal.is_human:
        raise TotpFlowError("human-session-required", "TOTP is enrolled from your own session.")
    row = _lock_user(db, user_id=principal.user_id)
    if row is None:
        raise AuthFailedError
    if row.totp_confirmed_at is not None:
        raise TotpFlowError(
            "totp-already-enrolled",
            "TOTP is already enrolled; ask an admin for a credential reset.",
        )
    secret = totp.new_secret()
    db.execute(
        text(
            "UPDATE app_user SET totp_secret_enc = :s, totp_last_step = NULL, updated_at = now() WHERE id = :u"
        ),
        {"s": vault.encrypt(secret), "u": row.id},
    )
    audit.record(
        db,
        action="auth.totp.enrol_begin",
        target_type="totp",
        target_id=str(row.id),
        actor_id=row.id,
        auth_method=principal.auth_method,
        source_ip=principal.source_ip,
        after={"state": "pending"},
    )
    db.commit()
    return secret, totp.provisioning_uri(secret, row.username)


def confirm_totp(
    db: Session,
    settings: Settings,
    vault: TotpVault | None,
    principal: Principal,
    code: str,
) -> tuple[str, str]:
    """Confirm the pending secret with a first code; return the rotated ``(session id, csrf token)``."""
    if vault is None:
        raise TotpUnavailableError("TOTP key not configured")
    if principal.session_hash is None or not principal.is_human:
        raise TotpFlowError("human-session-required", "TOTP is confirmed from your own session.")
    check_rate_limit(db, settings, principal.username, principal.source_ip)
    row = _lock_user(db, user_id=principal.user_id)
    if row is None or row.totp_secret_enc is None or row.totp_confirmed_at is not None:
        raise TotpFlowError(
            "totp-not-pending", "There is no pending TOTP enrolment; start one first."
        )
    step = totp.verify_code(vault.decrypt(row.totp_secret_enc), code)
    if step is None:
        raise _fail(db, "totp", row.username, row.id, principal.source_ip, "bad_totp")
    db.execute(
        text(
            "UPDATE app_user SET totp_confirmed_at = now(), totp_last_step = :s, updated_at = now() "
            "WHERE id = :u"
        ),
        {"s": step, "u": row.id},
    )
    new_session, csrf = rotate_session(
        db,
        settings,
        principal.session_hash,
        user_id=row.id,
        auth_method="password+totp",
        source_ip=principal.source_ip,
    )
    audit.record(
        db,
        action="auth.totp.enrol_confirm",
        target_type="totp",
        target_id=str(row.id),
        actor_id=row.id,
        auth_method="password+totp",
        source_ip=principal.source_ip,
        after={"state": "confirmed"},
    )
    db.commit()
    return new_session, csrf
