"""Authentication endpoints: login/logout/enrolment pages (HTMX forms) and the JSON session, token and user APIs.

Human pages: ``/login``, ``/logout``, ``/enrol/{link}``, ``/account/totp``.
JSON (api-design.md 3.8): ``/api/v1/session`` (+ ``/totp/enrol``, ``/totp/confirm``, ``/reauth``), ``/api/v1/tokens``,
``/api/v1/users`` (admin), ``/api/v1/role-bindings`` (admin), ``/api/v1/settings/auth`` (admin). Nobody ever submits a password for someone else:
the only password inputs are the user's own login, re-authentication and enrolment.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any
from uuid import UUID

from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm import __version__, audit
from ovlm.auth import csrf as csrf_mod
from ovlm.auth import events as _events  # noqa: F401  (registers the audit allowlists)
from ovlm.auth import installation, passwords, sod, tokens, users
from ovlm.auth import login as login_svc
from ovlm.auth.authz import Action
from ovlm.auth.deps import (
    client_ip,
    current_principal,
    get_db,
    get_hasher,
    get_settings,
    get_vault,
    require_action,
    require_role,
)
from ovlm.auth.errors import ProblemError, ProblemRoute, forbidden
from ovlm.auth.principal import GLOBAL, Principal, canonical_scope
from ovlm.auth.sessions import create_session, delete_session, delete_user_sessions
from ovlm.auth.stepup import consume_stepup
from ovlm.auth.totp import TotpUnavailableError, TotpVault
from ovlm.config import Settings
from ovlm.ui import TEMPLATE_DIR

log = logging.getLogger("ovlm.auth")
router = APIRouter(route_class=ProblemRoute)
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

Db = Annotated[Session, Depends(get_db)]
Cfg = Annotated[Settings, Depends(get_settings)]
Hasher = Annotated[PasswordHasher, Depends(get_hasher)]
Vault = Annotated[TotpVault | None, Depends(get_vault)]
Me = Annotated[Principal, Depends(current_principal)]
HumanAdmin = Annotated[Principal, Depends(require_action(Action.USER_MANAGE, GLOBAL))]
SettingsAdmin = Annotated[Principal, Depends(require_action(Action.SETTINGS_MANAGE, GLOBAL))]
GENERIC_LOGIN_ERROR = "Invalid username, password or code."


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- helpers --------------------------------------------------------------------------------------------------


def _set_session_cookie(response: Response, session_id: str) -> None:
    # __Host- prefix: Secure, Path=/, no Domain. No max-age: the lifetime is enforced server-side.
    response.set_cookie(
        csrf_mod.SESSION_COOKIE, session_id, httponly=True, secure=True, samesite="lax", path="/"
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        csrf_mod.SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax"
    )


def _link_url(settings: Settings, raw: str) -> str:
    return f"{(settings.external_url or '').rstrip('/')}/enrol/{raw}"


def _audit(
    db: Session, who: Principal, action: str, target_type: str, target_id: str | None, **kw: Any
) -> None:
    audit.record(
        db,
        action=action,
        target_type=target_type,
        target_id=target_id,
        actor_id=who.user_id,
        principal_type=who.principal_type,
        auth_method=who.auth_method,
        source_ip=who.source_ip,
        **kw,
    )


def _login_problem(exc: Exception) -> ProblemError:
    if isinstance(exc, login_svc.RateLimitedError):
        return ProblemError(
            429,
            "rate-limited",
            "Too many attempts",
            "Too many failed attempts; wait before trying again.",
            next_action=f"Retry in {exc.retry_after} seconds.",
            headers={"Retry-After": str(exc.retry_after)},
        )
    if isinstance(exc, TotpUnavailableError):
        log.error("TOTP unavailable: %s", exc)
        return ProblemError(
            503,
            "totp-unavailable",
            "TOTP is not configured",
            "The server cannot verify TOTP codes right now.",
        )
    return ProblemError(401, "invalid-credentials", "Invalid credentials", GENERIC_LOGIN_ERROR)


def _render(request: Request, name: str, status: int = 200, **ctx: Any) -> HTMLResponse:
    return templates.TemplateResponse(
        request, name, {"version": __version__, **ctx}, status_code=status
    )


async def _form_page(request: Request, name: str, status: int = 200, **ctx: Any) -> HTMLResponse:
    token = csrf_mod.new_form_token()
    response = _render(request, name, status, csrf_token=token, **ctx)
    csrf_mod.set_form_cookie(response, token)
    return response


# --- login / logout pages -------------------------------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request) -> HTMLResponse:
    return await _form_page(request, "auth/login.html", error=None)


@router.post("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_submit(
    request: Request,
    db: Db,
    settings: Cfg,
    hasher: Hasher,
    vault: Vault,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    totp_code: Annotated[str, Form()] = "",
) -> Response:
    if not await csrf_mod.check_form_token(request, settings):
        return await _form_page(
            request, "auth/login.html", 403, error="The form expired. Please try again."
        )
    try:
        result = await run_in_threadpool(
            login_svc.login,
            db,
            settings,
            hasher,
            vault,
            username=username,
            password=password,
            totp_code=totp_code or None,
            source_ip=client_ip(request),
        )
    except (login_svc.AuthFailedError, login_svc.RateLimitedError, TotpUnavailableError) as exc:
        problem = _login_problem(exc)
        page = await _form_page(
            request,
            "auth/login.html",
            problem.status_code,
            error=GENERIC_LOGIN_ERROR if problem.status_code == 401 else problem.detail,
        )
        for k, v in (problem.headers or {}).items():
            page.headers[k] = v
        return page
    response = RedirectResponse(
        "/account/totp" if result.totp_enrolment_required else "/", status_code=303
    )
    _set_session_cookie(response, result.session_id)
    response.delete_cookie(csrf_mod.FORM_COOKIE, path="/", secure=True, httponly=True)
    return response


@router.post("/logout", include_in_schema=False)
def logout_submit(request: Request, db: Db, who: Me) -> Response:
    if who.session_hash:
        delete_session(db, who.session_hash)
        _audit(db, who, "auth.logout", "session", None, after={"auth_method": who.auth_method})
        db.commit()
    response = RedirectResponse("/login", status_code=303)
    _clear_session_cookie(response)
    return response


# --- enrolment pages ------------------------------------------------------------------------------------------


@router.get("/enrol/{link}", response_class=HTMLResponse, include_in_schema=False)
async def enrol_page(request: Request, link: str, db: Db) -> HTMLResponse:
    info = await run_in_threadpool(users.peek_link, db, link)
    if info is None:
        return _render(
            request,
            "auth/message.html",
            404,
            title="Link not valid",
            message=(
                "This link is invalid, expired or already used. Ask an administrator for a new one."
            ),
        )
    return await _form_page(
        request,
        "auth/enrol.html",
        link=link,
        username=info.username,
        purpose=info.purpose,
        error=None,
    )


@router.post("/enrol/{link}", response_class=HTMLResponse, include_in_schema=False)
async def enrol_submit(
    request: Request,
    link: str,
    db: Db,
    settings: Cfg,
    hasher: Hasher,
    password: Annotated[str, Form()],
    password_confirm: Annotated[str, Form()],
) -> Response:
    if not await csrf_mod.check_form_token(request, settings):
        return _render(
            request,
            "auth/message.html",
            403,
            title="Form expired",
            message=("The form expired. Reload the link and try again."),
        )
    info = await run_in_threadpool(users.peek_link, db, link)
    if info is None:
        return _render(
            request,
            "auth/message.html",
            404,
            title="Link not valid",
            message=(
                "This link is invalid, expired or already used. Ask an administrator for a new one."
            ),
        )

    def complete() -> tuple[str, bool]:
        if password != password_confirm:
            raise passwords.PasswordPolicyError("The two passwords do not match.")
        done, created_by = users.redeem_link(db, hasher, link, password)
        session_id, _csrf = create_session(
            db, settings, user_id=done.user_id, auth_method="password", source_ip=client_ip(request)
        )
        audit.record(
            db,
            action="user.enrol" if done.purpose == "enrol" else "user.credential_reset",
            target_type="user",
            target_id=str(done.user_id),
            actor_id=done.user_id,
            auth_method="password",
            source_ip=client_ip(request),
            after={"state": "active"},
            authority_ref=str(created_by) if created_by else None,
        )
        needs = login_svc.needs_totp(users.load_bindings(db, done.user_id))
        db.commit()
        return session_id, needs

    try:
        session_id, needs_totp = await run_in_threadpool(complete)
    except passwords.PasswordPolicyError as exc:
        db.rollback()
        return await _form_page(
            request,
            "auth/enrol.html",
            422,
            link=link,
            username=info.username,
            purpose=info.purpose,
            error=str(exc),
        )
    except users.LinkInvalidError:
        db.rollback()
        return _render(
            request,
            "auth/message.html",
            404,
            title="Link not valid",
            message=(
                "This link is invalid, expired or already used. Ask an administrator for a new one."
            ),
        )
    response = RedirectResponse("/account/totp" if needs_totp else "/", status_code=303)
    _set_session_cookie(response, session_id)
    response.delete_cookie(csrf_mod.FORM_COOKIE, path="/", secure=True, httponly=True)
    return response


# --- TOTP pages -----------------------------------------------------------------------------------------------


@router.get("/account/totp", response_class=HTMLResponse, include_in_schema=False)
def totp_page(request: Request, who: Me) -> HTMLResponse:
    return _render(
        request,
        "auth/totp.html",
        csrf_token=who.csrf_token,
        confirmed=who.totp_confirmed,
        required=who.totp_enrolment_required,
        secret=None,
        uri=None,
        error=None,
    )


@router.post("/account/totp/enrol", response_class=HTMLResponse, include_in_schema=False)
def totp_page_enrol(request: Request, db: Db, who: Me, vault: Vault) -> HTMLResponse:
    try:
        secret, uri = login_svc.begin_totp_enrolment(db, vault, who)
    except (login_svc.TotpFlowError, TotpUnavailableError) as exc:
        return _render(
            request,
            "auth/totp.html",
            409,
            csrf_token=who.csrf_token,
            confirmed=who.totp_confirmed,
            required=who.totp_enrolment_required,
            secret=None,
            uri=None,
            error=str(exc),
        )
    return _render(
        request,
        "auth/totp.html",
        csrf_token=who.csrf_token,
        confirmed=False,
        required=who.totp_enrolment_required,
        secret=secret,
        uri=uri,
        error=None,
    )


@router.post("/account/totp/confirm", include_in_schema=False)
def totp_page_confirm(
    request: Request, db: Db, settings: Cfg, who: Me, vault: Vault, code: Annotated[str, Form()]
) -> Response:
    try:
        session_id, _ = login_svc.confirm_totp(db, settings, vault, who, code)
    except (
        login_svc.TotpFlowError,
        login_svc.AuthFailedError,
        login_svc.RateLimitedError,
        TotpUnavailableError,
    ) as exc:
        message = str(exc) if isinstance(exc, login_svc.TotpFlowError) else "The code is not valid."
        return _render(
            request,
            "auth/totp.html",
            422,
            csrf_token=who.csrf_token,
            confirmed=False,
            required=who.totp_enrolment_required,
            secret=None,
            uri=None,
            error=message,
        )
    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, session_id)
    return response


# --- JSON: session --------------------------------------------------------------------------------------------


class LoginBody(_Body):
    username: str = Field(max_length=256)
    password: str = Field(max_length=1024)
    totp_code: str | None = Field(default=None, max_length=16)


def _whoami(who: Principal) -> dict[str, Any]:
    return {
        "user_id": str(who.user_id),
        "username": who.username,
        "principal_type": who.principal_type,
        "auth_method": who.auth_method,
        "roles": [{"role": r, "scope": s} for r, s in sorted(who.grants)],
        "totp": {
            "confirmed": who.totp_confirmed,
            "enrolment_required": who.totp_enrolment_required,
        },
        "token_scopes": sorted(who.token_scopes),
    }


@router.post("/api/v1/session")
def api_login(
    body: LoginBody, request: Request, db: Db, settings: Cfg, hasher: Hasher, vault: Vault
) -> JSONResponse:
    if "origin" in request.headers and not csrf_mod.origin_allowed(request, settings):
        raise forbidden("csrf-failed", "The request origin is not allowed.")
    try:
        result = login_svc.login(
            db,
            settings,
            hasher,
            vault,
            username=body.username,
            password=body.password,
            totp_code=body.totp_code,
            source_ip=client_ip(request),
        )
    except (login_svc.AuthFailedError, login_svc.RateLimitedError, TotpUnavailableError) as exc:
        raise _login_problem(exc) from None
    response = JSONResponse(
        {
            "user_id": str(result.user_id),
            "auth_method": result.auth_method,
            "csrf_token": result.csrf_token,
            "totp_enrolment_required": result.totp_enrolment_required,
        }
    )
    _set_session_cookie(response, result.session_id)
    return response


@router.get("/api/v1/session")
def api_whoami(who: Me) -> dict[str, Any]:
    body = _whoami(who)
    if who.csrf_token:
        body["csrf_token"] = who.csrf_token
    return body


@router.delete("/api/v1/session", status_code=204)
def api_logout(db: Db, who: Me) -> Response:
    if not who.session_hash:
        raise forbidden(
            "human-session-required", "Only a login session can be ended; revoke tokens instead."
        )
    delete_session(db, who.session_hash)
    _audit(db, who, "auth.logout", "session", None, after={"auth_method": who.auth_method})
    db.commit()
    response = Response(status_code=204)
    _clear_session_cookie(response)
    return response


@router.post("/api/v1/session/totp/enrol")
def api_totp_enrol(db: Db, who: Me, vault: Vault) -> dict[str, str]:
    try:
        secret, uri = login_svc.begin_totp_enrolment(db, vault, who)
    except login_svc.TotpFlowError as exc:
        raise ProblemError(
            409 if exc.code != "human-session-required" else 403,
            exc.code,
            "TOTP enrolment refused",
            str(exc),
        ) from None
    except TotpUnavailableError as exc:
        raise _login_problem(exc) from None
    return {"secret": secret, "otpauth_uri": uri}


class CodeBody(_Body):
    code: str = Field(max_length=16)


@router.post("/api/v1/session/totp/confirm")
def api_totp_confirm(body: CodeBody, db: Db, settings: Cfg, who: Me, vault: Vault) -> JSONResponse:
    try:
        session_id, csrf = login_svc.confirm_totp(db, settings, vault, who, body.code)
    except login_svc.TotpFlowError as exc:
        raise ProblemError(409, exc.code, "TOTP confirmation refused", str(exc)) from None
    except (login_svc.AuthFailedError, login_svc.RateLimitedError, TotpUnavailableError) as exc:
        raise _login_problem(exc) from None
    response = JSONResponse({"confirmed": True, "csrf_token": csrf})
    _set_session_cookie(response, session_id)
    return response


class ReauthBody(_Body):
    password: str = Field(max_length=1024)
    totp_code: str | None = Field(default=None, max_length=16)
    action: str = Field(min_length=1, max_length=100)
    target_id: str = Field(min_length=1, max_length=200)


@router.post("/api/v1/session/reauth")
def api_reauth(
    body: ReauthBody, db: Db, settings: Cfg, hasher: Hasher, vault: Vault, who: Me
) -> dict[str, Any]:
    if not who.is_human:
        raise forbidden("human-session-required", "Step-up needs an interactive human session.")
    try:
        step = login_svc.reauth(
            db,
            settings,
            hasher,
            vault,
            who,
            password=body.password,
            totp_code=body.totp_code,
            action=body.action,
            target_id=body.target_id,
        )
    except login_svc.TotpFlowError as exc:
        raise ProblemError(403, exc.code, "Step-up refused", str(exc)) from None
    except (login_svc.AuthFailedError, login_svc.RateLimitedError, TotpUnavailableError) as exc:
        raise _login_problem(exc) from None
    return {
        "stepup_id": str(step.id),
        "action": step.action,
        "target_id": step.target_id,
        "expires_at": step.expires_at.isoformat()
        if hasattr(step.expires_at, "isoformat")
        else None,
    }


# --- JSON: API tokens -----------------------------------------------------------------------------------------


class TokenBody(_Body):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(min_length=1, max_length=3)
    project_scope: str = GLOBAL
    expires_in_days: int = Field(default=30, ge=1, le=tokens.MAX_DAYS)


@router.post("/api/v1/tokens", status_code=201)
def api_token_create(
    body: TokenBody,
    db: Db,
    who: Annotated[Principal, Depends(require_role("viewer", human_only=True))],
) -> dict[str, Any]:
    try:
        project_scope = users.check_scope(body.project_scope)  # canonical form (SEC-C-8)
        tokens.validate_request(
            sorted(who.grants), body.scopes, project_scope, body.expires_in_days
        )
    except ValueError as exc:
        raise ProblemError(422, "token-scope-exceeded", "Token not allowed", str(exc)) from None
    token_id, raw, expires_at = tokens.create_token(
        db,
        user_id=who.user_id,
        name=body.name,
        scopes=body.scopes,
        project_scope=project_scope,
        days=body.expires_in_days,
    )
    _audit(
        db,
        who,
        "token.create",
        "api_token",
        str(token_id),
        after={
            "name": body.name,
            "scopes": body.scopes,
            "project_scope": project_scope,
            "expires_at": expires_at,
            "owner_id": str(who.user_id),
        },
    )
    db.commit()
    return {
        "id": str(token_id),
        "token": raw,
        "expires_at": expires_at.isoformat(),
        "scopes": sorted(body.scopes),
        "project_scope": body.project_scope,
        "note": "The token is shown once; only its hash is stored.",
    }


@router.get("/api/v1/tokens")
def api_token_list(
    db: Db, who: Annotated[Principal, Depends(require_role("viewer", human_only=True))]
) -> dict[str, Any]:
    rows = db.execute(
        text(
            "SELECT id, name, scopes, project_scope, created_at, expires_at, last_used_at, revoked_at "
            "FROM api_token WHERE user_id = :u ORDER BY created_at DESC"
        ),
        {"u": who.user_id},
    ).all()
    return {
        "items": [
            {
                "id": str(r.id),
                "name": r.name,
                "scopes": list(r.scopes),
                "project_scope": r.project_scope,
                "created_at": r.created_at.isoformat(),
                "expires_at": r.expires_at.isoformat(),
                "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
                "revoked": r.revoked_at is not None,
            }
            for r in rows
        ]
    }


@router.delete("/api/v1/tokens/{token_id}", status_code=204)
def api_token_revoke(
    token_id: UUID,
    db: Db,
    who: Annotated[Principal, Depends(require_role("viewer", human_only=True))],
) -> Response:
    owner = db.execute(
        text("SELECT user_id FROM api_token WHERE id = :id"), {"id": token_id}
    ).scalar_one_or_none()
    is_admin = ("admin", GLOBAL) in who.grants
    if owner is None or (owner != who.user_id and not is_admin):
        raise ProblemError(404, "not-found", "Token not found", "No such token.")
    if tokens.revoke_token(db, token_id, revoked_by=who.user_id):
        _audit(db, who, "token.revoke", "api_token", str(token_id), after={"owner_id": str(owner)})
    db.commit()
    return Response(status_code=204)


# --- JSON: users and role bindings (admin, human session) ----------------------------------------------------


class RoleSpec(_Body):
    role: str
    scope: str = GLOBAL


class UserBody(_Body):
    """There is deliberately no password field: unknown fields are refused (422)."""

    username: str = Field(max_length=64)
    display_name: str = Field(default="", max_length=200)
    roles: list[RoleSpec] = Field(default_factory=list, max_length=20)


def _issue_link_response(
    db: Db, settings: Settings, who: Principal, user_id: UUID, purpose: str
) -> dict[str, Any]:
    link_id, raw = users.issue_link(
        db, settings, user_id=user_id, purpose=purpose, created_by=who.user_id
    )
    _audit(
        db,
        who,
        "user.enrolment_link.issue",
        "enrolment_link",
        str(link_id),
        after={"purpose": purpose, "user_id": str(user_id)},
    )
    return {
        "enrolment_link": _link_url(settings, raw),
        "purpose": purpose,
        "expires_in_hours": settings.auth.enrolment_link_hours,
        "note": "Single-use. Give it to the user; the user chooses their own password.",
    }


@router.post("/api/v1/users", status_code=201)
def api_user_create(body: UserBody, db: Db, settings: Cfg, who: HumanAdmin) -> dict[str, Any]:
    held: list[tuple[str, str]] = []
    for (
        r
    ) in body.roles:  # operator + approver in one scope is refused here too (security-model.md 3.2)
        sod.check_binding_sod(db, held, r.role, r.scope)
        held.append((r.role, r.scope))
    try:
        user_id = users.create_user(
            db,
            username=body.username,
            display_name=body.display_name,
            created_by=who.user_id,
            created_via="admin",
            bindings=[(r.role, r.scope) for r in body.roles],
        )
    except users.ScopeNotFoundError:
        db.rollback()
        raise ProblemError(
            404, "not-found", "Project not found", "No such project connection."
        ) from None
    except users.UserError as exc:
        db.rollback()
        raise ProblemError(422, "invalid-user", "User not created", str(exc)) from None
    _audit(
        db,
        who,
        "user.create",
        "user",
        str(user_id),
        after={
            "username": users.normalise_username(body.username),
            "display_name": body.display_name,
            "state": "pending_enrolment",
            "created_via": "admin",
            "roles": [f"{r.role}@{canonical_scope(r.scope)}" for r in body.roles],
        },
    )
    result = _issue_link_response(db, settings, who, user_id, "enrol")
    db.commit()
    return {"user_id": str(user_id), **result}


@router.get("/api/v1/users")
def api_user_list(db: Db, who: HumanAdmin) -> dict[str, Any]:
    rows = db.execute(
        text(
            "SELECT id, username, display_name, state, created_by, created_at, credential_reset_by, "
            "credential_reset_at, (totp_confirmed_at IS NOT NULL) AS totp FROM app_user ORDER BY username"
        )
    ).all()
    return {
        "items": [
            {
                "id": str(r.id),
                "username": r.username,
                "display_name": r.display_name,
                "state": r.state,
                "totp_enrolled": r.totp,
                "created_by": str(r.created_by) if r.created_by else None,
                "created_at": r.created_at.isoformat(),
                "credential_reset_by": str(r.credential_reset_by)
                if r.credential_reset_by
                else None,
                "credential_reset_at": r.credential_reset_at.isoformat()
                if r.credential_reset_at
                else None,
            }
            for r in rows
        ]
    }


@router.post("/api/v1/users/{user_id}/enrolment-link")
def api_user_reset(user_id: UUID, db: Db, settings: Cfg, who: HumanAdmin) -> dict[str, Any]:
    row = db.execute(
        text("SELECT state FROM app_user WHERE id = :u"), {"u": user_id}
    ).scalar_one_or_none()
    if row is None or row == "disabled":
        raise ProblemError(404, "not-found", "User not found", "No such active user.")
    result = _issue_link_response(
        db, settings, who, user_id, "enrol" if row == "pending_enrolment" else "reset"
    )
    db.commit()
    return result


@router.post("/api/v1/users/{user_id}/disable", status_code=204)
def api_user_disable(user_id: UUID, db: Db, who: HumanAdmin) -> Response:
    if users.disable_user(db, user_id):
        _audit(db, who, "user.disable", "user", str(user_id), after={"state": "disabled"})
    db.commit()
    return Response(status_code=204)


class BindingBody(_Body):
    user_id: UUID
    role: str
    scope: str = GLOBAL


def _user_state(db: Session, user_id: UUID) -> str | None:
    state: str | None = db.execute(
        text("SELECT state FROM app_user WHERE id = :u"), {"u": user_id}
    ).scalar_one_or_none()
    return state


def _guard_own_bindings(db: Session, who: Principal, user_id: UUID) -> bool:
    """An admin may not change their own bindings unless they are the only admin (security-model.md 3.1).
    Returns True when it is such an allowed self-change (the audit row then says so)."""
    if user_id != who.user_id:
        return False
    others = db.execute(
        text(
            """
            SELECT count(DISTINCT b.user_id) FROM role_binding b JOIN app_user u ON u.id = b.user_id
            WHERE b.role = 'admin' AND b.scope = 'global' AND b.revoked_at IS NULL
              AND u.state = 'active' AND b.user_id <> :me
            """
        ),
        {"me": who.user_id},
    ).scalar_one()
    if others:
        raise forbidden(
            "own-bindings",
            "Admins cannot change their own role bindings while another admin exists; ask another admin.",
        )
    return True


@router.post("/api/v1/role-bindings", status_code=201)
def api_binding_create(
    body: BindingBody, db: Db, who: HumanAdmin, response: Response
) -> dict[str, Any]:
    if _user_state(db, body.user_id) in (None, "disabled"):
        raise ProblemError(404, "not-found", "User not found", "No such active user.")
    own = _guard_own_bindings(db, who, body.user_id)
    try:
        scope = users.check_scope(body.scope)  # UUID project scopes in canonical form (SEC-C-8)
        users.check_project_exists(db, scope)
    except users.ScopeNotFoundError:
        raise ProblemError(
            404, "not-found", "Project not found", "No such project connection."
        ) from None
    except users.UserError as exc:
        raise ProblemError(422, "invalid-binding", "Binding not created", str(exc)) from None
    sod.check_binding_sod(db, users.load_bindings(db, body.user_id), body.role, scope)
    try:
        result = users.add_binding(
            db, user_id=body.user_id, role=body.role, scope=scope, created_by=who.user_id
        )
    except users.UserError as exc:
        raise ProblemError(422, "invalid-binding", "Binding not created", str(exc)) from None
    if (
        not result.created
    ):  # an identical active binding exists: nothing changed, nothing audited (SEC-C-9)
        db.rollback()
        response.status_code = 200
        return {"id": str(result.id), "created": False}
    _audit(
        db,
        who,
        "role_binding.create.own" if own else "role_binding.create",
        "role_binding",
        str(result.id),
        after={"user_id": str(body.user_id), "role": body.role, "scope": result.scope},
    )
    delete_user_sessions(db, body.user_id)  # privilege change: new session id at next login
    db.commit()
    return {"id": str(result.id), "created": True}


@router.get("/api/v1/role-bindings")
def api_binding_list(
    db: Db, who: HumanAdmin, user_id: UUID | None = None, include_revoked: bool = False
) -> dict[str, Any]:
    rows = db.execute(
        text(
            """
            SELECT b.id, b.user_id, u.username, b.role, b.scope, b.created_by, b.created_at,
                   b.revoked_by, b.revoked_at
            FROM role_binding b JOIN app_user u ON u.id = b.user_id
            WHERE (CAST(:u AS uuid) IS NULL OR b.user_id = :u) AND (:all OR b.revoked_at IS NULL)
            ORDER BY u.username, b.created_at
            """
        ),
        {"u": user_id, "all": include_revoked},
    ).all()
    return {
        "items": [
            {
                "id": str(r.id),
                "user_id": str(r.user_id),
                "username": r.username,
                "role": r.role,
                "scope": r.scope,
                "created_by": str(r.created_by) if r.created_by else None,
                "created_at": r.created_at.isoformat(),
                "revoked_by": str(r.revoked_by) if r.revoked_by else None,
                "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            }
            for r in rows
        ]
    }


@router.delete("/api/v1/role-bindings/{binding_id}", status_code=204)
def api_binding_revoke(binding_id: UUID, db: Db, who: HumanAdmin) -> Response:
    owner = db.execute(
        text("SELECT user_id FROM role_binding WHERE id = :id AND revoked_at IS NULL"),
        {"id": binding_id},
    ).scalar_one_or_none()
    if owner is None:
        raise ProblemError(404, "not-found", "Binding not found", "No such active binding.")
    own = _guard_own_bindings(db, who, owner)
    gone = users.revoke_binding(db, binding_id, revoked_by=who.user_id)
    if gone is None:
        raise ProblemError(404, "not-found", "Binding not found", "No such active binding.")
    user_id, role, scope = gone
    _audit(
        db,
        who,
        "role_binding.revoke.own" if own else "role_binding.revoke",
        "role_binding",
        str(binding_id),
        before={"user_id": str(user_id), "role": role, "scope": scope},
    )
    delete_user_sessions(db, user_id)
    db.commit()
    return Response(status_code=204)


@router.get("/api/v1/users/{user_id}")
def api_user_get(user_id: UUID, db: Db, who: HumanAdmin) -> dict[str, Any]:
    row = db.execute(
        text(
            "SELECT id, username, display_name, state, (totp_confirmed_at IS NOT NULL) AS totp "
            "FROM app_user WHERE id = :u"
        ),
        {"u": user_id},
    ).first()
    if row is None:
        raise ProblemError(404, "not-found", "User not found", "No such user.")
    return {
        "id": str(row.id),
        "username": row.username,
        "display_name": row.display_name,
        "state": row.state,
        "totp_enrolled": row.totp,
        "roles": [{"role": r, "scope": s} for r, s in sorted(users.load_bindings(db, user_id))],
        "provenance": sod.account_provenance(db, user_id),
    }


# --- JSON: installation settings (admin, human session, TOTP step-up, typed confirmation) -------------------

SETTING_STEPUP_ACTION = "settings.auth.update"


class AuthSettingsBody(_Body):
    allow_operator_approver: bool
    stepup_id: UUID
    #: Must read ``allow_operator_approver=true`` or ``allow_operator_approver=false``, matching the value.
    typed_confirmation: str = Field(max_length=100)
    reason: str = Field(default="", max_length=500)


@router.get("/api/v1/settings/auth")
def api_settings_auth_get(db: Db, who: SettingsAdmin) -> dict[str, Any]:
    return {
        "allow_operator_approver": installation.allow_operator_approver(db),
        "history": installation.setting_history(db, installation.ALLOW_OPERATOR_APPROVER),
        "stepup": {
            "action": SETTING_STEPUP_ACTION,
            "target_id": installation.ALLOW_OPERATOR_APPROVER,
        },
        "note": "When true, one person may hold operator and approver in a scope; their plan and cutover "
        "approvals are flagged self-approved. Retirement never allows self-approval.",
    }


@router.put("/api/v1/settings/auth")
def api_settings_auth_put(body: AuthSettingsBody, db: Db, who: SettingsAdmin) -> dict[str, Any]:
    value = body.allow_operator_approver
    expected = f"allow_operator_approver={'true' if value else 'false'}"
    if " ".join(body.typed_confirmation.split()).lower() != expected:
        raise ProblemError(
            422,
            "confirmation-mismatch",
            "Typed confirmation does not match",
            f"Type exactly '{expected}' to confirm.",
        )
    before = installation.allow_operator_approver(db)
    stepup_id = consume_stepup(
        db, who, body.stepup_id, action=SETTING_STEPUP_ACTION,
        target_id=installation.ALLOW_OPERATOR_APPROVER,
    )  # fmt: skip
    changed_at = installation.set_setting(
        db,
        installation.ALLOW_OPERATOR_APPROVER,
        value,
        changed_by=who.user_id,
        stepup_id=stepup_id,
        reason=body.reason,
    )
    _audit(
        db,
        who,
        "settings.auth.update",
        "installation_setting",
        installation.ALLOW_OPERATOR_APPROVER,
        before={"value": before},
        after={"value": value, "stepup_id": str(stepup_id), "reason": body.reason},
    )
    db.commit()
    return {"allow_operator_approver": value, "changed_at": changed_at.isoformat()}
