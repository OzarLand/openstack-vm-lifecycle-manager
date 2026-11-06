"""FastAPI dependencies: database session, current principal, and the reusable ``require_role(role, scope)``.

Typical use by other modules::

    @router.post("/projects/{project_id}/syncs")
    def start_sync(project_id: str,
                   who: Principal = Depends(require_role("operator", project_scope("project_id"),
                                                          token_scope="inventory:sync"))): ...

Authentication is resolved once per request: ``Authorization: Bearer ovlm_...`` (token, no CSRF) or the session
cookie (unsafe methods also need the CSRF token and a matching Origin). Anything else is ``401``.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from typing import Annotated, cast

from argon2 import PasswordHasher
from fastapi import Depends, Request
from sqlalchemy.orm import Session, sessionmaker

from ovlm.auth import csrf as csrf_mod
from ovlm.auth.authz import (
    MATRIX,
    Action,
    ScopeDecision,
    authorize,
    authorize_action,
    decide_in_scope,
    token_may,
)
from ovlm.auth.clientaddr import ClientAddress, resolve_client
from ovlm.auth.errors import ProblemError, forbidden, unauthenticated
from ovlm.auth.events import record_independent
from ovlm.auth.login import needs_totp
from ovlm.auth.passwords import make_hasher
from ovlm.auth.principal import TOTP_ROLES, Principal, Role
from ovlm.auth.sessions import load_session
from ovlm.auth.tokens import authenticate_token, token_grants
from ovlm.auth.totp import TotpUnavailableError, TotpVault
from ovlm.auth.users import load_bindings
from ovlm.config import Settings
from ovlm.db.engine import make_engine, make_session_factory

log = logging.getLogger("ovlm.auth")
_lock = threading.Lock()
_warned_no_forwarded = False
_DEFAULT_HASHER = make_hasher()
ScopeSpec = str | Callable[[Request], str | None] | None


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_session_factory(request: Request) -> sessionmaker[Session]:
    """``app.state.session_factory`` when the app set one, else built once from the settings (api DB role)."""
    app = request.app
    factory = getattr(app.state, "session_factory", None)
    if factory is None:
        with _lock:
            factory = getattr(app.state, "session_factory", None)
            if factory is None:
                engine = make_engine(app.state.settings)
                factory = make_session_factory(engine)
                app.state.auth_engine = engine
                app.state.session_factory = factory
    return cast("sessionmaker[Session]", factory)


def get_db(request: Request) -> Iterator[Session]:
    """One session per request. Handlers commit explicitly; anything uncommitted is rolled back on close."""
    with get_session_factory(request)() as session:
        yield session


def get_hasher(request: Request) -> PasswordHasher:
    hasher: PasswordHasher = getattr(request.app.state, "password_hasher", _DEFAULT_HASHER)
    return hasher


def get_vault(request: Request) -> TotpVault | None:
    """The TOTP vault, or ``None`` when no key is configured (TOTP then fails closed)."""
    app = request.app
    vault = getattr(app.state, "totp_vault", None)
    if vault is None:
        try:
            vault = TotpVault.from_file(app.state.settings.auth.totp_key_file)
        except (TotpUnavailableError, OSError):
            return None
        app.state.totp_vault = vault
    return cast(TotpVault, vault)


def client_address(request: Request) -> ClientAddress:
    """The client behind the trusted proxies (:mod:`ovlm.auth.clientaddr`), resolved once per request."""
    global _warned_no_forwarded  # noqa: PLW0603
    cached: ClientAddress | None = getattr(request.state, "client_address", None)
    if cached is not None:
        return cached
    settings: Settings = request.app.state.settings
    resolved = resolve_client(
        request.client.host if request.client else None,
        request.headers.getlist("x-forwarded-for"),
        settings.http.trusted_proxies,
    )
    if not resolved.attributable and not _warned_no_forwarded:
        _warned_no_forwarded = True
        log.warning(
            "a request from a trusted proxy names no client in X-Forwarded-For: its source address is "
            "unknown and only the per-account login limit applies; configure the proxy to set the header"
        )
    request.state.client_address = resolved
    return resolved


def client_ip(request: Request) -> str | None:
    """The client's address for audit rows, sessions and the per-source login limit.

    ``None`` when it is unknown: a trusted proxy that did not name the client. The proxy's own address is never
    returned for it, because it stands for every user at once (SEC-C-1)."""
    return client_address(request).rate_limit_key


def _endpoint(request: Request) -> str:
    route = request.scope.get("route")
    return f"{request.method} {getattr(route, 'path', request.url.path)}"


async def _supplied_csrf(request: Request) -> str | None:
    return await csrf_mod.supplied_csrf_token(request)


def current_principal(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    supplied_csrf: Annotated[str | None, Depends(_supplied_csrf)],
) -> Principal:
    cached: Principal | None = getattr(request.state, "principal", None)
    if cached is not None:
        return cached
    settings = get_settings(request)
    ip = client_ip(request)
    header = request.headers.get("authorization")
    if header is not None:
        scheme, _, credential = header.partition(" ")
        if scheme.lower() != "bearer":
            raise unauthenticated("Only 'Authorization: Bearer ovlm_<id>_<secret>' is accepted.")
        info = authenticate_token(db, credential.strip())
        if info is None:
            raise unauthenticated("The API token is invalid, expired or revoked.")
        principal = Principal(
            user_id=info.user_id,
            username=info.username,
            principal_type="token",
            auth_method="token",
            grants=token_grants(load_bindings(db, info.user_id), info.scopes, info.project_scope),
            source_ip=ip,
            token_id=info.id,
            token_scopes=info.scopes,
        )
    else:
        raw = request.cookies.get(csrf_mod.SESSION_COOKIE)
        info_s = load_session(db, settings, raw) if raw else None
        if info_s is None:
            raise unauthenticated("Log in to continue." if not raw else "Your session has expired.")
        if request.method not in csrf_mod.SAFE_METHODS and not (
            csrf_mod.origin_allowed(request, settings)
            and csrf_mod.tokens_equal(supplied_csrf, info_s.csrf_token)
        ):
            record_independent(
                db,
                action="auth.csrf.refused",
                target_type="endpoint",
                target_id=_endpoint(request),
                result="denied",
                actor_id=info_s.user_id,
                auth_method=info_s.auth_method,
                source_ip=ip,
            )
            raise forbidden("csrf-failed", "The CSRF token or the request origin is invalid.")
        bindings = load_bindings(db, info_s.user_id)
        privileged_ok = info_s.totp_confirmed and info_s.auth_method == "password+totp"
        principal = Principal(
            user_id=info_s.user_id,
            username=info_s.username,
            principal_type="human",
            auth_method=info_s.auth_method,
            grants=frozenset((r, s) for r, s in bindings if r not in TOTP_ROLES or privileged_ok),
            source_ip=ip,
            session_hash=info_s.id_hash,
            csrf_token=info_s.csrf_token,
            totp_confirmed=info_s.totp_confirmed,
            totp_enrolment_required=needs_totp(bindings) and not info_s.totp_confirmed,
        )
    request.state.principal = principal
    return principal


def project_scope(param: str) -> Callable[[Request], str]:
    """Scope from a path parameter: ``project_scope("project_id")`` -> ``project:<value>``."""

    def get(request: Request) -> str:
        return f"project:{request.path_params[param]}"

    return get


def require_role(
    role: Role,
    scope: ScopeSpec = None,
    *,
    human_only: bool = False,
    token_scope: str | None = None,
) -> Callable[..., Principal]:
    """Dependency factory: the caller must hold ``role`` covering ``scope``, else 401/403.

    * ``scope``: ``None`` (any scope the user holds; filter queries with :func:`ovlm.auth.authz.scopes_for`), a
      literal such as ``"global"`` / ``"project:abc"``, or a callable ``Request -> scope`` (:func:`project_scope`).
    * ``human_only``: API tokens get 403 (approvals, typed confirmations, user management: security-model 7.2).
    * ``token_scope``: for token callers at operator level, the endpoint's scope (``inventory:sync`` ...); a token
      holding only ``read`` or another scope is refused. ``operate`` tokens pass every operator endpoint.

    The decision itself is :func:`ovlm.auth.authz.authorize`. New endpoints should prefer :func:`require_action`,
    which reads the RBAC matrix. A denial on a mutating endpoint is audited.
    """

    def dependency(
        request: Request,
        principal: Annotated[Principal, Depends(current_principal)],
        db: Annotated[Session, Depends(get_db)],
    ) -> Principal:
        requested = scope(request) if callable(scope) else scope
        problem: ProblemError | None = None
        if human_only and not principal.is_human:
            problem = forbidden(
                "human-session-required",
                "This action needs an interactive human session; API tokens cannot do it.",
            )
        elif (
            not principal.is_human
            and role != "viewer"
            and not ({"operate"} | ({token_scope} if token_scope else set()))
            & principal.token_scopes
        ):
            problem = forbidden("token-scope", "The API token's scope does not allow this action.")
        elif not authorize(principal, role, requested):
            if principal.totp_enrolment_required and role in TOTP_ROLES:
                problem = forbidden(
                    "totp-enrolment-required",
                    f"The {role} role needs TOTP. Enrol TOTP in your session first.",
                )
            else:
                problem = forbidden("forbidden", principal.needs_role_message(role))
        if problem is None:
            return principal
        _audit_denial(request, db, principal, requested)
        raise problem

    return dependency


def _audit_denial(request: Request, db: Session, principal: Principal, scope: str | None) -> None:
    """Authorization denials on mutating endpoints are audited (security-model.md 8)."""
    if request.method in csrf_mod.SAFE_METHODS:
        return
    record_independent(
        db,
        action="authz.denied",
        target_type="endpoint",
        target_id=_endpoint(request),
        result="denied",
        actor_id=principal.user_id,
        principal_type=principal.principal_type,
        auth_method=principal.auth_method,
        source_ip=principal.source_ip,
        project_scope=scope,
    )


def _action_problem(principal: Principal, action: Action) -> ProblemError:
    rule = MATRIX[action]
    if not principal.is_human and rule.human_only:
        return forbidden(
            "human-session-required",
            "This action needs an interactive human session; API tokens cannot do it.",
        )
    if not token_may(principal, action):
        return forbidden("token-scope", "The API token's scope does not allow this action.")
    privileged = rule.roles & TOTP_ROLES
    if principal.totp_enrolment_required and privileged and rule.roles <= TOTP_ROLES:
        return forbidden(
            "totp-enrolment-required",
            f"This action needs the {'/'.join(sorted(privileged))} role, which needs TOTP. Enrol TOTP first.",
        )
    return forbidden("forbidden", f"Your roles do not allow '{action.value}' here.")


def require_action(action: Action, scope: ScopeSpec = None) -> Callable[..., Principal]:
    """Dependency factory reading the RBAC matrix (:data:`ovlm.auth.authz.MATRIX`): 401 unauthenticated, 403
    when no grant allows ``action`` in a scope covering ``scope``.

    With ``scope=None`` the check is "allowed in some scope"; the handler must then filter its query with
    :func:`ovlm.auth.authz.visible_projects` or check the resource with :func:`ensure_scope` once its project is
    known (out-of-scope resources answer 404, security-model.md 3.3).
    """

    def dependency(
        request: Request,
        principal: Annotated[Principal, Depends(current_principal)],
        db: Annotated[Session, Depends(get_db)],
    ) -> Principal:
        requested = scope(request) if callable(scope) else scope
        if authorize_action(principal, action, requested):
            return principal
        _audit_denial(request, db, principal, requested)
        raise _action_problem(principal, action)

    return dependency


def ensure_scope(
    request: Request,
    db: Session,
    principal: Principal,
    action: Action,
    scope: str | None,
    *,
    not_found: ProblemError,
) -> None:
    """Check ``action`` on one resource whose scope is now known.

    ``scope=None`` means the resource does not exist. A resource the caller cannot view raises ``not_found``
    (the same answer as a missing one, so existence never leaks); a visible one on which the action is not allowed
    raises 403. Denials on mutating requests are audited.
    """
    decision = (
        ScopeDecision.NOT_FOUND if scope is None else decide_in_scope(principal, action, scope)
    )
    if decision is ScopeDecision.ALLOWED:
        return
    if scope is not None:
        _audit_denial(request, db, principal, scope)
    if decision is ScopeDecision.NOT_FOUND:
        raise not_found
    raise _action_problem(principal, action)
