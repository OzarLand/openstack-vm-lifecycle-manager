"""Profiles and their immutable versions, api-design.md s.3.3.

Reads need ``viewer``; writes need ``operator`` (API tokens: scope ``operate``). A version is only ever created, never
changed (SEC-R-36). The profile's ETag is its row ``version``; ``POST /profiles/{id}/versions`` needs ``If-Match``.

Not implemented here, on purpose: the worker ``automation_lint`` run a new version should start (E5-3; versions answer
``lint_status: pending`` until it exists), the lint waiver endpoint (approver, step-up; needs ``lint_waiver``), the
repository allowlist check and the ``secret_refs`` ownership check (SEC-R-27; both need tables that do not exist yet).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.api.routes_common import IfMatch, ProblemRoute, audit_change, etag_of
from ovlm.auth.deps import get_db, require_role
from ovlm.auth.principal import Principal
from ovlm.profiles import service as profiles
from ovlm.profiles.errors import ProfileError
from ovlm.registry import service as registry
from ovlm.registry.errors import DomainError

VIEWER = Depends(require_role("viewer"))
OPERATOR = Depends(require_role("operator", token_scope="operate"))  # noqa: S106 - an API token scope name, not a secret

audit.register_entity("profile", ["service_id", "name", "latest_version", "version"])
# The spec is immutable and readable by (profile, number); the audit row names the version and the pinned automation.
audit.register_entity("profile_version", ["profile_id", "number", "automation_sha"])

router = APIRouter(prefix="/api/v1", route_class=ProblemRoute)

DB = Depends(get_db)


class ProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    spec: dict[str, Any]


class VersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: dict[str, Any]


def _scope_of_service(session: Session, service_id: UUID) -> str:
    svc = registry.get_service(session, service_id)
    if svc is None:
        raise DomainError(404, "service-not-found", "Service not found", "No such service.")
    return f"project:{svc['project_connection_id']}"


def _profile_or_404(session: Session, profile_id: UUID) -> dict[str, Any]:
    found = profiles.get_profile(session, profile_id)
    if found is None:
        raise ProfileError(404, "profile-not-found", "Profile not found", "No such profile.")
    return found


def _scope_of_profile(session: Session, profile: dict[str, Any]) -> str:
    return _scope_of_service(session, UUID(profile["service_id"]))


@router.get("/services/{service_id}/profiles")
def list_service_profiles(
    service_id: UUID, session: Session = DB, _: Principal = VIEWER
) -> dict[str, Any]:
    _scope_of_service(session, service_id)
    found = profiles.profile_of_service(session, service_id)
    return {"items": [found] if found else [], "next_cursor": None}


@router.post("/services/{service_id}/profiles", status_code=201)
def create_profile(
    service_id: UUID, body: ProfileCreate, response: Response, session: Session = DB, who: Principal = OPERATOR,
) -> dict[str, Any]:  # fmt: skip
    scope = _scope_of_service(session, service_id)
    created, version = profiles.create_profile(
        session, service_id, name=body.name, spec=body.spec, actor_id=who.user_id
    )
    audit_change(
        session, who, "profile.create", "profile", created["id"], scope=scope, after=created
    )
    audit_change(
        session,
        who,
        "profile.version.create",
        "profile_version",
        version["id"],
        scope=scope,
        after=version,
    )
    session.commit()
    response.headers["Location"] = f"/api/v1/profiles/{created['id']}"
    response.headers["ETag"] = etag_of(created["version"])
    return {**created, "latest": version}


@router.get("/profiles/{profile_id}")
def get_profile(
    profile_id: UUID, response: Response, session: Session = DB, _: Principal = VIEWER
) -> dict[str, Any]:
    found = _profile_or_404(session, profile_id)
    latest = (
        profiles.get_version(session, profile_id, found["latest_version"])
        if found["latest_version"]
        else None
    )
    response.headers["ETag"] = etag_of(found["version"])
    return {**found, "latest": latest}


@router.post("/profiles/{profile_id}/versions", status_code=201)
def create_version(
    profile_id: UUID, body: VersionCreate, response: Response, if_match: IfMatch = None,
    session: Session = DB, who: Principal = OPERATOR,
) -> dict[str, Any]:  # fmt: skip
    expected = registry.parse_if_match(if_match)
    scope = _scope_of_profile(session, _profile_or_404(session, profile_id))
    updated, version = profiles.add_version(
        session, profile_id, expected, spec=body.spec, actor_id=who.user_id
    )
    audit_change(
        session,
        who,
        "profile.version.create",
        "profile_version",
        version["id"],
        scope=scope,
        after=version,
    )
    audit_change(
        session, who, "profile.update", "profile", str(profile_id), scope=scope, after=updated
    )
    session.commit()
    response.headers["Location"] = f"/api/v1/profiles/{profile_id}/versions/{version['number']}"
    response.headers["ETag"] = etag_of(updated["version"])
    return version


@router.get("/profiles/{profile_id}/versions")
def list_versions(
    profile_id: UUID, limit: int | None = Query(default=None, ge=1, le=200), cursor: str | None = None,
    session: Session = DB, _: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    _profile_or_404(session, profile_id)
    try:
        items, nxt = profiles.list_versions(session, profile_id, limit=limit, cursor=cursor)
    except profiles.InvalidCursorError:
        raise DomainError(400, "invalid-cursor", "Invalid cursor", "The cursor is malformed.",
                          "Restart from the first page.") from None  # fmt: skip
    return {"items": items, "next_cursor": nxt}


@router.get("/profiles/{profile_id}/versions/{number}")
def get_version(
    profile_id: UUID, number: int, session: Session = DB, _: Principal = VIEWER
) -> dict[str, Any]:
    found = profiles.get_version(session, profile_id, number)
    if found is None:
        raise ProfileError(
            404, "profile-version-not-found", "Profile version not found", "No such version."
        )
    return found
