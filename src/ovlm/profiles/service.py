"""Profiles and immutable versions: functions for the api. Transactions belong to the caller.

A version is only ever INSERTed (SEC-R-36: the api role has no UPDATE or DELETE on ``profile_version``). Creating
one bumps ``profile.version`` (the ETag) and ``latest_version`` in the same statement the caller's ``If-Match`` is
checked in, so two concurrent writers cannot both get the same number.

INTEGRATION POINT (E5-3, stubbed): the design says a new version also starts a worker ``automation_lint`` run.
Nothing starts one yet: ``lint_result`` stays ``null`` ("lint pending") until that worker job exists.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Row, func, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ovlm.profiles.errors import ProfileError
from ovlm.profiles.spec import canonical, spec_hash, validate_spec
from ovlm.profiles.tables import profile, profile_version

MAX_PAGE = 200
DEFAULT_PAGE = 50


def etag(version: int) -> str:
    return f'"{version}"'


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _profile_dict(r: Row[Any]) -> dict[str, Any]:
    return {
        "id": str(r.id), "service_id": str(r.service_id), "name": r.name,
        "latest_version": r.latest_version, "version": r.version,
        "created_by": str(r.created_by) if r.created_by else None,
        "created_at": _iso(r.created_at), "updated_at": _iso(r.updated_at),
    }  # fmt: skip


def _version_dict(r: Row[Any], *, with_spec: bool = True) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": str(r.id), "profile_id": str(r.profile_id), "number": r.number,
        "spec_hash": r.spec_hash, "automation_sha": r.automation_sha,
        "created_by": str(r.created_by) if r.created_by else None,
        "created_at": _iso(r.created_at), "lint_result": r.lint_result,
        "lint_status": "pending" if r.lint_result is None else "done",
    }  # fmt: skip
    if with_spec:
        body["spec"] = r.spec
    return body


def _stale() -> ProfileError:
    return ProfileError(412, "etag-mismatch", "Precondition failed", "The profile was changed since you read it.",
                        "GET the profile again and retry.")  # fmt: skip


def get_profile(session: Session, profile_id: UUID) -> dict[str, Any] | None:
    row = session.execute(select(profile).where(profile.c.id == profile_id)).first()
    return _profile_dict(row) if row else None


def profile_of_service(session: Session, service_id: UUID) -> dict[str, Any] | None:
    row = session.execute(select(profile).where(profile.c.service_id == service_id)).first()
    return _profile_dict(row) if row else None


def create_profile(
    session: Session, service_id: UUID, *, name: str, spec: Any, actor_id: UUID | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The service's profile with its version 1. One profile per service in the MVP (409 if it exists)."""
    validated = validate_spec(spec)
    pid = uuid4()
    try:
        with session.begin_nested():
            session.execute(
                insert(profile).values(
                    id=pid, service_id=service_id, name=name, created_by=actor_id
                )
            )
    except IntegrityError:
        raise ProfileError(409, "profile-exists", "Service already has a profile",
                           "One profile per service in the MVP: add a version to it instead.",
                           "POST /api/v1/profiles/{id}/versions on the existing profile.") from None  # fmt: skip
    version = _insert_version(session, pid, 1, validated, actor_id)
    row = session.execute(
        update(profile).where(profile.c.id == pid).values(latest_version=1).returning(profile)
    ).one()
    return _profile_dict(row), version


def _insert_version(
    session: Session, profile_id: UUID, number: int, spec: Any, actor_id: UUID | None
) -> dict[str, Any]:
    body = canonical(spec)
    row = session.execute(
        insert(profile_version)
        .values(
            id=uuid4(), profile_id=profile_id, number=number, spec=body, spec_hash=spec_hash(spec),
            automation_sha=spec.automation.sha, created_by=actor_id,
        )
        .returning(profile_version)
    ).one()  # fmt: skip
    return _version_dict(row)


def add_version(
    session: Session, profile_id: UUID, expected_version: int, *, spec: Any, actor_id: UUID | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Insert the next immutable version. ``expected_version`` is the profile's ETag value."""
    validated = validate_spec(spec)
    if get_profile(session, profile_id) is None:
        raise ProfileError(404, "profile-not-found", "Profile not found", "No such profile.")
    claimed = session.execute(
        update(profile)
        .where(profile.c.id == profile_id, profile.c.version == expected_version)
        .values(
            latest_version=profile.c.latest_version + 1,
            version=profile.c.version + 1,
            updated_at=func.now(),
        )
        .returning(profile)
    ).first()
    if claimed is None:
        raise _stale()
    version = _insert_version(session, profile_id, claimed.latest_version, validated, actor_id)
    return _profile_dict(claimed), version


def get_version(session: Session, profile_id: UUID, number: int) -> dict[str, Any] | None:
    row = session.execute(
        select(profile_version).where(
            profile_version.c.profile_id == profile_id, profile_version.c.number == number
        )
    ).first()
    return _version_dict(row) if row else None


def get_version_by_id(session: Session, version_id: UUID) -> dict[str, Any] | None:
    row = session.execute(select(profile_version).where(profile_version.c.id == version_id)).first()
    return _version_dict(row) if row else None


class InvalidCursorError(ValueError):
    pass


def _decode(cursor: str) -> int:
    try:
        n = int(base64.urlsafe_b64decode(cursor.encode()).decode())
    except (ValueError, UnicodeError):
        raise InvalidCursorError(cursor) from None
    if n < 0:
        raise InvalidCursorError(cursor)
    return n


def list_versions(
    session: Session, profile_id: UUID, *, limit: int | None = None, cursor: str | None = None
) -> tuple[list[dict[str, Any]], str | None]:
    """Oldest first, by number (stable). ``cursor`` is the last number seen."""
    n = min(limit or DEFAULT_PAGE, MAX_PAGE)
    stmt = select(profile_version).where(profile_version.c.profile_id == profile_id)
    if cursor:
        stmt = stmt.where(profile_version.c.number > _decode(cursor))
    rows = list(session.execute(stmt.order_by(profile_version.c.number).limit(n + 1)))
    more = len(rows) > n
    rows = rows[:n]
    nxt = base64.urlsafe_b64encode(str(rows[-1].number).encode()).decode() if more else None
    return [_version_dict(r, with_spec=False) for r in rows], nxt
