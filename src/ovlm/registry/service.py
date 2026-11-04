"""Services and managed VMs: public functions for the api (architecture.md section 3, data-model.md section 4).

Transactions belong to the caller (the api commits per request); every function here only executes statements.
Consistency rules are enforced twice: checked here for clean error messages, and by database constraints for races
(``UNIQUE(openstack_server_id)``, one ``current`` per service, ``UNIQUE(slug)``).

Never imports ``ovlm.openstack``. Registration reads the observed server through ``ovlm.inventory.service``.

INTEGRATION POINTS (clearly stubbed, no behaviour guessed):

* audit: written by the api layer (``routes_inventory``) with ``ovlm.audit.record`` in the request's transaction.
* service lock (E5-1): ``_lock_holder`` always returns ``None`` until ``resource_lock`` exists.
* host-key scan run (ADR-0006): registration does not start one; the api answers ``201``, not ``202``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Row, delete, func, insert, select, tuple_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ovlm.inventory import service as inventory
from ovlm.inventory.ids import uuid7
from ovlm.inventory.service import Page, clamp_limit, decode_cursor, encode_cursor
from ovlm.registry.errors import DomainError, conflict, not_found
from ovlm.registry.tables import managed_vm, service, service_group

SLUG = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")
_UNSET: Any = object()


def etag(version: int) -> str:
    return f'"{version}"'


def parse_if_match(header: str | None) -> int:
    """``If-Match: "3"`` -> 3. Missing is ``428``, malformed or stale is ``412`` (api-design.md section 1)."""
    if header is None:
        raise DomainError(428, "precondition-required", "If-Match required", "Send If-Match with the current ETag.",
                          "GET the resource and repeat the request with its ETag.")  # fmt: skip
    value = header.strip().removeprefix("W/").strip('"')
    if not value.isdigit():
        raise DomainError(
            412, "etag-mismatch", "Precondition failed", "The If-Match value is not a valid ETag."
        )
    return int(value)


def _lock_holder(session: Session, service_id: UUID) -> UUID | None:
    """STUB (E5-1): the run id holding ``resource_lock('service', service_id)``, if any."""
    del session, service_id
    return None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _service_dict(r: Row[Any]) -> dict[str, Any]:
    return {
        "id": str(r.id), "name": r.name, "slug": r.slug,
        "service_group_id": str(r.service_group_id) if r.service_group_id else None,
        "project_connection_id": str(r.project_connection_id), "owner_contact": r.owner_contact,
        "current_profile_id": str(r.current_profile_id) if r.current_profile_id else None,
        "version": r.version, "created_by": str(r.created_by) if r.created_by else None,
        "created_at": _iso(r.created_at), "updated_at": _iso(r.updated_at),
    }  # fmt: skip


def _vm_dict(r: Row[Any]) -> dict[str, Any]:
    return {
        "id": str(r.id), "service_id": str(r.service_id), "observed_server_id": str(r.observed_server_id),
        "openstack_server_id": r.openstack_server_id, "role": r.role,
        "registered_by": str(r.registered_by) if r.registered_by else None,
        "registered_at": _iso(r.registered_at), "ssh_host_key_fingerprint": r.ssh_host_key_fingerprint,
        "host_key_confirmed_by": str(r.host_key_confirmed_by) if r.host_key_confirmed_by else None,
        "host_key_confirmed_at": _iso(r.host_key_confirmed_at),
        "launched_at_effective": _iso(r.launched_at_effective),
    }  # fmt: skip


# --- services -----------------------------------------------------------------------------------------------------


def _require_group(session: Session, group_id: UUID | None) -> None:
    if (
        group_id is not None
        and session.execute(
            select(service_group.c.id).where(service_group.c.id == group_id)
        ).first()
        is None
    ):
        raise DomainError(
            422, "unknown-service-group", "Unknown service group", f"No service group {group_id}."
        )


def create_service(
    session: Session,
    *,
    name: str,
    slug: str,
    project_connection_id: UUID,
    service_group_id: UUID | None = None,
    owner_contact: str | None = None,
    actor_id: UUID | None = None,
) -> dict[str, Any]:
    if not SLUG.match(slug):
        raise DomainError(422, "invalid-slug", "Invalid slug",
                          "A slug is 1 to 64 characters of a-z, 0-9 and '-', starting and ending alphanumeric.")  # fmt: skip
    _require_group(session, service_group_id)
    sid = uuid7()
    try:
        with session.begin_nested():
            session.execute(
                insert(service).values(
                    id=sid, name=name, slug=slug, service_group_id=service_group_id,
                    project_connection_id=project_connection_id, owner_contact=owner_contact, created_by=actor_id,
                )
            )  # fmt: skip
    except IntegrityError as exc:
        raise conflict("slug-taken", "Slug already in use", f"A service with slug '{slug}' exists.",
                       "Choose another slug.") from exc  # fmt: skip
    row = session.execute(select(service).where(service.c.id == sid)).one()
    return _service_dict(row)


def get_service(session: Session, service_id: UUID) -> dict[str, Any] | None:
    row = session.execute(select(service).where(service.c.id == service_id)).first()
    return _service_dict(row) if row else None


def list_services(
    session: Session,
    *,
    project: UUID | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> Page:
    n = clamp_limit(limit)
    stmt = select(service)
    if project is not None:
        stmt = stmt.where(service.c.project_connection_id == project)
    if cursor:
        ts, rid = decode_cursor(cursor)
        stmt = stmt.where(tuple_(service.c.created_at, service.c.id) > tuple_(ts, rid))
    rows = list(session.execute(stmt.order_by(service.c.created_at, service.c.id).limit(n + 1)))
    more = len(rows) > n
    rows = rows[:n]
    return Page(
        [_service_dict(r) for r in rows],
        encode_cursor(rows[-1].created_at, rows[-1].id) if more else None,
    )


def update_service(
    session: Session,
    service_id: UUID,
    expected_version: int,
    *,
    name: str | None = None,
    owner_contact: Any = _UNSET,
    service_group_id: Any = _UNSET,
) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    if name is not None:
        changes["name"] = name
    if owner_contact is not _UNSET:
        changes["owner_contact"] = owner_contact
    if service_group_id is not _UNSET:
        _require_group(session, service_group_id)
        changes["service_group_id"] = service_group_id
    if get_service(session, service_id) is None:
        raise not_found("service-not-found", "Service")
    result = session.execute(
        update(service)
        .where(service.c.id == service_id, service.c.version == expected_version)
        .values(**changes, version=service.c.version + 1, updated_at=func.now())
        .returning(service)
    ).first()
    if result is None:
        raise DomainError(412, "etag-mismatch", "Precondition failed",
                          "The service was changed since you read it.", "GET the service again and retry.")  # fmt: skip
    return _service_dict(result)


def delete_service(session: Session, service_id: UUID, expected_version: int) -> None:
    if get_service(session, service_id) is None:
        raise not_found("service-not-found", "Service")
    n = session.execute(
        select(func.count()).select_from(managed_vm).where(managed_vm.c.service_id == service_id)
    ).scalar_one()
    if n:  # data-model.md: refused while a VM is current; also refused for history rows (safest reading)
        raise conflict("service-has-managed-vms", "Service still has managed VMs",
                       f"{n} managed VM(s) are registered under this service.",
                       "Unregister the managed VMs first.")  # fmt: skip
    deleted = session.execute(
        delete(service)
        .where(service.c.id == service_id, service.c.version == expected_version)
        .returning(service.c.id)
    ).first()
    if deleted is None:
        raise DomainError(412, "etag-mismatch", "Precondition failed", "The service was changed since you read it.",
                          "GET the service again and retry.")  # fmt: skip


# --- managed VMs ---------------------------------------------------------------------------------------------------


def register_managed_vm(
    session: Session, service_id: UUID, observed_server_id: UUID, *, actor_id: UUID | None = None
) -> dict[str, Any]:
    """Register an observed server as the ``current`` VM of a service."""
    svc = get_service(session, service_id)
    if svc is None:
        raise not_found("service-not-found", "Service")
    ref = inventory.get_server_ref(session, observed_server_id)
    if ref is None:
        raise not_found("observed-server-not-found", "Observed server")
    if str(ref.project_connection_id) != svc["project_connection_id"]:
        raise conflict("project-mismatch", "Server belongs to another project",
                       "The observed server and the service are in different project connections.",
                       "Register the server under a service of its own project.")  # fmt: skip
    if ref.observation_status != "present" or ref.is_minimal_construct:
        raise conflict("observed-server-not-present", "Observed server is not present",
                       f"The last sync saw this server as '{ref.observation_status}'.",
                       "Run an inventory sync and register a server that is present.")  # fmt: skip
    vm_id = uuid7()
    try:
        with session.begin_nested():
            session.execute(
                insert(managed_vm).values(
                    id=vm_id, service_id=service_id, observed_server_id=ref.id,
                    openstack_server_id=ref.openstack_id, role="current", registered_by=actor_id,
                    registered_at=datetime.now(UTC), launched_at_effective=ref.launched_at or ref.created,
                )
            )  # fmt: skip
    except IntegrityError as exc:
        constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", "") or ""
        if "openstack_server_id" in constraint:
            raise conflict("already-registered", "Server already registered",
                           "This server is already a managed VM.", "Unregister it first.") from exc  # fmt: skip
        if "one_current" in constraint:
            raise conflict("service-has-current-vm", "Service already has a current VM",
                           "A service has exactly one current VM.",
                           "Unregister the current VM first, or renew the service.") from exc  # fmt: skip
        raise
    row = session.execute(select(managed_vm).where(managed_vm.c.id == vm_id)).one()
    return _vm_dict(row)


def list_managed_vms(
    session: Session,
    *,
    service_id: UUID | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> Page:
    n = clamp_limit(limit)
    stmt = select(managed_vm)
    if service_id is not None:
        stmt = stmt.where(managed_vm.c.service_id == service_id)
    if cursor:
        ts, rid = decode_cursor(cursor)
        stmt = stmt.where(tuple_(managed_vm.c.created_at, managed_vm.c.id) > tuple_(ts, rid))
    rows = list(
        session.execute(stmt.order_by(managed_vm.c.created_at, managed_vm.c.id).limit(n + 1))
    )
    more = len(rows) > n
    rows = rows[:n]
    return Page(
        [_vm_dict(r) for r in rows],
        encode_cursor(rows[-1].created_at, rows[-1].id) if more else None,
    )


def get_managed_vm(session: Session, vm_id: UUID) -> dict[str, Any] | None:
    """The managed VM with separate ``desired`` and ``observed`` blocks (FR-REG-4). ``desired`` carries the
    service's profile id only; profile versions arrive with the profiles module. Drift is V1."""
    row = session.execute(select(managed_vm).where(managed_vm.c.id == vm_id)).first()
    if row is None:
        return None
    out = _vm_dict(row)
    svc = get_service(session, row.service_id)
    out["desired"] = {
        "profile_id": svc["current_profile_id"] if svc else None,
        "profile_version": None,
    }
    out["observed"] = inventory.get_servers_by_openstack_ids(
        session, [row.openstack_server_id]
    ).get(row.openstack_server_id)
    return out


def unregister_managed_vm(session: Session, vm_id: UUID) -> None:
    row = session.execute(select(managed_vm).where(managed_vm.c.id == vm_id)).first()
    if row is None:
        raise not_found("managed-vm-not-found", "Managed VM")
    holder = _lock_holder(session, row.service_id)
    if holder is not None:
        raise conflict("resource-locked", "Service is locked by a run", f"Run {holder} holds the service lock.",
                       "Wait for the run to finish or abort it.")  # fmt: skip
    session.execute(delete(managed_vm).where(managed_vm.c.id == vm_id))


def registered_server_ids(session: Session) -> set[str]:
    """OpenStack ids of every registered server (for the inventory ``registered`` filter)."""
    return set(session.execute(select(managed_vm.c.openstack_server_id)).scalars())
