"""Policies, bindings, exceptions, effective policy and deadlines: functions for the api. Transactions belong to
the caller (the api commits per request).

Reads ``service``, ``service_group`` and ``managed_vm`` through ``ovlm.registry.tables``; never calls OpenStack.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Row, delete, func, insert, select, tuple_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.inventory.service import Page, clamp_limit, decode_cursor, encode_cursor
from ovlm.policies.deadline import Deadline, ExceptionRef, active_exception, compute_deadline
from ovlm.policies.durations import format_duration, parse_duration
from ovlm.policies.models import BindingIn, ExceptionIn, PolicyIn
from ovlm.policies.resolve import BindingRef, resolve
from ovlm.policies.tables import policy, policy_binding, policy_exception
from ovlm.policies.windows import rule_from_dict
from ovlm.registry.errors import DomainError, conflict, not_found
from ovlm.registry.tables import managed_vm, service, service_group

# Audit allowlists: registered here so the API and the UI audit policy changes with the same fields.
_POLICY_FIELDS = [
    "name", "max_age", "renewal_interval", "windows", "approvals", "require_distinct_approvers",
    "snapshot_retain_after_restore", "auto_restore_in_window", "max_window_duration", "retention_period", "version",
]  # fmt: skip
audit.register_entity("policy", _POLICY_FIELDS)
audit.register_entity("policy_binding", ["policy_id", "scope_type", "scope_id"])
audit.register_entity(
    "policy_exception",
    ["service_id", "reason", "starts_at", "expires_at", "requested_by", "approved_by"],
    secret_fields=["owner"],  # may be a person's contact: only the fact of a change is recorded
)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _id(value: UUID | None) -> str | None:
    return str(value) if value else None


def _policy_dict(r: Row[Any]) -> dict[str, Any]:
    retain = r.snapshot_retain_after_restore
    return {
        "id": str(r.id), "name": r.name,
        "max_age": format_duration(r.max_age_seconds),
        "renewal_interval": format_duration(r.renewal_interval_seconds),
        "windows": r.windows, "approvals": r.approvals,
        "require_distinct_approvers": r.require_distinct_approvers,
        "snapshot_retain_after_restore": retain,
        "auto_restore_in_window": r.auto_restore_in_window,
        "max_window_duration": format_duration(r.max_window_duration_seconds),
        "retention_period": format_duration(r.retention_period_seconds) if r.retention_period_seconds else None,
        "version": r.version, "last_edited_by": _id(r.last_edited_by),
        "created_at": _iso(r.created_at), "updated_at": _iso(r.updated_at),
    }  # fmt: skip


def _binding_dict(r: Row[Any]) -> dict[str, Any]:
    return {
        "id": str(r.id), "policy_id": str(r.policy_id), "scope_type": r.scope_type,
        "scope_id": str(r.scope_id), "created_by": _id(r.created_by), "created_at": _iso(r.created_at),
    }  # fmt: skip


def _exception_dict(r: Row[Any], now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    if r.approved_by is None:
        state = "expired" if r.expires_at <= now else "pending"
    elif r.expires_at <= now:
        state = "expired"
    else:
        state = "active" if r.starts_at <= now else "approved"
    return {
        "id": str(r.id), "service_id": str(r.service_id), "reason": r.reason, "owner": r.owner,
        "starts_at": _iso(r.starts_at), "expires_at": _iso(r.expires_at),
        "requested_by": _id(r.requested_by), "approved_by": _id(r.approved_by),
        "approved_at": _iso(r.approved_at), "created_at": _iso(r.created_at), "state": state,
    }  # fmt: skip


def _values(body: PolicyIn) -> dict[str, Any]:
    return {
        "name": body.name,
        "max_age_seconds": parse_duration(body.max_age),
        "renewal_interval_seconds": parse_duration(body.renewal_interval),
        "windows": [w.canonical() for w in body.windows],
        "approvals": body.approvals.model_dump(),
        "require_distinct_approvers": body.require_distinct_approvers,
        "snapshot_retain_after_restore": body.snapshot_retain_after_restore,
        "auto_restore_in_window": body.auto_restore_in_window,
        "max_window_duration_seconds": parse_duration(body.max_window_duration),
        "retention_period_seconds": parse_duration(body.retention_period)
        if body.retention_period
        else None,
    }


def _stale(what: str) -> DomainError:
    return DomainError(412, "etag-mismatch", "Precondition failed", f"The {what} was changed since you read it.",
                       f"GET the {what} again and retry.")  # fmt: skip


def _name_taken(name: str) -> DomainError:
    return conflict("policy-name-taken", "Policy name already in use", f"A policy named '{name}' exists.",
                    "Choose another name.")  # fmt: skip


# --- policies -------------------------------------------------------------------------------------------------------


def create_policy(session: Session, body: PolicyIn, *, actor_id: UUID | None) -> dict[str, Any]:
    pid = uuid4()
    try:
        with session.begin_nested():
            session.execute(insert(policy).values(id=pid, last_edited_by=actor_id, **_values(body)))
    except IntegrityError:
        raise _name_taken(body.name) from None
    return _policy_dict(session.execute(select(policy).where(policy.c.id == pid)).one())


def get_policy(session: Session, policy_id: UUID) -> dict[str, Any] | None:
    row = session.execute(select(policy).where(policy.c.id == policy_id)).first()
    return _policy_dict(row) if row else None


def list_policies(session: Session, *, limit: int | None = None, cursor: str | None = None) -> Page:
    n = clamp_limit(limit)
    stmt = select(policy)
    if cursor:
        ts, rid = decode_cursor(cursor)
        stmt = stmt.where(tuple_(policy.c.created_at, policy.c.id) > tuple_(ts, rid))
    rows = list(session.execute(stmt.order_by(policy.c.created_at, policy.c.id).limit(n + 1)))
    more = len(rows) > n
    rows = rows[:n]
    return Page(
        [_policy_dict(r) for r in rows],
        encode_cursor(rows[-1].created_at, rows[-1].id) if more else None,
    )


def update_policy(
    session: Session,
    policy_id: UUID,
    expected_version: int,
    body: PolicyIn,
    *,
    actor_id: UUID | None,
) -> dict[str, Any]:
    """Replace every editable field (``PUT``). The version bump is what the plan hash binds to."""
    if get_policy(session, policy_id) is None:
        raise not_found("policy-not-found", "Policy")
    try:
        with session.begin_nested():
            row = session.execute(
                update(policy)
                .where(policy.c.id == policy_id, policy.c.version == expected_version)
                .values(
                    **_values(body),
                    version=policy.c.version + 1,
                    last_edited_by=actor_id,
                    updated_at=func.now(),
                )
                .returning(policy)
            ).first()
    except IntegrityError:
        raise _name_taken(body.name) from None
    if row is None:
        raise _stale("policy")
    return _policy_dict(row)


def delete_policy(session: Session, policy_id: UUID, expected_version: int) -> None:
    if get_policy(session, policy_id) is None:
        raise not_found("policy-not-found", "Policy")
    bound = session.execute(
        select(func.count())
        .select_from(policy_binding)
        .where(policy_binding.c.policy_id == policy_id)
    ).scalar_one()
    if bound:
        raise conflict("policy-in-use", "Policy still has bindings", f"{bound} binding(s) point at this policy.",
                       "Delete the bindings first; services then have no policy and are never due.")  # fmt: skip
    gone = session.execute(
        delete(policy)
        .where(policy.c.id == policy_id, policy.c.version == expected_version)
        .returning(policy.c.id)
    ).first()
    if gone is None:
        raise _stale("policy")


# --- bindings -------------------------------------------------------------------------------------------------------


def _require_scope(session: Session, scope_type: str, scope_id: UUID) -> None:
    table = service if scope_type == "service" else service_group
    if session.execute(select(table.c.id).where(table.c.id == scope_id)).first() is None:
        raise DomainError(
            422, "unknown-scope", "Unknown scope", f"No {scope_type.replace('_', ' ')} {scope_id}."
        )


def create_binding(session: Session, body: BindingIn, *, actor_id: UUID | None) -> dict[str, Any]:
    if get_policy(session, body.policy_id) is None:
        raise DomainError(422, "unknown-policy", "Unknown policy", f"No policy {body.policy_id}.")
    _require_scope(session, body.scope_type, body.scope_id)
    bid = uuid4()
    try:
        with session.begin_nested():
            session.execute(
                insert(policy_binding).values(
                    id=bid, policy_id=body.policy_id, scope_type=body.scope_type, scope_id=body.scope_id,
                    created_by=actor_id,
                )
            )  # fmt: skip
    except IntegrityError:
        raise conflict("binding-exists", "Scope already has a policy",
                       f"The {body.scope_type.replace('_', ' ')} is already bound to a policy.",
                       "Delete that binding first, or change the policy itself.") from None  # fmt: skip
    return _binding_dict(
        session.execute(select(policy_binding).where(policy_binding.c.id == bid)).one()
    )


def get_binding(session: Session, binding_id: UUID) -> dict[str, Any] | None:
    row = session.execute(select(policy_binding).where(policy_binding.c.id == binding_id)).first()
    return _binding_dict(row) if row else None


def list_bindings(
    session: Session, *, policy_id: UUID | None = None, scope_type: str | None = None,
    scope_id: UUID | None = None, limit: int | None = None, cursor: str | None = None,
) -> Page:  # fmt: skip
    n = clamp_limit(limit)
    stmt = select(policy_binding)
    for col, val in ((policy_binding.c.policy_id, policy_id), (policy_binding.c.scope_type, scope_type),
                     (policy_binding.c.scope_id, scope_id)):  # fmt: skip
        if val is not None:
            stmt = stmt.where(col == val)
    if cursor:
        ts, rid = decode_cursor(cursor)
        stmt = stmt.where(
            tuple_(policy_binding.c.created_at, policy_binding.c.id) > tuple_(ts, rid)
        )
    rows = list(
        session.execute(
            stmt.order_by(policy_binding.c.created_at, policy_binding.c.id).limit(n + 1)
        )
    )
    more = len(rows) > n
    rows = rows[:n]
    return Page(
        [_binding_dict(r) for r in rows],
        encode_cursor(rows[-1].created_at, rows[-1].id) if more else None,
    )


def delete_binding(session: Session, binding_id: UUID) -> None:
    gone = session.execute(
        delete(policy_binding)
        .where(policy_binding.c.id == binding_id)
        .returning(policy_binding.c.id)
    ).first()
    if gone is None:
        raise not_found("binding-not-found", "Policy binding")


# --- exceptions (FR-POL-3) ------------------------------------------------------------------------------------------


def create_exception(
    session: Session, body: ExceptionIn, *, actor_id: UUID, now: datetime | None = None
) -> dict[str, Any]:
    """A request: it waives nothing until an approver (not the requester) approves it."""
    now = now or datetime.now(UTC)
    if session.execute(select(service.c.id).where(service.c.id == body.service_id)).first() is None:
        raise not_found("service-not-found", "Service")
    if body.expires_at <= now:
        raise DomainError(422, "exception-already-expired", "Exception already expired",
                          "expires_at is in the past.", "Choose an expiry in the future.")  # fmt: skip
    xid = uuid4()
    session.execute(
        insert(policy_exception).values(
            id=xid, service_id=body.service_id, reason=body.reason, owner=body.owner,
            starts_at=body.starts_at, expires_at=body.expires_at, requested_by=actor_id,
        )
    )  # fmt: skip
    return _exception_dict(
        session.execute(select(policy_exception).where(policy_exception.c.id == xid)).one(), now
    )


def get_exception(session: Session, exception_id: UUID) -> dict[str, Any] | None:
    row = session.execute(
        select(policy_exception).where(policy_exception.c.id == exception_id)
    ).first()
    return _exception_dict(row) if row else None


def list_exceptions(
    session: Session,
    *,
    service_id: UUID | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> Page:
    n = clamp_limit(limit)
    stmt = select(policy_exception)
    if service_id is not None:
        stmt = stmt.where(policy_exception.c.service_id == service_id)
    if cursor:
        ts, rid = decode_cursor(cursor)
        stmt = stmt.where(
            tuple_(policy_exception.c.created_at, policy_exception.c.id) > tuple_(ts, rid)
        )
    rows = list(
        session.execute(
            stmt.order_by(policy_exception.c.created_at, policy_exception.c.id).limit(n + 1)
        )
    )
    more = len(rows) > n
    rows = rows[:n]
    return Page(
        [_exception_dict(r) for r in rows],
        encode_cursor(rows[-1].created_at, rows[-1].id) if more else None,
    )


def approve_exception(
    session: Session, exception_id: UUID, *, approver_id: UUID, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    row = session.execute(
        select(policy_exception).where(policy_exception.c.id == exception_id)
    ).first()
    if row is None:
        raise not_found("exception-not-found", "Policy exception")
    if row.requested_by == approver_id:
        raise DomainError(403, "sod-violation", "Separation of duties",
                          "The requester of an exception cannot approve it.", "Ask another approver.")  # fmt: skip
    if row.approved_by is not None:
        raise conflict(
            "exception-already-approved", "Already approved", "This exception is already approved."
        )
    if row.expires_at <= now:
        raise conflict("exception-expired", "Exception expired", "This exception has already expired.",
                       "Request a new one.")  # fmt: skip
    done = session.execute(
        update(policy_exception)
        .where(policy_exception.c.id == exception_id, policy_exception.c.approved_by.is_(None))
        .values(approved_by=approver_id, approved_at=now)
        .returning(policy_exception)
    ).first()
    if done is None:  # lost a race with another approval
        raise conflict(
            "exception-already-approved", "Already approved", "This exception is already approved."
        )
    return _exception_dict(done, now)


def _exception_refs(session: Session, service_id: UUID) -> list[ExceptionRef]:
    rows = session.execute(
        select(policy_exception).where(policy_exception.c.service_id == service_id)
    )
    return [
        ExceptionRef(str(r.id), r.starts_at, r.expires_at, r.approved_by is not None) for r in rows
    ]


# --- effective policy and deadline ----------------------------------------------------------------------------------


def effective_policy(
    session: Session, service_id: UUID, *, now: datetime | None = None
) -> dict[str, Any] | None:
    """Which policy applies to the service and why (FR-POL-2); ``None`` when the service does not exist."""
    now = now or datetime.now(UTC)
    svc = session.execute(
        select(service.c.id, service.c.service_group_id).where(service.c.id == service_id)
    ).first()
    if svc is None:
        return None
    group_id = svc.service_group_id
    scopes = [service_id] + ([group_id] if group_id else [])
    rows = session.execute(select(policy_binding).where(policy_binding.c.scope_id.in_(scopes)))
    by_id = {r.id: r for r in rows}
    result = resolve(
        service_id,
        group_id,
        [BindingRef(r.id, r.policy_id, r.scope_type, r.scope_id) for r in by_id.values()],
    )
    pol = get_policy(session, result.winner.policy_id) if result.winner else None
    waiver = active_exception(_exception_refs(session, service_id), now)
    waiver_row = (
        session.execute(select(policy_exception).where(policy_exception.c.id == UUID(waiver.id))).first()
        if waiver else None
    )  # fmt: skip
    return {
        "service_id": str(service_id),
        "policy": pol,
        "source": result.winner.scope_type if result.winner else None,
        "binding": _binding_dict(by_id[result.winner.id]) if result.winner else None,
        "shadowed_bindings": [_binding_dict(by_id[b.id]) for b in result.shadowed],
        "reason": result.reason,
        "active_exception": _exception_dict(waiver_row, now) if waiver_row else None,
        "due_possible": pol is not None,  # no policy: the service is never due (FR-POL-4)
    }


def _deadline_dict(base: dict[str, Any], d: Deadline | None, now: datetime) -> dict[str, Any]:
    out = {**base, "computed_at": now.isoformat()}
    if d is not None:
        out.update(
            status=d.status, due=d.due, deadline=_iso(d.deadline), next_window_start=_iso(d.next_window_start),
            next_window_end=_iso(d.next_window_end), waived_until=_iso(d.waived_until), exception_id=d.exception_id,
        )  # fmt: skip
    return out


def vm_deadline(
    session: Session, managed_vm_id: UUID, *, now: datetime | None = None
) -> dict[str, Any] | None:
    """FR-POL-5 for one managed VM; ``None`` when it does not exist.

    Only the ``current`` VM of a service is subject to renewal: ``candidate``, ``retained`` and ``retired`` VMs answer
    ``not_applicable`` and are never due.
    """
    now = now or datetime.now(UTC)
    vm = session.execute(select(managed_vm).where(managed_vm.c.id == managed_vm_id)).first()
    if vm is None:
        return None
    eff = effective_policy(session, vm.service_id, now=now)
    if eff is None:  # cannot happen (foreign key); keeps the type honest
        return None
    pol = eff["policy"]
    base: dict[str, Any] = {
        "managed_vm_id": str(vm.id), "service_id": str(vm.service_id), "role": vm.role,
        "launched_at": _iso(vm.launched_at_effective),
        "policy_id": pol["id"] if pol else None, "policy_version": pol["version"] if pol else None,
        "max_age": pol["max_age"] if pol else None,
    }  # fmt: skip
    if vm.role != "current":
        return {**_deadline_dict(base, Deadline("not_applicable", None, None, None, False), now)}
    if pol is None:
        return _deadline_dict(
            base, compute_deadline(launched_at=None, max_age_seconds=None, windows=[], now=now), now
        )
    d = compute_deadline(
        launched_at=vm.launched_at_effective, max_age_seconds=parse_duration(pol["max_age"]),
        windows=[rule_from_dict(w) for w in pol["windows"]], now=now,
        exceptions=_exception_refs(session, vm.service_id),
    )  # fmt: skip
    return _deadline_dict(base, d, now)
