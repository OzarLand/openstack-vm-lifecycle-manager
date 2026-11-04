"""Policies, bindings, exceptions, effective policy and deadlines, api-design.md s.3.4.

Reads need ``viewer``. Policy and binding changes need ``admin`` (security-model.md s.3.2; an API token never reaches
admin). An exception is requested by an ``operator`` and approved by an ``approver`` in a human session with a
single-use step-up bound to that exception (the approver is never the requester); it waives the policy only between
``starts_at`` and ``expires_at``. ``PUT`` and ``DELETE`` on a policy need ``If-Match`` (428 missing, 412 stale).

# AUTH-HOOK (E3-2): results are not filtered by project scope yet (same gap as routes_inventory).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.api.routes_common import IfMatch, ProblemRoute, audit_change, etag_of, page_body
from ovlm.auth.deps import get_db, require_role
from ovlm.auth.principal import Principal
from ovlm.auth.stepup import consume_stepup
from ovlm.policies import service as policies
from ovlm.policies.models import ApproveIn, BindingIn, ExceptionIn, PolicyIn
from ovlm.registry import service as registry
from ovlm.registry.errors import DomainError, not_found

VIEWER = Depends(require_role("viewer"))
OPERATOR = Depends(require_role("operator", token_scope="operate"))  # noqa: S106 - an API token scope name, not a secret
APPROVER = Depends(require_role("approver", human_only=True))
ADMIN = Depends(require_role("admin"))

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

router = APIRouter(prefix="/api/v1", route_class=ProblemRoute)
DB = Depends(get_db)
Limit = Query(default=None, ge=1, le=200)


def _found[T](value: T | None, code: str, what: str) -> T:
    if value is None:
        raise not_found(code, what)
    return value


def _service_scope(session: Session, service_id: UUID) -> str | None:
    svc = registry.get_service(session, service_id)
    return f"project:{svc['project_connection_id']}" if svc else None


# --- policies ---------------------------------------------------------------------------------------------------------


@router.get("/policies")
def list_policies(
    limit: int | None = Limit,
    cursor: str | None = None,
    session: Session = DB,
    _: Principal = VIEWER,
) -> dict[str, Any]:
    return page_body(policies.list_policies(session, limit=limit, cursor=cursor))


@router.post("/policies", status_code=201)
def create_policy(
    body: PolicyIn, response: Response, session: Session = DB, who: Principal = ADMIN
) -> dict[str, Any]:
    created = policies.create_policy(session, body, actor_id=who.user_id)
    audit_change(
        session, who, "policy.create", "policy", created["id"], scope="global", after=created
    )
    session.commit()
    response.headers["Location"] = f"/api/v1/policies/{created['id']}"
    response.headers["ETag"] = etag_of(created["version"])
    return created


@router.get("/policies/{policy_id}")
def get_policy(
    policy_id: UUID, response: Response, session: Session = DB, _: Principal = VIEWER
) -> dict[str, Any]:
    found = _found(policies.get_policy(session, policy_id), "policy-not-found", "Policy")
    response.headers["ETag"] = etag_of(found["version"])
    return found


@router.put("/policies/{policy_id}")
def put_policy(
    policy_id: UUID, body: PolicyIn, response: Response, if_match: IfMatch = None,
    session: Session = DB, who: Principal = ADMIN,
) -> dict[str, Any]:  # fmt: skip
    expected = registry.parse_if_match(if_match)
    before = _found(policies.get_policy(session, policy_id), "policy-not-found", "Policy")
    updated = policies.update_policy(session, policy_id, expected, body, actor_id=who.user_id)
    audit_change(
        session,
        who,
        "policy.update",
        "policy",
        str(policy_id),
        scope="global",
        before=before,
        after=updated,
    )
    session.commit()
    response.headers["ETag"] = etag_of(updated["version"])
    return updated


@router.delete("/policies/{policy_id}", status_code=204)
def delete_policy(
    policy_id: UUID, if_match: IfMatch = None, session: Session = DB, who: Principal = ADMIN
) -> Response:
    expected = registry.parse_if_match(if_match)
    before = _found(policies.get_policy(session, policy_id), "policy-not-found", "Policy")
    policies.delete_policy(session, policy_id, expected)
    audit_change(
        session, who, "policy.delete", "policy", str(policy_id), scope="global", before=before
    )
    session.commit()
    return Response(status_code=204)


# --- bindings ---------------------------------------------------------------------------------------------------------


@router.get("/policy-bindings")
def list_bindings(
    policy_id: UUID | None = None, scope_type: str | None = Query(default=None, pattern="^(service_group|service)$"),
    scope_id: UUID | None = None, limit: int | None = Limit, cursor: str | None = None,
    session: Session = DB, _: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    return page_body(
        policies.list_bindings(
            session,
            policy_id=policy_id,
            scope_type=scope_type,
            scope_id=scope_id,
            limit=limit,
            cursor=cursor,
        )
    )


@router.post("/policy-bindings", status_code=201)
def create_binding(
    body: BindingIn, response: Response, session: Session = DB, who: Principal = ADMIN
) -> dict[str, Any]:
    created = policies.create_binding(session, body, actor_id=who.user_id)
    audit_change(
        session,
        who,
        "policy_binding.create",
        "policy_binding",
        created["id"],
        scope="global",
        after=created,
    )
    session.commit()
    response.headers["Location"] = f"/api/v1/policy-bindings/{created['id']}"
    return created


@router.delete("/policy-bindings/{binding_id}", status_code=204)
def delete_binding(binding_id: UUID, session: Session = DB, who: Principal = ADMIN) -> Response:
    before = _found(
        policies.get_binding(session, binding_id), "binding-not-found", "Policy binding"
    )
    policies.delete_binding(session, binding_id)
    audit_change(
        session,
        who,
        "policy_binding.delete",
        "policy_binding",
        str(binding_id),
        scope="global",
        before=before,
    )
    session.commit()
    return Response(status_code=204)


# --- exceptions -------------------------------------------------------------------------------------------------------


@router.get("/policy-exceptions")
def list_exceptions(
    service_id: UUID | None = None, limit: int | None = Limit, cursor: str | None = None,
    session: Session = DB, _: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    return page_body(
        policies.list_exceptions(session, service_id=service_id, limit=limit, cursor=cursor)
    )


@router.post("/policy-exceptions", status_code=201)
def request_exception(
    body: ExceptionIn, response: Response, session: Session = DB, who: Principal = OPERATOR
) -> dict[str, Any]:
    created = policies.create_exception(session, body, actor_id=who.user_id)
    audit_change(session, who, "policy_exception.request", "policy_exception", created["id"],
                 scope=_service_scope(session, body.service_id), after=created)  # fmt: skip
    session.commit()
    response.headers["Location"] = f"/api/v1/policy-exceptions/{created['id']}"
    return created


@router.get("/policy-exceptions/{exception_id}")
def get_exception(
    exception_id: UUID, session: Session = DB, _: Principal = VIEWER
) -> dict[str, Any]:
    return _found(
        policies.get_exception(session, exception_id), "exception-not-found", "Policy exception"
    )


@router.post("/policy-exceptions/{exception_id}/approve")
def approve_exception(
    exception_id: UUID, body: ApproveIn, session: Session = DB, who: Principal = APPROVER
) -> dict[str, Any]:
    before = _found(
        policies.get_exception(session, exception_id), "exception-not-found", "Policy exception"
    )
    # Checked before the step-up is spent, so a refused approval does not burn the approver's re-authentication.
    if before["requested_by"] == str(who.user_id):
        raise DomainError(403, "sod-violation", "Separation of duties",
                          "The requester of an exception cannot approve it.", "Ask another approver.")  # fmt: skip
    consume_stepup(
        session, who, body.stepup_id, action="policy_exception.approve", target_id=str(exception_id)
    )
    approved = policies.approve_exception(session, exception_id, approver_id=who.user_id)
    audit_change(session, who, "policy_exception.approve", "policy_exception", str(exception_id),
                 scope=_service_scope(session, UUID(approved["service_id"])), before=before, after=approved)  # fmt: skip
    session.commit()
    return approved


# --- effective policy and deadline --------------------------------------------------------------------------------------


@router.get("/services/{service_id}/effective-policy")
def get_effective_policy(
    service_id: UUID, session: Session = DB, _: Principal = VIEWER
) -> dict[str, Any]:
    return _found(policies.effective_policy(session, service_id), "service-not-found", "Service")


@router.get("/managed-vms/{vm_id}/deadline")
def get_deadline(vm_id: UUID, session: Session = DB, _: Principal = VIEWER) -> dict[str, Any]:
    return _found(policies.vm_deadline(session, vm_id), "managed-vm-not-found", "Managed VM")
