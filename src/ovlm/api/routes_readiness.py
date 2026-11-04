"""Rebuild readiness endpoints, api-design.md section 3.5.

``POST /managed-vms/{id}/assessments`` answers **202** with the worker run that will do the assessment: the api never
runs a check and never calls OpenStack. Reads need ``viewer`` and answer 404 for a VM outside the caller's scope; the
request needs ``operator`` in the VM's project (API tokens: scope ``operate``) and is audited.

By default an assessment runs no repository code on the live VM (SEC-R-28). Asking for it
(``run_repo_code_on_live_vm: true``) needs a human session, a TOTP step-up and the typed confirmation, and a worker
that can run it; this release has none, so the request is refused with a clear problem rather than silently running
the safe assessment instead.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.api.routes_common import ProblemRoute, audit_change
from ovlm.auth.authz import authorize
from ovlm.auth.deps import get_db, require_role
from ovlm.auth.principal import Principal
from ovlm.inventory.service import InvalidCursorError
from ovlm.readiness import service as readiness
from ovlm.registry import service as registry
from ovlm.registry.errors import DomainError

VIEWER = Depends(require_role("viewer"))
OPERATOR = Depends(require_role("operator", token_scope="operate"))  # noqa: S106 - an API token scope name, not a secret
DB = Depends(get_db)

router = APIRouter(prefix="/api/v1", route_class=ProblemRoute)


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_repo_code_on_live_vm: bool = False
    typed_confirmation: str | None = None


def _vm_scope(session: Session, vm: dict[str, Any]) -> str | None:
    svc = registry.get_service(session, UUID(vm["service_id"]))
    return f"project:{svc['project_connection_id']}" if svc else None


def _vm_or_404(
    session: Session, vm_id: UUID, who: Principal, role: str
) -> tuple[dict[str, Any], str | None]:
    vm = registry.get_managed_vm(session, vm_id)
    scope = _vm_scope(session, vm) if vm else None
    # Out of scope reads as "not found" (api-design.md): a viewer of another project learns nothing.
    if vm is None or (role == "viewer" and not authorize(who, "viewer", scope)):
        raise DomainError(
            404, "managed-vm-not-found", "Managed VM not found", "No such managed VM."
        )
    return vm, scope


@router.get("/checks")
def list_checks(_: Principal = VIEWER) -> dict[str, Any]:
    """The catalogue: every check key with its version, category and severity."""
    return {"items": readiness.catalogue(), "next_cursor": None}


@router.post("/managed-vms/{vm_id}/assessments", status_code=202)
def request_assessment(
    vm_id: UUID, response: Response, body: AssessmentRequest | None = None,
    session: Session = DB, who: Principal = OPERATOR,
) -> dict[str, Any]:  # fmt: skip
    body = body or AssessmentRequest()
    vm, scope = _vm_or_404(session, vm_id, who, "operator")
    if not authorize(who, "operator", scope):
        audit.record(
            session, action="readiness.request", target_type="readiness_request", target_id=str(vm_id),
            result="denied", actor_id=who.user_id, principal_type=who.principal_type,
            auth_method=who.auth_method, source_ip=who.source_ip, project_scope=scope,
        )  # fmt: skip
        session.commit()
        # Out of scope reads as "not found" (api-design.md), but the attempt is on record.
        raise DomainError(
            404, "managed-vm-not-found", "Managed VM not found", "No such managed VM."
        )
    if body.run_repo_code_on_live_vm:
        raise DomainError(
            409, "live-code-run-unavailable", "Live code run is not available",
            "Running repository code on the live VM (SEC-R-28) is not available in this release.",
            "Request the default assessment: it runs no repository code on the VM.",
        )  # fmt: skip
    run, created = readiness.request_assessment(session, vm, requested_by=who.user_id)
    audit_change(
        session, who, "readiness.request", "readiness_request", str(vm_id), scope=scope,
        after={"managed_vm_id": str(vm_id), "run_id": run["id"], "already_pending": not created,
               "run_repo_code_on_live_vm": False},
    )  # fmt: skip
    session.commit()
    response.headers["Location"] = f"/api/v1/managed-vms/{vm_id}/assessments"
    return {
        "run": run,
        "already_pending": not created,
        "links": {"assessments": f"/api/v1/managed-vms/{vm_id}/assessments"},
    }


@router.get("/managed-vms/{vm_id}/assessments")
def list_assessments(
    vm_id: UUID, limit: int | None = Query(default=None, ge=1, le=200), cursor: str | None = None,
    session: Session = DB, who: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    _vm_or_404(session, vm_id, who, "viewer")
    try:
        page = readiness.list_assessments(session, vm_id, limit=limit, cursor=cursor)
    except InvalidCursorError:
        raise DomainError(400, "invalid-cursor", "Invalid cursor", "The cursor is malformed.",
                          "Restart from the first page.") from None  # fmt: skip
    return {
        "items": page.items,
        "next_cursor": page.next_cursor,
        "runs": readiness.runs_of(session, vm_id),
    }


@router.get("/assessments/{assessment_id}")
def get_assessment(
    assessment_id: UUID, session: Session = DB, who: Principal = VIEWER
) -> dict[str, Any]:
    found = readiness.get_assessment(session, assessment_id)
    if found is not None:
        # The VM may be unregistered by now; its assessments stay readable to anyone who may see the project.
        vm = registry.get_managed_vm(session, UUID(found["managed_vm_id"]))
        if vm is not None and not authorize(who, "viewer", _vm_scope(session, vm)):
            found = None
    if found is None:
        raise DomainError(
            404, "assessment-not-found", "Assessment not found", "No such assessment."
        )
    return found
