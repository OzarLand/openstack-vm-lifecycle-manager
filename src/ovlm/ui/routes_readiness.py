"""``POST /inventory/servers/{id}/assess``: the human face of ``POST /api/v1/managed-vms/{id}/assessments``.

Same service call, same scope rule and the same audit row as the REST endpoint. Nothing runs in the web process:
the page only asks the worker for an assessment (default mode, no repository code on the VM, SEC-R-28) and goes back
to the details page, which shows the run until the worker has stored the result.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.authz import authorize
from ovlm.auth.deps import get_db, require_role
from ovlm.auth.principal import Principal
from ovlm.inventory import service as inventory
from ovlm.readiness import service as readiness
from ovlm.registry import service as registry
from ovlm.ui.support import UiRoute, error_page

router = APIRouter(route_class=UiRoute, include_in_schema=False)
Db = Annotated[Session, Depends(get_db)]
OPERATOR = Depends(require_role("operator"))


def _managed_vm_of(db: Session, observed_id: UUID) -> dict[str, object] | None:
    cursor = None
    while True:
        page = registry.list_managed_vms(db, limit=inventory.MAX_PAGE, cursor=cursor)
        for vm in page.items:
            if vm["observed_server_id"] == str(observed_id):
                return vm
        if not page.next_cursor:
            return None
        cursor = page.next_cursor


@router.post("/inventory/servers/{server_id}/assess")
def request_assessment(
    request: Request, server_id: str, db: Db, who: Principal = OPERATOR
) -> Response:
    observed: UUID | None
    try:
        observed = UUID(server_id)
    except ValueError:
        observed = None
    vm = _managed_vm_of(db, observed) if observed else None
    svc = registry.get_service(db, UUID(str(vm["service_id"]))) if vm else None
    scope = f"project:{svc['project_connection_id']}" if svc else None
    if vm is None or not authorize(who, "operator", scope):
        return error_page(
            request,
            404,
            "Not a managed VM",
            "Only a managed VM can be assessed for rebuild readiness.",
        )
    run, created = readiness.request_assessment(db, vm, requested_by=who.user_id)
    audit.record(
        db, action="readiness.request", target_type="readiness_request", target_id=str(vm["id"]),
        actor_id=who.user_id, principal_type=who.principal_type, auth_method=who.auth_method,
        source_ip=who.source_ip, project_scope=scope,
        after={"managed_vm_id": str(vm["id"]), "run_id": run["id"], "already_pending": not created,
               "run_repo_code_on_live_vm": False},
    )  # fmt: skip
    db.commit()
    return RedirectResponse(
        f"/inventory/servers/{observed}?notice=assessment-requested#readiness", status_code=303
    )
