"""Operator pages (E6-1, E6-2): dashboard, inventory, VM details with observed vs desired, services, placeholders.

Every page calls the service layer the REST API calls (``inventory.service``, ``registry.service``) behind the same
``require_role`` dependencies, and every change is audited the way the matching API endpoint audits it. The UI offers
nothing the API lacks: registering a VM is ``POST /api/v1/services/{id}/managed-vms``, creating a service is
``POST /api/v1/services``. Pages work without JavaScript (plain links and forms); HTMX only enhances them.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.deps import get_db, require_role
from ovlm.auth.principal import Principal
from ovlm.inventory import service as inventory
from ovlm.registry import service as registry
from ovlm.registry.errors import DomainError
from ovlm.ui.readiness_view import readiness_context
from ovlm.ui.routes_account import router as account_router
from ovlm.ui.routes_readiness import router as readiness_router
from ovlm.ui.support import UiRoute, error_page, render

router = APIRouter(route_class=UiRoute, include_in_schema=False)
router.include_router(
    account_router
)  # step-up page; one include_router line in api/app.py serves the whole UI
router.include_router(readiness_router)  # POST /inventory/servers/{id}/assess

Db = Annotated[Session, Depends(get_db)]
VIEWER = Depends(require_role("viewer"))
OPERATOR = Depends(require_role("operator"))

PAGE_SIZE = 50
COUNT_CAP = 1000
#: Observation statuses (inventory) plus the server statuses an operator filters by most.
STATUS_CHOICES = ("present", "gone", "unknown", "ACTIVE", "SHUTOFF", "ERROR", "BUILD", "PAUSED")
NOTICES = {
    "registered": "The server is now a managed VM.",
    "service-created": "Service created.",
    "assessment-requested": "Readiness assessment requested. The worker will store the result.",
}


def _uuid(value: str | None) -> UUID | None:
    if not value:
        return None
    try:
        return UUID(value)
    except ValueError:
        return None


def _audit(
    db: Session, who: Principal, action: str, target_type: str, target_id: str, *,
    scope: str | None, after: dict[str, Any],
) -> None:  # fmt: skip
    audit.record(
        db, action=action, target_type=target_type, target_id=target_id, actor_id=who.user_id,
        principal_type=who.principal_type, auth_method=who.auth_method, source_ip=who.source_ip,
        project_scope=scope, after=after,
    )  # fmt: skip


def _is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


# --- dashboard ----------------------------------------------------------------------------------------------------


def _count(db: Session, resource: str, **filters: Any) -> tuple[int, bool]:
    """Rows matching the filters, counted page by page up to ``COUNT_CAP`` (the second value: capped)."""
    total, cursor = 0, None
    while True:
        page = inventory.list_observed(
            db, resource, limit=inventory.MAX_PAGE, cursor=cursor, **filters
        )
        total += len(page.items)
        if not page.next_cursor:
            return total, False
        if total >= COUNT_CAP:
            return total, True
        cursor = page.next_cursor


def _summary(db: Session) -> dict[str, Any]:
    managed, managed_capped = 0, False
    cursor = None
    while True:
        page = registry.list_managed_vms(db, limit=inventory.MAX_PAGE, cursor=cursor)
        managed += len(page.items)
        if not page.next_cursor:
            break
        if managed >= COUNT_CAP:
            managed_capped = True
            break
        cursor = page.next_cursor
    counts = {
        "servers": _count(db, "server"),
        "present": _count(db, "server", status="present"),
        "gone": _count(db, "server", status="gone"),
        "unknown": _count(db, "server", status="unknown"),
        "volumes": _count(db, "volume", status="present"),
        "floating_ips": _count(db, "floating_ip", status="present"),
        "managed": (managed, managed_capped),
    }
    return {"counts": counts}


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Db, who: Principal = VIEWER) -> HTMLResponse:
    return render(request, "dashboard.html", active="dashboard", **_summary(db))


@router.get("/ui/fragments/summary", response_class=HTMLResponse)
def summary_fragment(request: Request, db: Db, who: Principal = VIEWER) -> HTMLResponse:
    """Polled by the dashboard (HTMX enhancement; the page already shows the same numbers without JavaScript)."""
    return render(request, "fragments/summary.html", **_summary(db))


# --- inventory ------------------------------------------------------------------------------------------------------


def _row(db: Session, item: dict[str, Any], registered: set[str]) -> dict[str, Any]:
    detail = inventory.server_detail(db, UUID(item["id"])) or item
    return {
        "item": item,
        "managed": item["openstack_id"] in registered,
        "volumes": [
            {"id": a["data"].get("volume_openstack_id", ""), "device": a["data"].get("device")}
            for a in detail.get("attachments", [])
        ],
        "floating_ips": [
            f["data"].get("floating_ip_address") or f["name"]
            for f in detail.get("floating_ips", [])
        ],
    }


@router.get("/inventory", response_class=HTMLResponse)
def inventory_list(
    request: Request, db: Db, project: str = "", status: str = "", registered: str = "",
    cursor: str = "", who: Principal = VIEWER,
) -> HTMLResponse:  # fmt: skip
    problems: list[str] = []
    project_id = _uuid(project)
    if project and project_id is None:
        problems.append("The project filter must be a project connection id (a UUID).")
    if status and status not in STATUS_CHOICES:
        problems.append("Unknown status filter.")
        status = ""
    known = registry.registered_server_ids(db)
    only = known if registered == "yes" else None
    exclude = known if registered == "no" else None
    rows: list[dict[str, Any]] = []
    next_cursor = None
    if not problems:
        try:
            page = inventory.list_observed(
                db, "server", project=project_id, status=status or None, openstack_ids=only,
                exclude_openstack_ids=exclude, limit=PAGE_SIZE, cursor=cursor or None,
            )  # fmt: skip
        except inventory.InvalidCursorError:
            problems.append("The page link is not valid. Showing the first page.")
            page = inventory.list_observed(db, "server", limit=PAGE_SIZE)
        rows = [_row(db, item, known) for item in page.items]
        next_cursor = page.next_cursor
    return render(
        request, "inventory/list.html", 422 if problems and not rows else 200, active="inventory",
        rows=rows, next_cursor=next_cursor, problems=problems, statuses=STATUS_CHOICES,
        filters={"project": project, "status": status, "registered": registered},
    )  # fmt: skip


def _find_managed_vm(db: Session, openstack_id: str) -> dict[str, Any] | None:
    cursor = None
    while True:
        page = registry.list_managed_vms(db, limit=inventory.MAX_PAGE, cursor=cursor)
        for vm in page.items:
            if vm["openstack_server_id"] == openstack_id:
                return vm
        if not page.next_cursor:
            return None
        cursor = page.next_cursor


def _detail_context(db: Session, server_id: UUID) -> dict[str, Any] | None:
    server = inventory.server_detail(db, server_id)
    if server is None:
        return None
    managed = desired = service = None
    if server["openstack_id"] in registry.registered_server_ids(db):
        vm = _find_managed_vm(db, server["openstack_id"])
        if vm is not None:
            managed = registry.get_managed_vm(db, UUID(vm["id"]))
            desired = managed["desired"] if managed else None
            service = registry.get_service(db, UUID(vm["service_id"]))
    project = UUID(server["project_connection_id"])
    services = registry.list_services(db, project=project, limit=inventory.MAX_PAGE).items
    observation = server["observation"]
    can_register = managed is None and observation["status"] == "present"
    return {
        "server": server, "managed": managed, "desired": desired, "service": service,
        "services": services, "can_register": can_register,
        "readiness": readiness_context(db, UUID(managed["id"])) if managed else None,
    }  # fmt: skip


@router.get("/inventory/servers/{server_id}", response_class=HTMLResponse)
def server_page(
    request: Request, server_id: str, db: Db, notice: str = "", who: Principal = VIEWER
) -> HTMLResponse:
    parsed = _uuid(server_id)
    ctx = _detail_context(db, parsed) if parsed else None
    if ctx is None:
        return error_page(request, 404, "Server not found", "No such server in the inventory.")
    return render(
        request,
        "inventory/detail.html",
        active="inventory",
        notice=NOTICES.get(notice),
        error=None,
        **ctx,
    )


@router.post("/inventory/servers/{server_id}/register", response_class=HTMLResponse)
def register_server(
    request: Request, server_id: str, db: Db, service_id: Annotated[str, Form()] = "",
    who: Principal = OPERATOR,
) -> Response:  # fmt: skip
    parsed, service = _uuid(server_id), _uuid(service_id)
    ctx = _detail_context(db, parsed) if parsed else None
    if parsed is None or ctx is None:
        return error_page(request, 404, "Server not found", "No such server in the inventory.")
    try:
        if service is None:
            raise DomainError(
                422, "invalid-service", "Choose a service", "Select the service this VM belongs to."
            )
        vm = registry.register_managed_vm(db, service, parsed, actor_id=who.user_id)
        svc = registry.get_service(db, service)
        _audit(db, who, "managed_vm.register", "managed_vm", vm["id"],
               scope=f"project:{svc['project_connection_id']}" if svc else None, after=vm)  # fmt: skip
        db.commit()
    except DomainError as exc:
        db.rollback()
        return render(
            request, "inventory/detail.html", exc.status, active="inventory", notice=None,
            error={"title": exc.title, "detail": exc.detail, "next_action": exc.next_action}, **ctx,
        )  # fmt: skip
    return RedirectResponse(f"/inventory/servers/{parsed}?notice=registered", status_code=303)


# --- services -----------------------------------------------------------------------------------------------------


def _services_context(db: Session, project: UUID | None, cursor: str | None) -> dict[str, Any]:
    page = registry.list_services(db, project=project, limit=PAGE_SIZE, cursor=cursor)
    vms = {
        v["service_id"]: v for v in registry.list_managed_vms(db, limit=inventory.MAX_PAGE).items
    }
    return {"services": page.items, "next_cursor": page.next_cursor, "vms": vms}


@router.get("/services", response_class=HTMLResponse)
def services_list(
    request: Request, db: Db, project: str = "", cursor: str = "", notice: str = "",
    who: Principal = VIEWER,
) -> HTMLResponse:  # fmt: skip
    project_id = _uuid(project)
    problems = (
        []
        if not project or project_id
        else ["The project filter must be a project connection id (a UUID)."]
    )
    try:
        ctx = _services_context(db, project_id, cursor or None)
    except inventory.InvalidCursorError:
        problems.append("The page link is not valid. Showing the first page.")
        ctx = _services_context(db, project_id, None)
    return render(
        request, "services/list.html", active="services", problems=problems, project=project,
        notice=NOTICES.get(notice), form={}, form_error=None, **ctx,
    )  # fmt: skip


@router.post("/services", response_class=HTMLResponse)
def services_create(
    request: Request, db: Db, name: Annotated[str, Form()] = "", slug: Annotated[str, Form()] = "",
    project_connection_id: Annotated[str, Form()] = "", owner_contact: Annotated[str, Form()] = "",
    who: Principal = OPERATOR,
) -> Response:  # fmt: skip
    form = {"name": name, "slug": slug, "project_connection_id": project_connection_id,
            "owner_contact": owner_contact}  # fmt: skip
    project_id = _uuid(project_connection_id.strip())
    try:
        if not name.strip() or len(name) > 200 or len(slug) > 64 or len(owner_contact) > 500:
            raise DomainError(422, "invalid-service", "Check the form", "Name is required (200 characters at most); slug 64; contact 500.")  # fmt: skip
        if project_id is None:
            raise DomainError(422, "invalid-project", "Check the form", "The project must be a project connection id (a UUID).")  # fmt: skip
        created = registry.create_service(
            db, name=name.strip(), slug=slug.strip(), project_connection_id=project_id,
            owner_contact=owner_contact.strip() or None, actor_id=who.user_id,
        )  # fmt: skip
        _audit(db, who, "service.create", "service", created["id"],
               scope=f"project:{created['project_connection_id']}", after=created)  # fmt: skip
        db.commit()
    except DomainError as exc:
        db.rollback()
        return render(
            request, "services/list.html", exc.status, active="services", problems=[], project="",
            notice=None, form=form, form_error=f"{exc.title}: {exc.detail}", **_services_context(db, None, None),
        )  # fmt: skip
    return RedirectResponse("/services?notice=service-created", status_code=303)


# --- pages that arrive with later tasks -----------------------------------------------------------------------------


@router.get("/renewals", response_class=HTMLResponse)
def renewals(request: Request, who: Principal = VIEWER) -> HTMLResponse:
    return render(
        request, "placeholder.html", active="renewals", title="Renewals",
        detail="Renewal plans, readiness results and approvals arrive with the renewal workflow (backlog E4, E5, E6-3).",
    )  # fmt: skip


@router.get("/audit", response_class=HTMLResponse)
def audit_view(request: Request, who: Principal = VIEWER) -> HTMLResponse:
    return render(
        request, "placeholder.html", active="audit", title="Audit",
        detail="The audit view arrives with backlog E6-4. Audit records are already written for every change.",
    )  # fmt: skip
