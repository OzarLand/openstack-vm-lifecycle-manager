"""REST endpoints for inventory (observed state) and registration (services, managed VMs), api-design.md s.3.2, 3.3.

Reads the database only: the api never calls OpenStack (architecture.md section 2). Syncs are run by the worker.

Authentication and RBAC come from the RBAC matrix (``ovlm.auth.authz``): ``inventory.view`` for reads,
``registry.manage`` (operator only) for changes; API tokens need the ``operate`` scope for changes. Changes are
audited with ``ovlm.audit.record`` in the request's transaction, with allowlisted fields.

Project scoping (security-model.md 3.3): every query is restricted to the projects the caller may view
(``visible_projects``); a resource outside them answers 404 exactly like a missing one. A change is checked in the
resource's own project (``ensure_scope``): invisible -> 404, visible but not allowed -> 403.

Work the api starts, it only **queues** (a ``workflow_run`` in ``requested``; the worker does it, SEC-R-1):

* ``POST /projects/{id}/syncs``: an ``inventory_sync`` run (202), or 409 while one of that project is queued or
  running. ``inventory.sync``: operator or admin; API tokens need the ``inventory:sync`` (or ``operate``) scope.
* Registration (``POST /services/{id}/managed-vms``) queues a ``host_key_scan`` of the new VM; the operator then
  confirms the scanned fingerprint (``POST /managed-vms/{id}/host-key/confirm``, human session only, ADR-0006).
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine, Iterator
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.authz import Action, project_scope_of, project_visible, visible_projects
from ovlm.auth.deps import ensure_scope, get_db, require_action
from ovlm.auth.errors import ProblemError, problem_response
from ovlm.auth.principal import Principal
from ovlm.config import Settings
from ovlm.db.engine import make_engine, make_session_factory
from ovlm.inventory import requests as sync_requests
from ovlm.inventory import service as inventory
from ovlm.registry import host_keys
from ovlm.registry import service as registry
from ovlm.registry.errors import DomainError

# One dependency object per action (also keeps ruff B008 quiet). Tokens need the ``operate`` scope for changes.
VIEWER = Depends(require_action(Action.INVENTORY_VIEW))
OPERATOR = Depends(require_action(Action.REGISTRY_MANAGE))
SYNCER = Depends(require_action(Action.INVENTORY_SYNC))
HOST_KEY_CONFIRMER = Depends(require_action(Action.HOST_KEY_CONFIRM))


audit.register_entity(
    "service",
    ["name", "slug", "project_connection_id", "service_group_id", "version"],
    secret_fields=["owner_contact"],  # contact details: only the fact of a change is recorded
)
audit.register_entity(
    "managed_vm", ["service_id", "observed_server_id", "openstack_server_id", "role"]
)
# A sync request is audited by what was asked (the run), never by inventory contents.
audit.register_entity("inventory_sync_request", ["project_connection_id", "run_id"])


def _audit(
    session: Session, who: Principal, action: str, target_type: str,
    target_id: str, *, scope: str | None, before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> None:  # fmt: skip
    """Append the audit row in the request's transaction (the caller commits both together)."""
    audit.record(
        session, action=action, target_type=target_type, target_id=target_id,
        actor_id=who.user_id, principal_type=who.principal_type, auth_method=who.auth_method,
        source_ip=who.source_ip, project_scope=scope, before=before, after=after,
    )  # fmt: skip


# --- problem+json ---------------------------------------------------------------------------------------------------


class ProblemRoute(APIRoute):
    """Turns ``DomainError`` and the auth module's ``ProblemError`` into RFC 9457 ``application/problem+json`` (api-design.md section 1)."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except ProblemError as exc:  # raised by the auth dependencies (401, 403)
                return problem_response(exc, request)
            except DomainError as exc:
                body = {
                    "type": f"https://ovlm.dev/problems/{exc.code}",  # placeholder domain (api-design.md)
                    "title": exc.title, "status": exc.status, "detail": exc.detail,
                    "instance": request.url.path, "code": exc.code,
                }  # fmt: skip
                if exc.next_action:
                    body["next_action"] = exc.next_action
                return JSONResponse(
                    body, status_code=exc.status, media_type="application/problem+json"
                )

        return handler


router = APIRouter(prefix="/api/v1", route_class=ProblemRoute)


# --- dependencies -----------------------------------------------------------------------------------------------------


def get_session(request: Request) -> Iterator[Session]:
    """One session per request. Handlers that write commit explicitly (``session.commit()``), so a failure after
    the response started can never be hidden. The factory comes from ``app.state.session_factory`` (tests set it);
    otherwise it is built once from the settings with this process's own DB role."""
    state = request.app.state
    factory = getattr(state, "session_factory", None)
    if factory is None:
        settings: Settings = state.settings
        state.session_factory = factory = make_session_factory(make_engine(settings))
    with factory() as session:
        yield session


DB = Annotated[Session, Depends(get_session)]
AuthDb = Annotated[Session, Depends(get_db)]  # denials are audited in their own transaction
Limit = Annotated[int | None, Query(ge=1, le=inventory.MAX_PAGE)]
CursorQ = Annotated[str | None, Query()]


def _page(page: inventory.Page) -> dict[str, Any]:
    return {"items": page.items, "next_cursor": page.next_cursor}


def _cursor_guard(fn: Callable[[], inventory.Page]) -> dict[str, Any]:
    try:
        return _page(fn())
    except inventory.InvalidCursorError as exc:
        raise DomainError(400, "invalid-cursor", "Invalid cursor", "The cursor is malformed.",
                          "Restart from the first page.") from exc  # fmt: skip


def _found[T](value: T | None, code: str, what: str) -> T:
    if value is None:
        raise DomainError(404, code, f"{what} not found", f"No such {what.lower()}.")
    return value


def _not_found(code: str, what: str) -> ProblemError:
    return ProblemError(404, code, f"{what} not found", f"No such {what.lower()}.")


def _check(
    request: Request,
    db: Session,
    who: Principal,
    action: Action,
    project: Any,
    code: str,
    what: str,
) -> None:
    """``action`` on a resource of ``project`` (``None``: missing): 404 if invisible or missing, 403 if visible
    but not allowed."""
    scope = project_scope_of(project) if project is not None else None
    ensure_scope(request, db, who, action, scope, not_found=_not_found(code, what))


# --- inventory ---------------------------------------------------------------------------------------------------------


@router.post("/projects/{project_id}/syncs", status_code=202)
def request_sync(
    project_id: UUID, request: Request, response: Response, session: DB, auth_db: AuthDb,
    who: Principal = SYNCER,
) -> dict[str, Any]:  # fmt: skip
    """Queue an inventory sync of one project connection (the worker runs it with the project's read credential).
    409 while a sync of this project is queued or running (its run id is in the problem)."""
    row = session.execute(
        text("SELECT enabled FROM project_connection WHERE id = :p"), {"p": project_id}
    ).first()
    _check(request, auth_db, who, Action.INVENTORY_SYNC, project_id if row else None,
           "project-not-found", "Project")  # fmt: skip
    assert row is not None  # noqa: S101 - _check answered 404 otherwise
    if not row.enabled:
        raise DomainError(409, "project-disabled", "Project connection disabled",
                          "A disabled project connection is not synced.",
                          "Ask an admin to enable the project connection.")  # fmt: skip
    run, created = sync_requests.request_sync(
        session.connection(), project_id, requested_by=who.user_id
    )
    if not created:
        session.rollback()
        raise DomainError(409, "sync-already-pending", "A sync is already queued or running",
                          f"Sync run {run['id']} of this project is {run['state']}.",
                          f"Follow it at GET /api/v1/projects/{project_id}/syncs.")  # fmt: skip
    _audit(session, who, "inventory.sync.request", "inventory_sync_request", run["id"],
           scope=project_scope_of(project_id),
           after={"project_connection_id": str(project_id), "run_id": run["id"]})  # fmt: skip
    session.commit()
    response.headers["Location"] = f"/api/v1/projects/{project_id}/syncs"
    return {"run": run, "links": {"syncs": f"/api/v1/projects/{project_id}/syncs"}}


@router.get("/projects/{project_id}/syncs")
def list_syncs(
    project_id: UUID, session: DB, limit: Limit = None, cursor: CursorQ = None,
    who: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    """``items``: the sync records (status, kind, counts, error), newest first. ``runs``: the newest sync runs of
    the project (queued, running, or why one ended), so a queued request is visible before its record exists."""
    if not project_visible(visible_projects(who), project_id):
        raise _not_found("project-not-found", "Project")
    page = _cursor_guard(
        lambda: inventory.list_syncs(session, project_id, limit=limit, cursor=cursor)
    )
    return {**page, "runs": sync_requests.recent_runs(session.connection(), project_id)}


@router.get("/syncs/{sync_id}")
def get_sync(sync_id: UUID, session: DB, who: Principal = VIEWER) -> dict[str, Any]:
    return _found(
        inventory.get_sync(session, sync_id, projects=visible_projects(who)),
        "sync-not-found",
        "Sync",
    )


@router.get("/servers")
def list_servers(
    session: DB,
    project: UUID | None = None,
    status: str | None = None,
    tag: str | None = None,
    registered: bool | None = None,
    limit: Limit = None,
    cursor: CursorQ = None,
    who: Principal = VIEWER,
) -> dict[str, Any]:
    """``status`` is the observation status (present, gone, unknown) or the server's own status (ACTIVE...)."""
    only = exclude = None
    if registered is True:
        only = registry.registered_server_ids(session)
    elif registered is False:
        exclude = registry.registered_server_ids(session)
    return _cursor_guard(
        lambda: inventory.list_observed(
            session, "server", project=project, status=status, tag=tag, openstack_ids=only,
            exclude_openstack_ids=exclude, limit=limit, cursor=cursor, projects=visible_projects(who),
        )
    )  # fmt: skip


@router.get("/servers/{server_id}")
def get_server(server_id: UUID, session: DB, who: Principal = VIEWER) -> dict[str, Any]:
    detail = inventory.server_detail(session, server_id, projects=visible_projects(who))
    return _found(detail, "server-not-found", "Server")


@router.get("/servers/{server_id}/revisions")
def list_server_revisions(
    server_id: UUID, session: DB, limit: Limit = None, cursor: CursorQ = None,
    who: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    page = _cursor_guard_none(
        lambda: inventory.list_revisions(
            session, "server", server_id, limit=limit, cursor=cursor, projects=visible_projects(who)
        )
    )
    return _page(_found(page, "server-not-found", "Server"))


def _cursor_guard_none(fn: Callable[[], inventory.Page | None]) -> inventory.Page | None:
    try:
        return fn()
    except inventory.InvalidCursorError as exc:
        raise DomainError(400, "invalid-cursor", "Invalid cursor", "The cursor is malformed.",
                          "Restart from the first page.") from exc  # fmt: skip


def _simple_resource(path: str, resource: str, what: str) -> None:
    """``GET /<path>`` and ``GET /<path>/{id}`` for a resource without extra filters."""

    def list_all(
        session: DB, project: UUID | None = None, status: str | None = None, tag: str | None = None,
        limit: Limit = None, cursor: CursorQ = None, who: Principal = VIEWER,
    ) -> dict[str, Any]:  # fmt: skip
        return _cursor_guard(
            lambda: inventory.list_observed(
                session,
                resource,
                project=project,
                status=status,
                tag=tag,
                limit=limit,
                cursor=cursor,
                projects=visible_projects(who),
            )
        )

    def get_one(item_id: UUID, session: DB, who: Principal = VIEWER) -> dict[str, Any]:
        found = inventory.get_observed(session, resource, item_id, projects=visible_projects(who))
        return _found(found, f"{resource}-not-found", what)

    router.add_api_route(f"/{path}", list_all, methods=["GET"], name=f"list_{resource}")
    router.add_api_route(f"/{path}/{{item_id}}", get_one, methods=["GET"], name=f"get_{resource}")


for _path, _resource, _what in (
    ("volumes", "volume", "Volume"),
    ("ports", "port", "Port"),
    ("floating-ips", "floating_ip", "Floating IP"),
    ("images", "image", "Image"),
    ("flavors", "flavor", "Flavor"),
):
    _simple_resource(_path, _resource, _what)


# --- services ---------------------------------------------------------------------------------------------------------------


class ServiceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=1, max_length=64)
    project_connection_id: UUID
    service_group_id: UUID | None = None
    owner_contact: str | None = Field(default=None, max_length=500)


class ServicePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=200)
    owner_contact: str | None = Field(default=None, max_length=500)
    service_group_id: UUID | None = None


class RegisterVm(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observed_server_id: UUID


def _service_scope(session: Session, service_id: UUID) -> str | None:
    svc = registry.get_service(session, service_id)
    return project_scope_of(svc["project_connection_id"]) if svc else None


def _service_project(session: Session, service_id: UUID) -> str | None:
    svc = registry.get_service(session, service_id)
    return svc["project_connection_id"] if svc else None


def _with_etag(response: Response, body: dict[str, Any]) -> dict[str, Any]:
    response.headers["ETag"] = registry.etag(int(body["version"]))
    return body


@router.get("/services")
def list_services(
    session: DB, project: UUID | None = None, limit: Limit = None, cursor: CursorQ = None,
    who: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    return _cursor_guard(
        lambda: registry.list_services(
            session, project=project, limit=limit, cursor=cursor, projects=visible_projects(who)
        )
    )


@router.post("/services", status_code=201)
def create_service(
    body: ServiceCreate, request: Request, response: Response, session: DB, auth_db: AuthDb,
    who: Principal = OPERATOR,
) -> dict[str, Any]:  # fmt: skip
    _check(request, auth_db, who, Action.REGISTRY_MANAGE, body.project_connection_id,
           "project-not-found", "Project")  # fmt: skip
    created = registry.create_service(session, actor_id=who.user_id, **body.model_dump())
    _audit(session, who, "service.create", "service", created["id"],
           scope=f"project:{created['project_connection_id']}", after=created)  # fmt: skip
    session.commit()
    response.headers["Location"] = f"/api/v1/services/{created['id']}"
    return _with_etag(response, created)


@router.get("/services/{service_id}")
def get_service(
    service_id: UUID, response: Response, session: DB, who: Principal = VIEWER
) -> dict[str, Any]:
    found = registry.get_service(session, service_id, projects=visible_projects(who))
    return _with_etag(response, _found(found, "service-not-found", "Service"))


@router.patch("/services/{service_id}")
def patch_service(
    service_id: UUID, body: ServicePatch, request: Request, response: Response, session: DB,
    auth_db: AuthDb, if_match: Annotated[str | None, Header()] = None, who: Principal = OPERATOR,
) -> dict[str, Any]:  # fmt: skip
    _check(request, auth_db, who, Action.REGISTRY_MANAGE, _service_project(session, service_id),
           "service-not-found", "Service")  # fmt: skip
    version = registry.parse_if_match(if_match)
    fields = body.model_dump(exclude_unset=True)
    before = registry.get_service(session, service_id)
    updated = registry.update_service(session, service_id, version, **fields)
    _audit(session, who, "service.update", "service", str(service_id),
           scope=f"project:{updated['project_connection_id']}", before=before, after=updated)  # fmt: skip
    session.commit()
    return _with_etag(response, updated)


@router.delete("/services/{service_id}", status_code=204)
def delete_service(
    service_id: UUID, request: Request, session: DB, auth_db: AuthDb,
    if_match: Annotated[str | None, Header()] = None, who: Principal = OPERATOR,
) -> Response:  # fmt: skip
    _check(request, auth_db, who, Action.REGISTRY_MANAGE, _service_project(session, service_id),
           "service-not-found", "Service")  # fmt: skip
    before = _found(registry.get_service(session, service_id), "service-not-found", "Service")
    registry.delete_service(session, service_id, registry.parse_if_match(if_match))
    _audit(session, who, "service.delete", "service", str(service_id),
           scope=f"project:{before['project_connection_id']}", before=before)  # fmt: skip
    session.commit()
    return Response(status_code=204)


# --- managed VMs ------------------------------------------------------------------------------------------------------------


@router.post("/services/{service_id}/managed-vms", status_code=201)
def register_managed_vm(
    service_id: UUID, body: RegisterVm, request: Request, response: Response, session: DB,
    auth_db: AuthDb, who: Principal = OPERATOR,
) -> dict[str, Any]:  # fmt: skip
    """Register an observed server as the service's current VM (201, the VM) and queue a ``host_key_scan`` run
    (``host_key_scan_run``). The renewal needs the scanned fingerprint **confirmed** by an operator
    (``POST /managed-vms/{id}/host-key/confirm``, ADR-0006) before a plan can be created."""
    _check(request, auth_db, who, Action.REGISTRY_MANAGE, _service_project(session, service_id),
           "service-not-found", "Service")  # fmt: skip
    vm = registry.register_managed_vm(
        session, service_id, body.observed_server_id, actor_id=who.user_id,
        projects=visible_projects(who, Action.REGISTRY_MANAGE),
    )  # fmt: skip
    _audit(session, who, "managed_vm.register", "managed_vm", vm["id"],
           scope=_service_scope(session, service_id), after=vm)  # fmt: skip
    scan, _ = host_keys.request_scan(session, vm, requested_by=who.user_id)
    session.commit()
    response.headers["Location"] = f"/api/v1/managed-vms/{vm['id']}"
    return {**vm, "host_key_scan_run": scan}


class HostKeyConfirm(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: str = Field(min_length=1, max_length=100)


def _vm_project(session: Session, vm_id: UUID) -> Any:
    return registry.managed_vm_project(session, vm_id)


@router.post("/managed-vms/{vm_id}/host-key-scans", status_code=202)
def request_host_key_scan(
    vm_id: UUID, request: Request, session: DB, auth_db: AuthDb, who: Principal = OPERATOR
) -> dict[str, Any]:
    """Scan the VM's SSH host key again (202, the run; an already queued scan is returned)."""
    _check(request, auth_db, who, Action.REGISTRY_MANAGE, _vm_project(session, vm_id),
           "managed-vm-not-found", "Managed VM")  # fmt: skip
    vm = _found(registry.get_managed_vm(session, vm_id), "managed-vm-not-found", "Managed VM")
    run, created = host_keys.request_scan(session, vm, requested_by=who.user_id)
    session.commit()
    return {"run": run, "already_pending": not created,
            "links": {"managed_vm": f"/api/v1/managed-vms/{vm_id}"}}  # fmt: skip


@router.post("/managed-vms/{vm_id}/host-key/confirm")
def confirm_host_key(
    vm_id: UUID, body: HostKeyConfirm, request: Request, session: DB, auth_db: AuthDb,
    who: Principal = HOST_KEY_CONFIRMER,
) -> dict[str, Any]:  # fmt: skip
    """The operator confirms the scanned fingerprint after comparing it out of band (the VM's console). Human
    session only; the body names the fingerprint, so a key that changed since the operator looked is refused."""
    _check(request, auth_db, who, Action.HOST_KEY_CONFIRM, _vm_project(session, vm_id),
           "managed-vm-not-found", "Managed VM")  # fmt: skip
    assert who.user_id is not None  # noqa: S101 - human session (matrix: human_only)
    result = host_keys.confirm(session, vm_id, body.fingerprint.strip(), actor_id=who.user_id)
    if not result["already_confirmed"]:
        _audit(session, who, "managed_vm.host_key_confirm", "managed_vm_host_key", str(vm_id),
               scope=project_scope_of(_vm_project(session, vm_id)),
               after={"managed_vm_id": str(vm_id), "fingerprint": result["fingerprint"]})  # fmt: skip
    session.commit()
    vm = _found(registry.get_managed_vm(session, vm_id), "managed-vm-not-found", "Managed VM")
    return {**vm, "already_confirmed": result["already_confirmed"]}


@router.get("/managed-vms")
def list_managed_vms(
    session: DB, service: UUID | None = None, limit: Limit = None, cursor: CursorQ = None,
    who: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    return _cursor_guard(
        lambda: registry.list_managed_vms(
            session, service_id=service, limit=limit, cursor=cursor, projects=visible_projects(who)
        )
    )


@router.get("/managed-vms/{vm_id}")
def get_managed_vm(vm_id: UUID, session: DB, who: Principal = VIEWER) -> dict[str, Any]:
    found = registry.get_managed_vm(session, vm_id, projects=visible_projects(who))
    return _found(found, "managed-vm-not-found", "Managed VM")


@router.delete("/managed-vms/{vm_id}", status_code=204)
def unregister_managed_vm(
    vm_id: UUID, request: Request, session: DB, auth_db: AuthDb, who: Principal = OPERATOR
) -> Response:
    _check(request, auth_db, who, Action.REGISTRY_MANAGE, registry.managed_vm_project(session, vm_id),
           "managed-vm-not-found", "Managed VM")  # fmt: skip
    before = _found(registry.get_managed_vm(session, vm_id), "managed-vm-not-found", "Managed VM")
    registry.unregister_managed_vm(session, vm_id)
    _audit(session, who, "managed_vm.unregister", "managed_vm", str(vm_id),
           scope=_service_scope(session, UUID(before["service_id"])), before=before)  # fmt: skip
    session.commit()
    return Response(status_code=204)
