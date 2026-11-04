"""REST endpoints for inventory (observed state) and registration (services, managed VMs), api-design.md s.3.2, 3.3.

Reads the database only: the api never calls OpenStack (architecture.md section 2). Syncs are run by the worker.

Authentication and RBAC come from ``ovlm.auth.deps.require_role`` (viewer for reads, operator for changes; API
tokens need the ``operate`` scope for changes). Changes are audited with ``ovlm.audit.record`` in the request's
transaction, with allowlisted fields.

# AUTH-HOOK (E3-2): project scoping of results is not done yet. Reads accept any role holder, and list results are
not filtered with ``ovlm.auth.authz.scopes_for``; a project-scoped viewer still sees every project, where the design
says out-of-scope resources answer 404. Filtering needs each resource mapped to its project in the inventory and
registry queries, so it is left for E3-2 rather than half done here.

Not implemented here, on purpose (workflow engine, E5-1): ``POST /projects/{id}/syncs`` (202 run) and the host-key scan
that registration should start (api-design.md s.3.3 says 202; this returns 201 without a scan).
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine, Iterator
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.deps import require_role
from ovlm.auth.errors import ProblemError, problem_response
from ovlm.auth.principal import Principal
from ovlm.config import Settings
from ovlm.db.engine import make_engine, make_session_factory
from ovlm.inventory import service as inventory
from ovlm.registry import service as registry
from ovlm.registry.errors import DomainError

# One dependency object per role (also keeps ruff B008 quiet). Tokens need the ``operate`` scope for changes.
VIEWER = Depends(require_role("viewer"))
OPERATOR = Depends(require_role("operator", token_scope="operate"))  # noqa: S106 - an API token scope name, not a secret


audit.register_entity(
    "service",
    ["name", "slug", "project_connection_id", "service_group_id", "version"],
    secret_fields=["owner_contact"],  # contact details: only the fact of a change is recorded
)
audit.register_entity(
    "managed_vm", ["service_id", "observed_server_id", "openstack_server_id", "role"]
)


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


# --- inventory ---------------------------------------------------------------------------------------------------------


@router.get("/projects/{project_id}/syncs")
def list_syncs(
    project_id: UUID, session: DB, limit: Limit = None, cursor: CursorQ = None,
    _: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    return _cursor_guard(
        lambda: inventory.list_syncs(session, project_id, limit=limit, cursor=cursor)
    )


@router.get("/syncs/{sync_id}")
def get_sync(sync_id: UUID, session: DB, _: Principal = VIEWER) -> dict[str, Any]:
    return _found(inventory.get_sync(session, sync_id), "sync-not-found", "Sync")


@router.get("/servers")
def list_servers(
    session: DB,
    project: UUID | None = None,
    status: str | None = None,
    tag: str | None = None,
    registered: bool | None = None,
    limit: Limit = None,
    cursor: CursorQ = None,
    _: Principal = VIEWER,
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
            exclude_openstack_ids=exclude, limit=limit, cursor=cursor,
        )
    )  # fmt: skip


@router.get("/servers/{server_id}")
def get_server(server_id: UUID, session: DB, _: Principal = VIEWER) -> dict[str, Any]:
    return _found(inventory.server_detail(session, server_id), "server-not-found", "Server")


@router.get("/servers/{server_id}/revisions")
def list_server_revisions(
    server_id: UUID, session: DB, limit: Limit = None, cursor: CursorQ = None,
    _: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    page = _cursor_guard_none(
        lambda: inventory.list_revisions(session, "server", server_id, limit=limit, cursor=cursor)
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
        limit: Limit = None, cursor: CursorQ = None, _: Principal = VIEWER,
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
            )
        )

    def get_one(item_id: UUID, session: DB, _: Principal = VIEWER) -> dict[str, Any]:
        return _found(
            inventory.get_observed(session, resource, item_id), f"{resource}-not-found", what
        )

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
    return f"project:{svc['project_connection_id']}" if svc else None


def _with_etag(response: Response, body: dict[str, Any]) -> dict[str, Any]:
    response.headers["ETag"] = registry.etag(int(body["version"]))
    return body


@router.get("/services")
def list_services(
    session: DB, project: UUID | None = None, limit: Limit = None, cursor: CursorQ = None,
    _: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    return _cursor_guard(
        lambda: registry.list_services(session, project=project, limit=limit, cursor=cursor)
    )


@router.post("/services", status_code=201)
def create_service(
    body: ServiceCreate, response: Response, session: DB, who: Principal = OPERATOR
) -> dict[str, Any]:
    created = registry.create_service(session, actor_id=who.user_id, **body.model_dump())
    _audit(session, who, "service.create", "service", created["id"],
           scope=f"project:{created['project_connection_id']}", after=created)  # fmt: skip
    session.commit()
    response.headers["Location"] = f"/api/v1/services/{created['id']}"
    return _with_etag(response, created)


@router.get("/services/{service_id}")
def get_service(
    service_id: UUID, response: Response, session: DB, _: Principal = VIEWER
) -> dict[str, Any]:
    return _with_etag(
        response, _found(registry.get_service(session, service_id), "service-not-found", "Service")
    )


@router.patch("/services/{service_id}")
def patch_service(
    service_id: UUID, body: ServicePatch, response: Response, session: DB,
    if_match: Annotated[str | None, Header()] = None, who: Principal = OPERATOR,
) -> dict[str, Any]:  # fmt: skip
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
    service_id: UUID, session: DB, if_match: Annotated[str | None, Header()] = None,
    who: Principal = OPERATOR,
) -> Response:  # fmt: skip
    before = _found(registry.get_service(session, service_id), "service-not-found", "Service")
    registry.delete_service(session, service_id, registry.parse_if_match(if_match))
    _audit(session, who, "service.delete", "service", str(service_id),
           scope=f"project:{before['project_connection_id']}", before=before)  # fmt: skip
    session.commit()
    return Response(status_code=204)


# --- managed VMs ------------------------------------------------------------------------------------------------------------


@router.post("/services/{service_id}/managed-vms", status_code=201)
def register_managed_vm(
    service_id: UUID, body: RegisterVm, response: Response, session: DB, who: Principal = OPERATOR,
) -> dict[str, Any]:  # fmt: skip
    """Register an observed server as the service's current VM. api-design.md says this also starts a host-key scan
    run (202); that needs the workflow engine, so for now it answers 201 and the host key stays unconfirmed."""
    vm = registry.register_managed_vm(
        session, service_id, body.observed_server_id, actor_id=who.user_id
    )
    _audit(session, who, "managed_vm.register", "managed_vm", vm["id"],
           scope=_service_scope(session, service_id), after=vm)  # fmt: skip
    session.commit()
    response.headers["Location"] = f"/api/v1/managed-vms/{vm['id']}"
    return vm


@router.get("/managed-vms")
def list_managed_vms(
    session: DB, service: UUID | None = None, limit: Limit = None, cursor: CursorQ = None,
    _: Principal = VIEWER,
) -> dict[str, Any]:  # fmt: skip
    return _cursor_guard(
        lambda: registry.list_managed_vms(session, service_id=service, limit=limit, cursor=cursor)
    )


@router.get("/managed-vms/{vm_id}")
def get_managed_vm(vm_id: UUID, session: DB, _: Principal = VIEWER) -> dict[str, Any]:
    return _found(registry.get_managed_vm(session, vm_id), "managed-vm-not-found", "Managed VM")


@router.delete("/managed-vms/{vm_id}", status_code=204)
def unregister_managed_vm(vm_id: UUID, session: DB, who: Principal = OPERATOR) -> Response:
    before = _found(registry.get_managed_vm(session, vm_id), "managed-vm-not-found", "Managed VM")
    registry.unregister_managed_vm(session, vm_id)
    _audit(session, who, "managed_vm.unregister", "managed_vm", str(vm_id),
           scope=_service_scope(session, UUID(before["service_id"])), before=before)  # fmt: skip
    session.commit()
    return Response(status_code=204)
