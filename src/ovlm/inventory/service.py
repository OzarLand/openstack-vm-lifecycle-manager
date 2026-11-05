"""Read side of the inventory, used by the api and by ``registry`` (architecture.md section 3).

Never imports ``ovlm.openstack`` (the api must not reach it, not even indirectly) and never writes: the observed
tables are written by the worker's sync job only (data-model.md section 1). Listings are cursor paged over
``(created_at, id)`` (api-design.md section 1).
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Row, Select, and_, any_, false, literal, or_, select
from sqlalchemy.orm import Session

from ovlm.inventory.reasons import public_error
from ovlm.inventory.tables import OBSERVATION_STATUSES, OBSERVED, REVISIONS, sync_run

MAX_PAGE = 200
DEFAULT_PAGE = 50
#: Typed Nova/Cinder/... status column per resource, for ``?status=ACTIVE`` style filters.
_NATIVE_STATUS = {
    "server": "server_status",
    "volume": "volume_status",
    "port": "port_status",
    "floating_ip": "floating_ip_status",
    "network": "network_status",
    "image": "image_status",
}


class InvalidCursorError(ValueError):
    pass


#: Project scoping (security-model.md 3.3): ``None`` = every project (global binding), otherwise the set of
#: ``project_connection`` ids the caller may see (``ovlm.auth.authz.visible_projects``). An empty set sees nothing.
Projects = Collection[UUID] | None


def scoped(stmt: Select[Any], column: Any, projects: Projects) -> Select[Any]:
    """Restrict ``stmt`` to rows whose ``column`` (a project_connection id) is in ``projects``."""
    if projects is None:
        return stmt
    return stmt.where(column.in_(list(projects))) if projects else stmt.where(false())


@dataclass(frozen=True)
class Page:
    items: list[dict[str, Any]]
    next_cursor: str | None


def encode_cursor(created_at: datetime, row_id: UUID) -> str:
    raw = json.dumps([created_at.isoformat(), str(row_id)]).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        ts, rid = json.loads(raw)
        return datetime.fromisoformat(ts), UUID(rid)
    except (ValueError, TypeError, binascii.Error, json.JSONDecodeError) as exc:
        raise InvalidCursorError("malformed cursor") from exc


def clamp_limit(limit: int | None) -> int:
    return max(1, min(limit or DEFAULT_PAGE, MAX_PAGE))


def _page(rows: list[Row[Any]], limit: int, to_dict: Any) -> Page:
    more = len(rows) > limit
    rows = rows[:limit]
    nxt = encode_cursor(rows[-1].created_at, rows[-1].id) if more and rows else None
    return Page([to_dict(r) for r in rows], nxt)


def _keyset(stmt: Select[Any], table: Any, cursor: str | None) -> Select[Any]:
    if cursor:
        ts, rid = decode_cursor(cursor)
        stmt = stmt.where(
            or_(table.c.created_at > ts, and_(table.c.created_at == ts, table.c.id > rid))
        )
    return stmt.order_by(table.c.created_at, table.c.id)


def _observed_dict(row: Row[Any]) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "openstack_id": row.openstack_id,
        "project_connection_id": str(row.project_connection_id),
        "name": row.name,
        "observation": {
            "status": row.status,
            "missed_syncs": row.missed_syncs,
            "first_seen_sync_id": str(row.first_seen_sync_id),
            "last_seen_sync_id": str(row.last_seen_sync_id),
            "synced_at": row.synced_at.isoformat(),
            "gone_at": row.gone_at.isoformat() if row.gone_at else None,
        },
        "data": row.payload,
    }


def list_observed(
    session: Session,
    resource: str,
    *,
    project: UUID | None = None,
    status: str | None = None,
    tag: str | None = None,
    openstack_ids: Collection[str] | None = None,
    exclude_openstack_ids: Collection[str] | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    projects: Projects = None,
) -> Page:
    """``status`` is the observation status (``present``, ``gone``, ``unknown``) or, for other values, the
    resource's own status (for example a server's ``ACTIVE``). ``tag`` applies to servers and floating IPs.
    ``openstack_ids`` / ``exclude_openstack_ids`` restrict to, or exclude, a known set (the ``registered`` filter)."""
    tbl = OBSERVED[resource]
    n = clamp_limit(limit)
    stmt = scoped(select(tbl), tbl.c.project_connection_id, projects)
    if project is not None:
        stmt = stmt.where(tbl.c.project_connection_id == project)
    if status is not None:
        if status in OBSERVATION_STATUSES:
            stmt = stmt.where(tbl.c.status == status)
        elif resource in _NATIVE_STATUS:
            stmt = stmt.where(tbl.c[_NATIVE_STATUS[resource]] == status)
        else:
            return Page([], None)
    if tag is not None and "tags" in tbl.c:
        stmt = stmt.where(literal(tag) == any_(tbl.c.tags))
    if openstack_ids is not None:
        stmt = stmt.where(tbl.c.openstack_id.in_(list(openstack_ids)))
    if exclude_openstack_ids:
        stmt = stmt.where(tbl.c.openstack_id.not_in(list(exclude_openstack_ids)))
    stmt = _keyset(stmt, tbl, cursor).limit(n + 1)
    return _page(list(session.execute(stmt)), n, _observed_dict)


def get_observed(
    session: Session, resource: str, row_id: UUID, *, projects: Projects = None
) -> dict[str, Any] | None:
    """``None`` when absent **or** outside ``projects`` (the api answers 404 for both)."""
    tbl = OBSERVED[resource]
    stmt = scoped(select(tbl).where(tbl.c.id == row_id), tbl.c.project_connection_id, projects)
    row = session.execute(stmt).first()
    return _observed_dict(row) if row else None


def server_detail(
    session: Session, row_id: UUID, *, projects: Projects = None
) -> dict[str, Any] | None:
    """The observed server with its attachments, ports and floating IPs (api-design.md section 3.2). The related
    rows are taken from the server's own project only."""
    server = get_observed(session, "server", row_id, projects=projects)
    if server is None:
        return None
    project = UUID(server["project_connection_id"])
    sid = server["openstack_id"]
    att, port, fip = (OBSERVED[r] for r in ("volume_attachment", "port", "floating_ip"))
    attachments = session.execute(
        select(att).where(att.c.project_connection_id == project, att.c.server_openstack_id == sid)
    ).all()
    ports = session.execute(
        select(port).where(port.c.project_connection_id == project, port.c.device_id == sid)
    ).all()
    port_ids = [p.openstack_id for p in ports]
    fips = (
        session.execute(
            select(fip).where(fip.c.project_connection_id == project, fip.c.port_id.in_(port_ids))
        ).all()
        if port_ids
        else []
    )
    server["attachments"] = [_observed_dict(r) for r in attachments]
    server["ports"] = [_observed_dict(r) for r in ports]
    server["floating_ips"] = [_observed_dict(r) for r in fips]
    server["links"] = {"revisions": f"/api/v1/servers/{row_id}/revisions"}
    return server


def list_revisions(
    session: Session,
    resource: str,
    row_id: UUID,
    *,
    limit: int | None = None,
    cursor: str | None = None,
    projects: Projects = None,
) -> Page | None:
    """Snapshot history, oldest first. ``None`` if the observed row does not exist or is outside ``projects``."""
    cur, rev = OBSERVED[resource], REVISIONS[resource]
    parent = scoped(
        select(cur.c.id).where(cur.c.id == row_id), cur.c.project_connection_id, projects
    )
    if session.execute(parent).first() is None:
        return None
    n = clamp_limit(limit)
    fk = rev.c[f"observed_{resource}_id"]
    stmt = select(rev).where(fk == row_id)
    if cursor:
        ts, rid = decode_cursor(cursor)
        stmt = stmt.where(
            or_(rev.c.observed_at > ts, and_(rev.c.observed_at == ts, rev.c.id > rid))
        )
    stmt = stmt.order_by(rev.c.observed_at, rev.c.id).limit(n + 1)
    rows = list(session.execute(stmt))
    more = len(rows) > n
    rows = rows[:n]

    def to_dict(r: Row[Any]) -> dict[str, Any]:
        return {
            "id": str(r.id),
            "sync_run_id": str(r.sync_run_id),
            "observed_at": r.observed_at.isoformat(),
            "payload_hash": r.payload_hash,
            "payload": r.payload,
        }

    return Page(
        [to_dict(r) for r in rows],
        encode_cursor(rows[-1].observed_at, rows[-1].id) if more else None,
    )


def _sync_dict(r: Row[Any]) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "project_connection_id": str(r.project_connection_id),
        "kind": r.kind,
        "status": r.status,
        "started_at": r.started_at.isoformat(),
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "counts": r.counts,
        "versions": r.versions,
        "error": public_error(r.error),  # a fixed code only (review IS-4)
        "workflow_run_id": str(r.workflow_run_id) if r.workflow_run_id else None,
    }


def list_syncs(
    session: Session, project: UUID, *, limit: int | None = None, cursor: str | None = None
) -> Page:
    """Newest first. The cursor is ``(started_at, id)``."""
    n = clamp_limit(limit)
    stmt = select(sync_run).where(sync_run.c.project_connection_id == project)
    if cursor:
        ts, rid = decode_cursor(cursor)
        stmt = stmt.where(
            or_(sync_run.c.started_at < ts, and_(sync_run.c.started_at == ts, sync_run.c.id < rid))
        )
    rows = list(
        session.execute(
            stmt.order_by(sync_run.c.started_at.desc(), sync_run.c.id.desc()).limit(n + 1)
        )
    )
    more = len(rows) > n
    rows = rows[:n]
    return Page(
        [_sync_dict(r) for r in rows],
        encode_cursor(rows[-1].started_at, rows[-1].id) if more else None,
    )


def get_sync(
    session: Session, sync_id: UUID, *, projects: Projects = None
) -> dict[str, Any] | None:
    stmt = select(sync_run).where(sync_run.c.id == sync_id)
    row = session.execute(scoped(stmt, sync_run.c.project_connection_id, projects)).first()
    return _sync_dict(row) if row else None


@dataclass(frozen=True)
class ObservedServerRef:
    """What registration needs to know about an observed server."""

    id: UUID
    openstack_id: str
    project_connection_id: UUID
    name: str | None
    observation_status: str
    is_minimal_construct: bool
    server_status: str
    launched_at: datetime | None
    created: datetime | None


def get_server_ref(
    session: Session, row_id: UUID, *, projects: Projects = None
) -> ObservedServerRef | None:
    t = OBSERVED["server"]
    r = session.execute(
        scoped(select(t).where(t.c.id == row_id), t.c.project_connection_id, projects)
    ).first()
    if r is None:
        return None
    return ObservedServerRef(
        r.id, r.openstack_id, r.project_connection_id, r.name, r.status, r.is_minimal_construct,
        r.server_status, r.launched_at, r.created,
    )  # fmt: skip


def get_servers_by_openstack_ids(
    session: Session, ids: Collection[str], *, projects: Projects = None
) -> Mapping[str, dict[str, Any]]:
    """Observed servers by OpenStack id, for the managed-VM ``observed`` block; pass the managed VM's own project
    in ``projects`` so a server observed in another project is never shown."""
    if not ids:
        return {}
    t = OBSERVED["server"]
    stmt = scoped(
        select(t).where(t.c.openstack_id.in_(list(ids))), t.c.project_connection_id, projects
    )
    rows = session.execute(stmt).all()
    return {r.openstack_id: _observed_dict(r) for r in rows}
