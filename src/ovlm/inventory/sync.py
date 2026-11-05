"""The inventory sync job (worker process only: it calls OpenStack through a ``ReadClient``).

A plain function, ``run_inventory_sync``. The ``inventory_sync`` workflow (:mod:`ovlm.inventory.job`) calls it with
the run's real ``project_connection_id`` and ``workflow_run_id`` (written to ``sync_run``), after opening the read
client from the project's stored read credential. Nothing here depends on the engine.

Rules implemented (data-model.md section 3, openstack-integration.md section 1 and recommendation 9):

* The cloud is read completely **before** anything is written; a failed read marks the ``sync_run`` failed and
  changes nothing else, so a failed sync never marks anything ``gone``.
* Current rows are updated in place; a revision row is appended only when the normalised payload hash changes.
* ``full``: every kind of resource is listed. A resource absent from a successful full sync gets
  ``missed_syncs + 1``; at ``gone_after_missed_syncs`` it becomes ``gone`` (never deleted). Seen again: ``present``.
* ``servers_delta``: Nova ``changes-since`` only. Tombstones (status ``DELETED``) mark ``gone`` at once; nothing
  is counted as missed (a delta is not a full listing).
* Minimal-construct servers (status ``UNKNOWN``, unreachable cell) become ``unknown``: never ``gone``, and their
  last known payload is kept, not overwritten with empty fields.
* One sync per project at a time (PostgreSQL advisory lock); a second caller gets ``SyncAlreadyRunningError``.
"""

from __future__ import annotations

import dataclasses
import logging
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import Connection, Engine, bindparam, case, func, insert, select, update

from ovlm.inventory.ids import uuid7
from ovlm.inventory.tables import OBSERVED, REVISIONS, sync_run
from ovlm.observability.redaction import redact_text
from ovlm.openstack.interface import ReadClient
from ovlm.openstack.types import (
    FlavorInfo,
    FloatingIpInfo,
    ImageInfo,
    NegotiatedVersions,
    NetworkInfo,
    PortInfo,
    ServerInfo,
    VolumeAttachmentInfo,
    VolumeInfo,
    payload_hash,
    to_payload,
)

log = logging.getLogger("ovlm.inventory")

SyncKind = Literal["full", "servers_delta"]
_CHUNK = 2000
_COUNT_KEYS = (
    "seen",
    "created",
    "changed",
    "unchanged",
    "unknown",
    "gone",
    "missed",
    "reappeared",
    "ignored_tombstones",
)


class SyncAlreadyRunningError(RuntimeError):
    """Another sync of the same project holds the advisory lock."""


@dataclass(frozen=True)
class SyncConfig:
    """Mirrors ``Settings.inventory`` (architecture.md section 5); the worker builds it with
    :func:`ovlm.inventory.job.sync_config`. Defaults are TBD in the lab."""

    gone_after_missed_syncs: int = 3
    #: A delta asks for changes since (previous successful sync start - overlap): covers clock skew.
    delta_overlap: timedelta = timedelta(seconds=120)
    #: ``auto`` runs a full sync when the last full one is older than this (Nova delta cannot see tag edits for
    #: sure, openstack-integration.md section 1).
    full_sync_every: timedelta = timedelta(hours=6)


@dataclass
class SyncResult:
    sync_run_id: UUID
    kind: SyncKind
    status: Literal["succeeded", "failed"]
    counts: dict[str, dict[str, int]] = field(default_factory=dict)
    versions: dict[str, str | None] = field(default_factory=dict)
    error: dict[str, str] | None = None


@dataclass
class _Item:
    openstack_id: str
    name: str | None
    typed: dict[str, Any]
    payload: dict[str, Any]
    digest: str
    unknown: bool = False
    tombstone: bool = False


# --- adapter objects -> rows --------------------------------------------------------------------------------


def _item(
    info: Any, openstack_id: str, name: str | None, typed: dict[str, Any], **flags: bool
) -> _Item:
    payload = to_payload(info)
    return _Item(openstack_id, name, typed, payload, payload_hash(payload), **flags)


def server_item(s: ServerInfo) -> _Item:
    typed = {
        "server_status": s.status, "vm_state": s.vm_state, "task_state": s.task_state,
        "power_state": s.power_state, "created": s.created, "launched_at": s.launched_at,
        "nova_updated_at": s.updated, "flavor_original_name": s.flavor_original_name,
        "flavor_vcpus": s.flavor_vcpus, "flavor_ram": s.flavor_ram, "flavor_disk": s.flavor_disk,
        "image_id": s.image_id, "availability_zone": s.availability_zone, "locked": s.locked,
        "locked_reason": s.locked_reason, "tags": list(s.tags), "metadata": dict(s.metadata),
        "host_id": s.host_id, "is_minimal_construct": s.is_minimal_construct,
    }  # fmt: skip
    return _item(
        s, s.openstack_id, s.name, typed, unknown=s.is_minimal_construct, tombstone=s.is_deleted
    )


def volume_item(v: VolumeInfo) -> _Item:
    typed = {
        "volume_status": v.status, "size": v.size, "bootable": v.bootable, "multiattach": v.multiattach,
        "availability_zone": v.availability_zone, "volume_type": v.volume_type, "metadata": dict(v.metadata),
    }  # fmt: skip
    return _item(v, v.openstack_id, v.name, typed)


def attachment_item(a: VolumeAttachmentInfo) -> _Item:
    typed = {
        "server_openstack_id": a.server_openstack_id, "volume_openstack_id": a.volume_openstack_id,
        "device": a.device, "attachment_id": a.attachment_id,
        "delete_on_termination": a.delete_on_termination,
    }  # fmt: skip
    return _item(a, a.openstack_id, None, typed)


def port_item(p: PortInfo) -> _Item:
    typed = {
        "network_id": p.network_id, "device_id": p.device_id, "device_owner": p.device_owner,
        "fixed_ips": [{"ip_address": ip, "subnet_id": sn} for ip, sn in p.fixed_ips], "mac": p.mac,
        "security_group_ids": list(p.security_group_ids), "port_status": p.status,
    }  # fmt: skip
    return _item(p, p.openstack_id, p.name, typed)


def floating_ip_item(f: FloatingIpInfo) -> _Item:
    typed = {
        "floating_ip_address": f.floating_ip_address, "port_id": f.port_id,
        "fixed_ip_address": f.fixed_ip_address, "router_id": f.router_id,
        "floating_network_id": f.floating_network_id, "floating_ip_status": f.status, "tags": list(f.tags),
    }  # fmt: skip
    return _item(f, f.openstack_id, f.floating_ip_address, typed)


def network_item(n: NetworkInfo) -> _Item:
    typed = {"network_status": n.status, "is_external": n.is_external, "is_shared": n.is_shared}
    return _item(n, n.openstack_id, n.name, typed)


def image_item(i: ImageInfo) -> _Item:
    typed = {"image_status": i.status, "visibility": i.visibility, "owner_id": i.owner_id}
    return _item(i, i.openstack_id, i.name, typed)


def flavor_item(f: FlavorInfo) -> _Item:
    typed = {
        "vcpus": f.vcpus,
        "ram": f.ram,
        "disk": f.disk,
        "ephemeral": f.ephemeral,
        "is_public": f.is_public,
    }
    return _item(f, f.openstack_id, f.name, typed)


def derive_attachments(
    servers: Sequence[ServerInfo], volumes: Sequence[VolumeInfo]
) -> list[VolumeAttachmentInfo]:
    """Cinder says which server a volume is attached to; ``delete_on_termination`` comes from the server's
    ``volumes_attached`` (compute >= 2.79), so no per-server call is needed."""
    dot = {
        (s.openstack_id, av.volume_id): av.delete_on_termination
        for s in servers
        for av in s.attached_volumes
    }
    return [
        dataclasses.replace(
            a, delete_on_termination=dot.get((a.server_openstack_id, a.volume_openstack_id))
        )
        for v in volumes
        for a in v.attachments
    ]


# --- fetch ----------------------------------------------------------------------------------------------------


def _fetch_full(client: ReadClient) -> dict[str, list[_Item]]:
    servers = client.list_servers()
    volumes = client.list_volumes()
    return {
        "server": [server_item(s) for s in servers],
        "volume": [volume_item(v) for v in volumes],
        "volume_attachment": [attachment_item(a) for a in derive_attachments(servers, volumes)],
        "port": [port_item(p) for p in client.list_ports()],
        "floating_ip": [floating_ip_item(f) for f in client.list_floating_ips()],
        "network": [network_item(n) for n in client.list_networks()],
        "image": [image_item(i) for i in client.list_images()],
        "flavor": [flavor_item(f) for f in client.list_flavors()],
    }


def _fetch_delta(client: ReadClient, since: datetime) -> dict[str, list[_Item]]:
    return {"server": [server_item(s) for s in client.list_servers(changes_since=since)]}


# --- write ----------------------------------------------------------------------------------------------------


def _chunks(seq: Sequence[Any], size: int = _CHUNK) -> Iterator[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _apply(
    conn: Connection,
    resource: str,
    items: list[_Item],
    *,
    project: UUID,
    sync_id: UUID,
    now: datetime,
    full: bool,
    gone_after: int,
) -> dict[str, int]:
    tbl, rev = OBSERVED[resource], REVISIONS[resource]
    rev_fk = f"observed_{resource}_id"
    counts: Counter[str] = Counter({k: 0 for k in _COUNT_KEYS})
    counts["seen"] = len(items)

    query = select(tbl.c.id, tbl.c.openstack_id, tbl.c.payload_hash, tbl.c.status).where(
        tbl.c.project_connection_id == project
    )
    existing = {r.openstack_id: r for r in conn.execute(query)}

    inserts: list[dict[str, Any]] = []
    revisions: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unchanged: list[UUID] = []
    unknown: list[UUID] = []
    tombstoned: list[UUID] = []

    def new_revision(row_id: UUID, item: _Item) -> None:
        revisions.append(
            {"id": uuid7(), rev_fk: row_id, "sync_run_id": sync_id, "payload": item.payload,
             "payload_hash": item.digest, "observed_at": now}
        )  # fmt: skip

    for item in items:
        row = existing.get(item.openstack_id)
        if item.tombstone:
            if row is None:
                counts["ignored_tombstones"] += 1  # deleted before we ever saw it
            elif row.status != "gone":
                tombstoned.append(row.id)
            continue
        if row is None:
            row_id = uuid7()
            inserts.append(
                {"id": row_id, "project_connection_id": project, "openstack_id": item.openstack_id,
                 "name": item.name, **item.typed, "payload": item.payload, "payload_hash": item.digest,
                 "first_seen_sync_id": sync_id, "last_seen_sync_id": sync_id, "missed_syncs": 0,
                 "status": "unknown" if item.unknown else "present", "gone_at": None, "synced_at": now,
                 "created_at": now, "updated_at": now}
            )  # fmt: skip
            new_revision(row_id, item)
            counts["created"] += 1
            counts["unknown"] += int(item.unknown)
            continue
        if (
            item.unknown
        ):  # keep the last known payload; the cell is unreachable, not the server gone
            unknown.append(row.id)
            counts["unknown"] += 1
            continue
        if row.status == "gone":
            counts["reappeared"] += 1
        if row.payload_hash == item.digest:
            unchanged.append(row.id)
            counts["unchanged"] += 1
        else:
            changed.append(
                {"b_id": row.id, "name": item.name, **item.typed, "payload": item.payload,
                 "payload_hash": item.digest, "last_seen_sync_id": sync_id, "missed_syncs": 0,
                 "status": "present", "gone_at": None, "synced_at": now, "updated_at": now}
            )  # fmt: skip
            new_revision(row.id, item)
            counts["changed"] += 1

    if inserts:
        conn.execute(insert(tbl), inserts)
    if changed:
        conn.execute(update(tbl).where(tbl.c.id == bindparam("b_id")), changed)
    for chunk in _chunks(unchanged):
        conn.execute(
            update(tbl).where(tbl.c.id.in_(chunk)).values(
                last_seen_sync_id=sync_id, missed_syncs=0, status="present", gone_at=None,
                synced_at=now, updated_at=now,
            )
        )  # fmt: skip
    for chunk in _chunks(unknown):
        conn.execute(
            update(tbl).where(tbl.c.id.in_(chunk)).values(
                last_seen_sync_id=sync_id, missed_syncs=0, status="unknown", synced_at=now, updated_at=now
            )
        )  # fmt: skip
    for chunk in _chunks(tombstoned):  # last known payload kept; the tombstone adds nothing we need
        conn.execute(
            update(tbl).where(tbl.c.id.in_(chunk)).values(
                last_seen_sync_id=sync_id, status="gone", gone_at=now, synced_at=now, updated_at=now
            )
        )  # fmt: skip
        counts["gone"] += len(chunk)
    if revisions:
        conn.execute(insert(rev), revisions)

    if full:
        # Everything seen carries last_seen_sync_id == sync_id, so "absent" is "different": one statement.
        over = tbl.c.missed_syncs + 1 >= gone_after
        result = conn.execute(
            update(tbl)
            .where(
                tbl.c.project_connection_id == project,
                tbl.c.status.in_(("present", "unknown")),
                tbl.c.last_seen_sync_id != sync_id,
            )
            .values(
                missed_syncs=tbl.c.missed_syncs + 1,
                status=case((over, "gone"), else_=tbl.c.status),
                gone_at=case((over, now), else_=tbl.c.gone_at),
                updated_at=now,
            )
            .returning(tbl.c.status)
        )
        statuses = [r.status for r in result]
        counts["missed"] += len(statuses)
        counts["gone"] += sum(1 for s in statuses if s == "gone")
    return dict(counts)


# --- the job ---------------------------------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _lock_key(project: UUID) -> Any:
    return func.hashtextextended(f"ovlm.inventory.sync:{project}", 0)


def _last_success(engine: Engine, project: UUID, kind: SyncKind | None) -> datetime | None:
    cond = [sync_run.c.project_connection_id == project, sync_run.c.status == "succeeded"]
    if kind is not None:
        cond.append(sync_run.c.kind == kind)
    with engine.connect() as conn:
        found: datetime | None = conn.execute(
            select(sync_run.c.started_at)
            .where(*cond)
            .order_by(sync_run.c.started_at.desc())
            .limit(1)
        ).scalar()
    return found


def choose_kind(
    engine: Engine,
    project: UUID,
    now: datetime,
    config: SyncConfig,
    requested: SyncKind | Literal["auto"] = "auto",
) -> tuple[SyncKind, datetime | None]:
    """``(kind, delta_since)``. A delta needs a previous successful sync and a full sync before it (the delta
    only updates what changed). ``auto`` also forces a full sync once the last one is older than
    ``full_sync_every``."""
    last_ok = _last_success(engine, project, None)
    last_full = _last_success(engine, project, "full")
    if requested == "full" or last_ok is None or last_full is None:
        return "full", None
    if requested == "auto" and now - last_full >= config.full_sync_every:
        return "full", None
    return "servers_delta", last_ok - config.delta_overlap


def run_inventory_sync(
    engine: Engine,
    client: ReadClient,
    project_connection_id: UUID,
    *,
    kind: SyncKind | Literal["auto"] = "auto",
    config: SyncConfig | None = None,
    clock: Callable[[], datetime] = _utcnow,
    workflow_run_id: UUID | None = None,
) -> SyncResult:
    """Sync one project. Returns the result (``failed`` is a result, not an exception); raises
    ``SyncAlreadyRunningError`` if another sync of the project is active."""
    config = config or SyncConfig()
    started = clock()
    sync_id = uuid7()

    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as lock_conn:
        got = lock_conn.execute(
            select(func.pg_try_advisory_lock(_lock_key(project_connection_id)))
        ).scalar()
        if not got:
            raise SyncAlreadyRunningError(
                f"a sync of project {project_connection_id} is already running"
            )
        try:
            return _run_locked(
                engine,
                client,
                project_connection_id,
                kind,
                config,
                clock,
                started,
                sync_id,
                workflow_run_id,
            )
        finally:
            lock_conn.execute(select(func.pg_advisory_unlock(_lock_key(project_connection_id))))


def _run_locked(
    engine: Engine,
    client: ReadClient,
    project: UUID,
    requested: SyncKind | Literal["auto"],
    config: SyncConfig,
    clock: Callable[[], datetime],
    started: datetime,
    sync_id: UUID,
    workflow_run_id: UUID | None,
) -> SyncResult:
    kind, since = choose_kind(engine, project, started, config, requested)

    with engine.begin() as conn:
        conn.execute(
            insert(sync_run).values(
                id=sync_id, project_connection_id=project, kind=kind, status="running",
                started_at=started, workflow_run_id=workflow_run_id,
            )
        )  # fmt: skip
    log.info("inventory sync started", extra={"sync_run_id": str(sync_id), "kind": kind})

    try:
        versions: NegotiatedVersions = client.negotiated_versions()
        fetched = (
            _fetch_delta(client, since)
            if kind == "servers_delta" and since
            else _fetch_full(client)
        )
        now = clock()
        counts: dict[str, dict[str, int]] = {}
        with engine.begin() as conn:
            for resource, items in fetched.items():
                counts[resource] = _apply(
                    conn, resource, items, project=project, sync_id=sync_id, now=now,
                    full=kind == "full", gone_after=config.gone_after_missed_syncs,
                )  # fmt: skip
            conn.execute(
                update(sync_run).where(sync_run.c.id == sync_id).values(
                    status="succeeded", finished_at=now, counts=counts, versions=versions.as_json()
                )
            )  # fmt: skip
    except Exception as exc:  # noqa: BLE001 - recorded on the sync_run, nothing else was changed
        error = {"type": type(exc).__name__, "message": redact_text(str(exc))[:500]}
        with engine.begin() as conn:
            conn.execute(
                update(sync_run).where(sync_run.c.id == sync_id).values(
                    status="failed", finished_at=clock(), error=error
                )
            )  # fmt: skip
        log.error("inventory sync failed", extra={"sync_run_id": str(sync_id), "error": error})
        return SyncResult(sync_id, kind, "failed", error=error)
    log.info("inventory sync finished", extra={"sync_run_id": str(sync_id), "kind": kind})
    return SyncResult(sync_id, kind, "succeeded", counts, versions.as_json())
