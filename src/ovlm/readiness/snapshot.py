"""The input snapshot: everything the checks read, as plain JSON, taken once per assessment (FR-RDY-4).

The loader reads only the DB inventory and the desired state, through the public service functions of ``inventory``,
``registry`` and ``profiles``: it never calls OpenStack and never touches the guest. The checks then read nothing
but this dict, so the stored snapshot lets anyone re-derive the stored results.

Shape (``schema`` 1)::

    taken_at, now                 ISO timestamps (``now`` is what attestation expiry is judged against)
    live_code_run                 false: an assessment runs no repository code on the live VM (SEC-R-28)
    managed_vm                    {id, service_id, openstack_server_id, role}
    profile                       {id, version_id, number, spec_hash, spec} or null; ``spec`` leaves out
                                  ``automation.inventory_vars`` and ``automation.secret_refs`` (never stored here)
    server                        {id, openstack_id, name, observation_status, synced_at, payload_hash,
                                   revision_id, data}   (``data`` is the observed payload)
    attachments                   [{volume_openstack_id, device, delete_on_termination}]
    volumes                       {openstack_id: {status, size, bootable, multiattach, volume_type, observation_status}}
    ports / networks / floating_ips   of this server only
    flavor_candidates             flavors whose name equals the profile's flavor
    image_candidates              images whose name equals the profile's image name (only for a name rule)
    quota                         null: the inventory holds no quota reading yet
    attestations                  rows of ``attestation`` for this VM
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ovlm.inventory import service as inventory
from ovlm.profiles import service as profiles
from ovlm.readiness.tables import attestation
from ovlm.registry import service as registry

SCHEMA = 1


def _all(session: Session, resource: str, **filters: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor = None
    while True:
        page = inventory.list_observed(
            session, resource, limit=inventory.MAX_PAGE, cursor=cursor, **filters
        )
        items.extend(page.items)
        if not page.next_cursor:
            return items
        cursor = page.next_cursor


def _latest_revision(session: Session, server_id: UUID) -> dict[str, Any] | None:
    """The newest observed revision of the server (its history is short: one row per change)."""
    last: dict[str, Any] | None = None
    cursor = None
    while True:
        page = inventory.list_revisions(session, "server", server_id, cursor=cursor)
        if page is None:
            return last
        if page.items:
            last = page.items[-1]
        if not page.next_cursor:
            return last
        cursor = page.next_cursor


def _storable(spec: dict[str, Any]) -> dict[str, Any]:
    """The spec as the snapshot keeps it: without ``automation.inventory_vars`` (free-form values that may hold a
    secret by mistake) and ``automation.secret_refs``. The spec hash identifies the full spec."""
    out = {**spec, "automation": {k: v for k, v in spec["automation"].items() if k not in _DROPPED}}
    return out


_DROPPED = ("inventory_vars", "secret_refs")


def build_snapshot(
    session: Session, managed_vm_id: UUID, *, now: datetime | None = None
) -> dict[str, Any] | None:
    """The snapshot for one managed VM, or ``None`` if the VM no longer exists."""
    taken = (now or datetime.now(UTC)).astimezone(UTC)
    vm = registry.get_managed_vm(session, managed_vm_id)
    if vm is None:
        return None
    service = registry.get_service(session, UUID(vm["service_id"]))
    prof = profiles.profile_of_service(session, UUID(vm["service_id"])) if service else None
    version = (
        profiles.get_version(session, UUID(prof["id"]), prof["latest_version"])
        if prof and prof["latest_version"]
        else None
    )
    spec = _storable(version["spec"]) if version else None

    snap: dict[str, Any] = {
        "schema": SCHEMA,
        "taken_at": taken.isoformat(),
        "now": taken.isoformat(),
        "live_code_run": False,
        "managed_vm": {k: vm[k] for k in ("id", "service_id", "openstack_server_id", "role")},
        "profile": (
            {"id": prof["id"], "version_id": version["id"], "number": version["number"],
             "spec_hash": version["spec_hash"], "spec": spec}  # fmt: skip
            if prof and version
            else None
        ),
        "server": None, "attachments": [], "volumes": {}, "ports": [], "networks": {},
        "floating_ips": [], "flavor_candidates": [], "image_candidates": [],
        "quota": None, "attestations": [],
    }  # fmt: skip

    detail = inventory.server_detail(session, UUID(vm["observed_server_id"]))
    if detail is not None:
        revision = _latest_revision(session, UUID(detail["id"]))
        obs = detail["observation"]
        snap["server"] = {
            "id": detail["id"], "openstack_id": detail["openstack_id"], "name": detail["name"],
            "observation_status": obs["status"], "synced_at": obs["synced_at"],
            "payload_hash": revision["payload_hash"] if revision else None,
            "revision_id": revision["id"] if revision else None, "data": detail["data"],
        }  # fmt: skip
        project = UUID(detail["project_connection_id"])
        snap["attachments"] = [
            {
                k: a["data"].get(k)
                for k in ("volume_openstack_id", "device", "delete_on_termination")
            }
            for a in detail["attachments"]
        ]
        vol_ids = [a["volume_openstack_id"] for a in snap["attachments"]]
        if spec and (spec.get("data_volume") or {}).get("volume_id"):
            vol_ids.append(str(spec["data_volume"]["volume_id"]))
        if vol_ids:
            for v in _all(session, "volume", project=project, openstack_ids=set(vol_ids)):
                d = v["data"]
                snap["volumes"][v["openstack_id"]] = {
                    "status": d.get("status"), "size": d.get("size"), "bootable": d.get("bootable"),
                    "multiattach": d.get("multiattach"), "volume_type": d.get("volume_type"),
                    "observation_status": v["observation"]["status"],
                }  # fmt: skip
        snap["ports"] = [
            {"openstack_id": p["openstack_id"], "network_id": p["data"].get("network_id")}
            for p in detail["ports"]
        ]
        net_ids = {p["network_id"] for p in snap["ports"] if p["network_id"]}
        if net_ids:
            for n in _all(session, "network", project=project, openstack_ids=net_ids):
                snap["networks"][n["openstack_id"]] = {
                    "name": n["name"], "is_external": bool(n["data"].get("is_external")),
                }  # fmt: skip
        snap["floating_ips"] = [
            {"openstack_id": f["openstack_id"], "floating_ip_address": f["data"].get("floating_ip_address"),
             "port_id": f["data"].get("port_id")}
            for f in detail["floating_ips"]
        ]  # fmt: skip
        if spec:
            flavor = spec.get("flavor")
            snap["flavor_candidates"] = [
                {"openstack_id": f["openstack_id"], "name": f["name"], **{k: f["data"].get(k) for k in ("vcpus", "ram", "disk")}}
                for f in _all(session, "flavor", project=project, status="present")
                if f["name"] == flavor
            ]  # fmt: skip
            image_name = (spec.get("image") or {}).get("name")
            if image_name:
                snap["image_candidates"] = [
                    {"openstack_id": i["openstack_id"], "name": i["name"], "status": i["data"].get("status"),
                     "visibility": i["data"].get("visibility")}
                    for i in _all(session, "image", project=project, status="present")
                    if i["name"] == image_name
                ]  # fmt: skip

    rows = session.execute(
        select(attestation).where(attestation.c.managed_vm_id == managed_vm_id)
        .order_by(attestation.c.attested_at.desc())
    ).all()  # fmt: skip
    snap["attestations"] = [
        {"check_key": r.check_key, "attested_by": str(r.attested_by), "attested_at": r.attested_at.isoformat(),
         "expires_at": r.expires_at.isoformat() if r.expires_at else None,
         "profile_version_id": str(r.profile_version_id)}
        for r in rows
    ]  # fmt: skip
    return snap
