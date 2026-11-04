"""openstacksdk-backed write backend and ``connect_write`` (E5-2).

* Uses the **write credential** (its own ``clouds.yaml`` entry) on a session that carries the write guard
  (``allowlist.install_write_guard``) before its first request. Reads reuse ``SdkReadClient`` on that session
  (GET passes the guard), so read behaviour is the read client's, unchanged.
* Every mutating call is an explicit request (method, relative path, JSON body) through the SDK's service
  proxies, which are keystoneauth Adapters: the verb and body are OVLM's, not the SDK's choice (the claim must use
  the per-tag add and the metadata merge forms, SEC-R-24), and the allowlist sees exactly what is sent.
* Compute write calls pin microversion :data:`COMPUTE_WRITE_MICROVERSION` (2.79: tags at create >= 2.52, lock
  reason >= 2.73, ``delete_on_termination`` on attachments >= 2.79). A cloud below it is refused before any write.
  ``write_microversions()`` returns what is pinned and what the cloud offers, for step evidence.
* HTTP errors are translated by ``errors.translate_http_error`` from the response body's message.

Not covered by CI: there is no real cloud in CI. Requests are tested against a canned transport; the first run
against a real cloud is the lab run (E5-6). Until then this module is "unit tested" only.
"""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import openstack
from openstack.config import OpenStackConfig
from openstack.network.v2.floating_ip import FloatingIP as SdkFloatingIP

from ovlm.openstack.allowlist import Gate, GateBinding, install_write_guard
from ovlm.openstack.errors import (
    NotFoundError,
    UnsupportedCloudError,
    WriteNotAllowedError,
    translate_http_error,
)
from ovlm.openstack.ownership import OwnershipRegistry
from ovlm.openstack.sdk_read import (
    SdkReadClient,
    map_floating_ip,
    map_port,
    parse_version,
    translated,
)
from ovlm.openstack.types import (
    CreateServerSpec,
    FlavorInfo,
    FloatingIpInfo,
    ImageInfo,
    NegotiatedVersions,
    NetworkInfo,
    PortInfo,
    ServerInfo,
    VolumeAttachmentInfo,
    VolumeInfo,
    VolumeTypeInfo,
)
from ovlm.openstack.write import GuardedWriteClient

log = logging.getLogger("ovlm.openstack.write")

COMPUTE_WRITE_MICROVERSION = "2.79"
_COMPUTE_MIN = parse_version(COMPUTE_WRITE_MICROVERSION)


def error_message(resp: Any) -> str:
    """The ``message`` of a Nova (``{"conflictingRequest": {"message": ...}}``), Cinder (same shape) or Neutron
    (``{"NeutronError": {"message": ...}}``) error body; the raw text, truncated, otherwise."""
    try:
        body = resp.json()
    except (ValueError, json.JSONDecodeError):
        body = None
    if isinstance(body, dict):
        for value in body.values():
            if isinstance(value, dict) and isinstance(value.get("message"), str):
                return str(value["message"])
        if isinstance(body.get("message"), str):
            return str(body["message"])
    return str(getattr(resp, "text", "") or "")[:500]


def _check(resp: Any) -> Any:
    status = int(resp.status_code)
    if status >= 400:
        raise translate_http_error(status, error_message(resp))
    return resp


class SdkWriteBackend:
    """Raw write operations on a guarded connection. Not for steps: they get ``GuardedWriteClient``."""

    def __init__(self, conn: Any, binding: GateBinding) -> None:
        self._conn = conn
        self._binding = binding
        self._reader = SdkReadClient(conn)
        self._compute_max: tuple[int, int] | None = None

    @property
    def gate_binding(self) -> GateBinding:
        return self._binding

    # --- versions ------------------------------------------------------------------------------------------

    def _require_compute(self) -> None:
        if self._compute_max is None:
            versions = self._reader.negotiated_versions()
            if _COMPUTE_MIN is None or versions.compute_max < _COMPUTE_MIN:
                raise UnsupportedCloudError(
                    f"compute microversion {versions.compute_max} is below {COMPUTE_WRITE_MICROVERSION}"
                )
            self._compute_max = versions.compute_max

    def write_microversions(self) -> dict[str, str | None]:
        self._require_compute()
        versions = self._reader.negotiated_versions()
        return {
            "compute_write": COMPUTE_WRITE_MICROVERSION,
            "compute_max": versions.as_json()["compute_max"],
            "block_storage_write": "3.0",
            "block_storage_max": versions.as_json()["block_storage_max"],
            "network": None,  # Neutron has no microversions
        }

    # --- reads (delegated) ---------------------------------------------------------------------------------

    def negotiated_versions(self) -> NegotiatedVersions:
        return self._reader.negotiated_versions()

    def project_id(self) -> str:
        return self._reader.project_id()

    def list_servers(
        self,
        *,
        changes_since: datetime | None = None,
        tags: Iterable[str] = (),
        tags_any: Iterable[str] = (),
        name: str | None = None,
    ) -> list[ServerInfo]:
        return self._reader.list_servers(
            changes_since=changes_since, tags=tags, tags_any=tags_any, name=name
        )

    def get_server(self, server_id: str) -> ServerInfo:
        return self._reader.get_server(server_id)

    def list_server_volume_attachments(self, server_id: str) -> list[VolumeAttachmentInfo]:
        return self._reader.list_server_volume_attachments(server_id)

    def list_volumes(self) -> list[VolumeInfo]:
        return self._reader.list_volumes()

    def get_volume(self, volume_id: str) -> VolumeInfo:
        return self._reader.get_volume(volume_id)

    def list_volume_types(self) -> list[VolumeTypeInfo]:
        return self._reader.list_volume_types()

    def list_ports(self) -> list[PortInfo]:
        return self._reader.list_ports()

    def list_floating_ips(self) -> list[FloatingIpInfo]:
        return self._reader.list_floating_ips()

    def list_networks(self) -> list[NetworkInfo]:
        return self._reader.list_networks()

    def list_images(self) -> list[ImageInfo]:
        return self._reader.list_images()

    def list_flavors(self) -> list[FlavorInfo]:
        return self._reader.list_flavors()

    def get_floating_ip(self, floating_ip_id: str) -> FloatingIpInfo:
        with translated():
            return map_floating_ip(self._conn.network.get_ip(floating_ip_id))

    def get_port(self, port_id: str) -> PortInfo:
        with translated():
            return map_port(self._conn.network.get_port(port_id))

    def get_server_fault(self, server_id: str) -> str | None:
        with translated():
            resp = _check(self._conn.compute.get(f"/servers/{quote(server_id, safe='')}"))
            fault = resp.json().get("server", {}).get("fault") or {}
            message = fault.get("message") if isinstance(fault, dict) else None
            return str(message) if message else None

    # --- writes --------------------------------------------------------------------------------------------

    def _compute(self, method: str, path: str, body: Any = None) -> Any:
        self._require_compute()
        call: Callable[..., Any] = getattr(self._conn.compute, method)
        kwargs: dict[str, Any] = {"microversion": COMPUTE_WRITE_MICROVERSION}
        if body is not None:
            kwargs["json"] = body
        with translated():
            return _check(call(path, **kwargs))

    def _action(self, server_id: str, body: dict[str, Any]) -> Any:
        return self._compute("post", f"/servers/{quote(server_id, safe='')}/action", body)

    def create_server(self, spec: CreateServerSpec) -> ServerInfo:
        if bool(spec.network_id) == bool(spec.port_id):
            raise WriteNotAllowedError("create_server needs exactly one of network_id and port_id")
        server: dict[str, Any] = {
            "name": spec.name,
            "imageRef": spec.image_id,
            "flavorRef": spec.flavor_id,
            "networks": [{"uuid": spec.network_id} if spec.network_id else {"port": spec.port_id}],
            "tags": list(spec.tags),
            "metadata": dict(spec.metadata),
        }
        if spec.availability_zone:
            server["availability_zone"] = spec.availability_zone
        if spec.security_group_names:
            server["security_groups"] = [{"name": n} for n in spec.security_group_names]
        if spec.key_name:
            server["key_name"] = spec.key_name
        if spec.user_data is not None:
            server["user_data"] = base64.b64encode(spec.user_data.encode()).decode()
        resp = self._compute("post", "/servers", {"server": server})
        created = resp.json().get("server") or {}  # carries adminPass: never logged, never returned
        server_id = str(created.get("id") or "")
        if not server_id:
            raise NotFoundError(
                "create_server: the response carries no server id", status=resp.status_code
            )
        log.info("server create accepted", extra={"server_id": server_id})
        return ServerInfo(
            openstack_id=server_id, name=spec.name, status="BUILD", tags=tuple(spec.tags),
            metadata=dict(spec.metadata), image_id=spec.image_id,
        )  # fmt: skip

    def delete_server(self, server_id: str) -> None:
        self._compute("delete", f"/servers/{quote(server_id, safe='')}")

    def stop_server(self, server_id: str) -> None:
        self._action(server_id, {"os-stop": None})

    def start_server(self, server_id: str) -> None:
        self._action(server_id, {"os-start": None})

    def lock_server(self, server_id: str, reason: str | None = None) -> None:
        self._action(server_id, {"lock": {"locked_reason": reason} if reason else None})

    def unlock_server(self, server_id: str) -> None:
        self._action(server_id, {"unlock": None})

    def get_console_output(self, server_id: str, length: int | None = None) -> str:
        body: dict[str, Any] = {} if length is None else {"length": int(length)}
        resp = self._action(server_id, {"os-getConsoleOutput": body})
        return str(resp.json().get("output") or "")

    def add_server_tag(self, server_id: str, tag: str) -> None:
        self._compute("put", f"/servers/{quote(server_id, safe='')}/tags/{quote(tag, safe='')}")

    def attach_volume(self, server_id: str, volume_id: str) -> None:
        self._compute(
            "post",
            f"/servers/{quote(server_id, safe='')}/os-volume_attachments",
            {"volumeAttachment": {"volumeId": volume_id}},
        )

    def detach_volume(self, server_id: str, volume_id: str) -> None:
        self._compute(
            "delete",
            f"/servers/{quote(server_id, safe='')}/os-volume_attachments/{quote(volume_id, safe='')}",
        )

    def update_floating_ip(
        self, floating_ip_id: str, port_id: str, fixed_ip_address: str | None = None
    ) -> FloatingIpInfo:
        fip: dict[str, Any] = {"port_id": port_id}
        if fixed_ip_address:
            fip["fixed_ip_address"] = fixed_ip_address
        with translated():
            resp = _check(
                self._conn.network.put(
                    f"/floatingips/{quote(floating_ip_id, safe='')}", json={"floatingip": fip}
                )
            )
            return map_floating_ip(SdkFloatingIP.existing(**resp.json()["floatingip"]))

    def add_floating_ip_tag(self, floating_ip_id: str, tag: str) -> None:
        with translated():
            _check(
                self._conn.network.put(
                    f"/floatingips/{quote(floating_ip_id, safe='')}/tags/{quote(tag, safe='')}"
                )
            )

    def merge_volume_metadata(self, volume_id: str, items: Mapping[str, str]) -> None:
        with translated():
            _check(
                self._conn.block_storage.post(
                    f"/volumes/{quote(volume_id, safe='')}/metadata",
                    json={"metadata": {str(k): str(v) for k, v in items.items()}},
                )
            )


def connect_write(
    cloud: str,
    *,
    registry: OwnershipRegistry,
    gate: Gate,
    process_role: str,
    clouds_yaml: Path | None = None,
) -> GuardedWriteClient:
    """Build the write client of one step attempt from the **write** credential's ``clouds.yaml`` entry.

    Refuses outside the worker process (architecture.md section 3). The write guard is installed on the session
    before any request (authentication happens lazily on the first call). Environment variables are not read."""
    if process_role != "worker":
        raise WriteNotAllowedError(
            f"the write client exists only in the worker, not in {process_role!r}"
        )
    files = [str(clouds_yaml)] if clouds_yaml else None
    config = OpenStackConfig(config_files=files, load_envvars=False)
    region = config.get_one(cloud=cloud)
    binding = GateBinding()
    install_write_guard(region.get_session(), binding)
    conn = openstack.connection.Connection(config=region)
    return GuardedWriteClient(SdkWriteBackend(conn, binding), registry, gate)
