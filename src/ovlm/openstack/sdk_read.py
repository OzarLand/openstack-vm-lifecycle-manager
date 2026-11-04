"""The openstacksdk-backed ``ReadClient`` (the only module that imports ``openstack``).

* The session is wrapped by the GET/HEAD-only hook before its first request (``guard``).
* Microversions are negotiated once and recorded (``NegotiatedVersions``): the SDK pins a per-resource maximum
  (``Server`` 2.100, ``Volume`` 3.71 at openstacksdk 4.22.0) and uses ``min(pinned, cloud max)``. This client
  requires compute >= 2.52 (tags) and reports what it will use.
* Everything returned is an OVLM dataclass; SDK exceptions are translated to ``ovlm.openstack.errors``.

Not covered by CI: there is no real cloud in CI. Mapping is tested with SDK resources built from Nova-, Cinder-
and Neutron-shaped bodies; the first run against a real cloud is the lab run (E2-4). Until then this module is
"unit tested" only, never "lab validated".
"""

from __future__ import annotations

import contextlib
import logging
import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import openstack
from keystoneauth1 import exceptions as ks_exc
from openstack import exceptions as os_exc
from openstack.block_storage.v3.volume import Volume as SdkVolume
from openstack.compute.v2.server import Server as SdkServer
from openstack.config import OpenStackConfig

from ovlm.openstack.errors import (
    AuthenticationError,
    NotFoundError,
    OpenStackError,
    UnsupportedCloudError,
    translate_http_error,
)
from ovlm.openstack.guard import install_read_only_guard
from ovlm.openstack.types import (
    COMPUTE_TAGS_AT_CREATE,
    STATUS_UNKNOWN,
    AttachedVolume,
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

log = logging.getLogger("ovlm.openstack")

Version = tuple[int, int]


def parse_version(value: str | tuple[int, ...] | None) -> Version | None:
    if value is None:
        return None
    if isinstance(value, tuple):
        return (int(value[0]), int(value[1]))
    major, _, minor = str(value).partition(".")
    return (int(major), int(minor or 0))


def parse_time(value: object) -> datetime | None:
    """Nova returns ``...Z`` or naive timestamps (UTC); always return an aware UTC datetime."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


@contextlib.contextmanager
def translated() -> Iterator[None]:
    """Translate SDK and keystoneauth exceptions into OVLM errors."""
    try:
        yield
    except OpenStackError:
        raise
    except os_exc.HttpException as exc:
        status = int(exc.status_code or 0)
        raise translate_http_error(status, exc.details or str(exc)) from exc
    except ks_exc.Unauthorized as exc:
        raise AuthenticationError(str(exc), status=401) from exc
    except (os_exc.SDKException, ks_exc.ClientException) as exc:
        raise OpenStackError(str(exc)) from exc


# --- mapping (pure functions, unit tested with SDK resources) -----------------------------------------------


def _image_id(image: Any) -> str | None:
    if not image:
        return None
    value = image.get("id") if isinstance(image, dict) else getattr(image, "id", None)
    return str(value) if value else None


def map_server(s: Any) -> ServerInfo:
    status = str(s.status or "")
    flavor = s.flavor
    fl_name = (
        (getattr(flavor, "original_name", None) or getattr(flavor, "name", None))
        if flavor
        else None
    )
    attached = tuple(
        AttachedVolume(
            volume_id=str(getattr(v, "volume_id", None) or v.id),
            delete_on_termination=getattr(v, "delete_on_termination", None),
        )
        for v in (s.attached_volumes or [])
    )
    return ServerInfo(
        openstack_id=str(s.id),
        name=s.name,
        status=status,
        vm_state=s.vm_state,
        task_state=s.task_state,
        power_state=s.power_state,
        created=parse_time(s.created_at),
        launched_at=parse_time(s.launched_at),
        updated=parse_time(s.updated_at),
        flavor_original_name=fl_name,
        flavor_vcpus=getattr(flavor, "vcpus", None) if flavor else None,
        flavor_ram=getattr(flavor, "ram", None) if flavor else None,
        flavor_disk=getattr(flavor, "disk", None) if flavor else None,
        image_id=_image_id(s.image),
        availability_zone=s.availability_zone,
        locked=s.is_locked,
        locked_reason=s.locked_reason,
        tags=tuple(s.tags or ()),
        metadata=dict(s.metadata or {}),
        host_id=s.host_id,
        attached_volumes=attached,
        is_minimal_construct=status == STATUS_UNKNOWN,
    )


def map_volume(v: Any) -> VolumeInfo:
    attachments = tuple(
        VolumeAttachmentInfo(
            server_openstack_id=str(a["server_id"]),
            volume_openstack_id=str(v.id),
            device=a.get("device"),
            attachment_id=a.get("attachment_id"),
        )
        for a in (v.attachments or [])
        if a.get("server_id")
    )
    return VolumeInfo(
        openstack_id=str(v.id),
        name=v.name,
        status=str(v.status or ""),
        size=v.size,
        bootable=v.is_bootable,
        multiattach=v.is_multiattach,
        availability_zone=v.availability_zone,
        volume_type=v.volume_type,
        metadata=dict(v.metadata or {}),
        attachments=attachments,
    )


def map_port(p: Any) -> PortInfo:
    return PortInfo(
        openstack_id=str(p.id),
        name=p.name,
        network_id=p.network_id,
        device_id=p.device_id,
        device_owner=p.device_owner,
        fixed_ips=tuple(
            (str(f.get("ip_address")), f.get("subnet_id")) for f in (p.fixed_ips or [])
        ),
        mac=p.mac_address,
        security_group_ids=tuple(p.security_group_ids or ()),
        status=p.status,
    )


def map_floating_ip(f: Any) -> FloatingIpInfo:
    return FloatingIpInfo(
        openstack_id=str(f.id),
        floating_ip_address=str(f.floating_ip_address),
        port_id=f.port_id,
        fixed_ip_address=f.fixed_ip_address,
        router_id=f.router_id,
        floating_network_id=f.floating_network_id,
        status=f.status,
        tags=tuple(f.tags or ()),
    )


def map_network(n: Any) -> NetworkInfo:
    return NetworkInfo(
        openstack_id=str(n.id),
        name=n.name,
        status=n.status,
        is_external=bool(n.is_router_external),
        is_shared=bool(n.is_shared),
        subnet_ids=tuple(n.subnet_ids or ()),
    )


def map_image(i: Any) -> ImageInfo:
    return ImageInfo(
        openstack_id=str(i.id),
        name=i.name,
        status=i.status,
        visibility=i.visibility,
        owner_id=i.owner,
    )


def map_flavor(f: Any) -> FlavorInfo:
    return FlavorInfo(
        openstack_id=str(f.id),
        name=str(f.name),
        vcpus=f.vcpus,
        ram=f.ram,
        disk=f.disk,
        ephemeral=f.ephemeral,
        is_public=f.is_public,
    )


# --- the client ---------------------------------------------------------------------------------------------


class SdkReadClient:
    """``ReadClient`` on an openstacksdk ``Connection`` whose session already carries the read-only hook."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn
        self._versions: NegotiatedVersions | None = None

    # versions ---------------------------------------------------------------------------------------------

    def negotiated_versions(self) -> NegotiatedVersions:
        if self._versions is not None:
            return self._versions
        with translated():
            compute = self._conn.compute.get_endpoint_data()
            if compute is None:
                raise UnsupportedCloudError("no compute endpoint in the service catalog")
            compute_max = parse_version(compute.max_microversion)
            if compute_max is None:
                raise UnsupportedCloudError("the compute API does not advertise microversions")
            if compute_max < COMPUTE_TAGS_AT_CREATE:
                raise UnsupportedCloudError(
                    f"compute microversion {compute_max[0]}.{compute_max[1]} is below 2.52 (server tags)"
                )
            sdk_compute = parse_version(SdkServer._max_microversion) or compute_max
            bs_max = bs_used = None
            bs = self._conn.block_storage.get_endpoint_data()
            if bs is not None:
                bs_max = parse_version(bs.max_microversion)
                sdk_bs = parse_version(SdkVolume._max_microversion)
                if bs_max is not None and sdk_bs is not None:
                    bs_used = min(bs_max, sdk_bs)
        self._versions = NegotiatedVersions(
            compute_max=compute_max,
            compute_used=min(compute_max, sdk_compute),
            block_storage_max=bs_max,
            block_storage_used=bs_used,
        )
        log.info("microversions negotiated", extra={"versions": self._versions.as_json()})
        return self._versions

    def project_id(self) -> str:
        with translated():
            value = self._conn.session.get_project_id()
        if not value:
            raise AuthenticationError("the token is not project scoped")
        return str(value)

    # servers ----------------------------------------------------------------------------------------------

    def list_servers(
        self,
        *,
        changes_since: datetime | None = None,
        tags: Iterable[str] = (),
        tags_any: Iterable[str] = (),
        name: str | None = None,
    ) -> list[ServerInfo]:
        query: dict[str, Any] = {}
        if changes_since is not None:
            query["changes_since"] = changes_since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        if tag_list := list(tags):
            query["tags"] = ",".join(tag_list)
        if any_list := list(tags_any):
            query["any_tags"] = ",".join(any_list)
        if name is not None:
            query["name"] = f"^{re.escape(name)}$"  # Nova's name filter is a regex
        with translated():
            servers = [map_server(s) for s in self._conn.compute.servers(details=True, **query)]
        if name is not None:
            servers = [s for s in servers if s.name == name]  # re-check equality client side
        return servers

    def get_server(self, server_id: str) -> ServerInfo:
        with translated():
            try:
                return map_server(self._conn.compute.get_server(server_id))
            except os_exc.NotFoundException as exc:
                raise NotFoundError(f"server {server_id} not found", status=404) from exc

    def list_server_volume_attachments(self, server_id: str) -> list[VolumeAttachmentInfo]:
        with translated():
            return [
                VolumeAttachmentInfo(
                    server_openstack_id=server_id,
                    volume_openstack_id=str(a.volume_id),
                    device=a.device,
                    attachment_id=a.attachment_id,
                    delete_on_termination=a.delete_on_termination,
                )
                for a in self._conn.compute.volume_attachments(server_id)
            ]

    # block storage ----------------------------------------------------------------------------------------

    def list_volumes(self) -> list[VolumeInfo]:
        with translated():
            return [map_volume(v) for v in self._conn.block_storage.volumes(details=True)]

    def get_volume(self, volume_id: str) -> VolumeInfo:
        with translated():
            try:
                return map_volume(self._conn.block_storage.get_volume(volume_id))
            except os_exc.NotFoundException as exc:
                raise NotFoundError(f"volume {volume_id} not found", status=404) from exc

    def list_volume_types(self) -> list[VolumeTypeInfo]:
        default_id: str | None = None
        with translated():
            try:  # GET /types/default (block storage 3.62); a cloud without a default type answers with an error
                body = self._conn.block_storage.get("/types/default", microversion="3.62").json()
                default_id = (body.get("volume_type") or {}).get("id")
            except (os_exc.SDKException, ks_exc.ClientException, ValueError):
                default_id = None
            return [
                VolumeTypeInfo(str(t.id), str(t.name), is_default=str(t.id) == default_id)
                for t in self._conn.block_storage.types()
            ]

    # network, image, flavor -------------------------------------------------------------------------------

    def list_ports(self) -> list[PortInfo]:
        with translated():
            return [map_port(p) for p in self._conn.network.ports()]

    def list_floating_ips(self) -> list[FloatingIpInfo]:
        with translated():
            return [map_floating_ip(f) for f in self._conn.network.ips()]

    def list_networks(self) -> list[NetworkInfo]:
        with translated():
            return [map_network(n) for n in self._conn.network.networks()]

    def list_images(self) -> list[ImageInfo]:
        with translated():
            return [map_image(i) for i in self._conn.image.images()]

    def list_flavors(self) -> list[FlavorInfo]:
        with translated():
            return [map_flavor(f) for f in self._conn.compute.flavors(details=True)]


def connect_read_only(cloud: str, clouds_yaml: Path | None = None) -> SdkReadClient:
    """Build a read client from a ``clouds.yaml`` entry. The GET/HEAD guard is installed before any request
    (authentication happens lazily on the first call). Environment variables are not read."""
    files = [str(clouds_yaml)] if clouds_yaml else None
    config = OpenStackConfig(config_files=files, load_envvars=False)
    region = config.get_one(cloud=cloud)
    install_read_only_guard(region.get_session())
    conn = openstack.connection.Connection(config=region)
    return SdkReadClient(conn)
