"""OVLM's own vocabulary for what OpenStack reports. Frozen, hashable, JSON-serialisable via ``to_payload``.

Nothing here imports the SDK. Field choices follow data-model.md section 3 and openstack-integration.md section 1:
the embedded flavor (no id from compute 2.47), nullable ``launched_at``, ``is_minimal_construct`` for servers
returned by an unreachable cell (compute 2.69), and no admin-only attributes (host names stay out).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

#: Compute microversion that tags at create need (tags filter and list need 2.26).
COMPUTE_TAGS_AT_CREATE = (2, 52)
#: Compute microversion that exposes ``delete_on_termination`` on volume attachments.
COMPUTE_DELETE_ON_TERMINATION = (2, 79)
#: Server status a Nova ``changes-since`` listing returns for a deleted server (tombstone).
STATUS_DELETED = "DELETED"
#: Status of a server returned as a minimal construct by an unreachable cell (compute 2.69).
STATUS_UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class NegotiatedVersions:
    """What the cloud supports and what this client uses; recorded on every sync run."""

    compute_max: tuple[int, int]
    compute_used: tuple[int, int]
    block_storage_max: tuple[int, int] | None = None
    block_storage_used: tuple[int, int] | None = None

    def as_json(self) -> dict[str, str | None]:
        def fmt(v: tuple[int, int] | None) -> str | None:
            return None if v is None else f"{v[0]}.{v[1]}"

        return {
            "compute_max": fmt(self.compute_max),
            "compute_used": fmt(self.compute_used),
            "block_storage_max": fmt(self.block_storage_max),
            "block_storage_used": fmt(self.block_storage_used),
        }


@dataclass(frozen=True)
class AttachedVolume:
    """One entry of a server's ``os-extended-volumes:volumes_attached`` (``delete_on_termination`` from 2.79)."""

    volume_id: str
    delete_on_termination: bool | None = None


@dataclass(frozen=True)
class ServerInfo:
    openstack_id: str
    name: str | None
    status: str
    vm_state: str | None = None
    task_state: str | None = None
    power_state: int | None = None
    created: datetime | None = None
    launched_at: datetime | None = None
    updated: datetime | None = None
    flavor_original_name: str | None = None
    flavor_vcpus: int | None = None
    flavor_ram: int | None = None
    flavor_disk: int | None = None
    image_id: str | None = None  # None for boot from volume
    availability_zone: str | None = None
    locked: bool | None = None
    locked_reason: str | None = None
    tags: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)
    host_id: str | None = None  # opaque hash, never a host name
    attached_volumes: tuple[AttachedVolume, ...] = ()
    is_minimal_construct: bool = False

    @property
    def is_deleted(self) -> bool:
        return self.status == STATUS_DELETED


@dataclass(frozen=True)
class VolumeAttachmentInfo:
    """A volume attached to a server. ``delete_on_termination`` is None when the cloud does not say."""

    server_openstack_id: str
    volume_openstack_id: str
    device: str | None = None
    attachment_id: str | None = None
    delete_on_termination: bool | None = None

    @property
    def openstack_id(self) -> str:
        """Nova has no id of its own for this relation: the pair is the key."""
        return f"{self.server_openstack_id}:{self.volume_openstack_id}"


@dataclass(frozen=True)
class VolumeInfo:
    openstack_id: str
    name: str | None
    status: str
    size: int | None = None
    bootable: bool | None = None
    multiattach: bool | None = None
    availability_zone: str | None = None
    volume_type: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    attachments: tuple[VolumeAttachmentInfo, ...] = ()


@dataclass(frozen=True)
class VolumeTypeInfo:
    openstack_id: str
    name: str
    is_default: bool = False


@dataclass(frozen=True)
class PortInfo:
    openstack_id: str
    name: str | None
    network_id: str | None = None
    device_id: str | None = None
    device_owner: str | None = None
    fixed_ips: tuple[tuple[str, str | None], ...] = ()  # (ip_address, subnet_id)
    mac: str | None = None
    security_group_ids: tuple[str, ...] = ()
    status: str | None = None


@dataclass(frozen=True)
class FloatingIpInfo:
    openstack_id: str
    floating_ip_address: str
    port_id: str | None = None
    fixed_ip_address: str | None = None
    router_id: str | None = None
    floating_network_id: str | None = None
    status: str | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class NetworkInfo:
    openstack_id: str
    name: str | None
    status: str | None = None
    is_external: bool = False
    is_shared: bool = False
    subnet_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ImageInfo:
    openstack_id: str
    name: str | None
    status: str | None = None
    visibility: str | None = None
    owner_id: str | None = None


@dataclass(frozen=True)
class FlavorInfo:
    openstack_id: str
    name: str
    vcpus: int | None = None
    ram: int | None = None
    disk: int | None = None
    ephemeral: int | None = None
    is_public: bool | None = None


@dataclass(frozen=True)
class CreateServerSpec:
    """Input of ``WriteClient.create_server``. Tags are set atomically with the create (compute >= 2.52)."""

    name: str
    image_id: str
    flavor_id: str
    network_id: str | None = None
    port_id: str | None = None
    tags: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)
    availability_zone: str | None = None
    security_group_names: tuple[str, ...] = ()
    key_name: str | None = None
    #: cloud-init user-data (plain text; the client base64-encodes it). May hold the per-run bootstrap host key
    #: (ADR-0006): kept out of ``repr`` and never logged.
    user_data: str | None = field(default=None, repr=False)


# --- payload normalisation (the jsonb stored in observed_* and compared by hash) -----------------------------


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def to_payload(obj: object) -> dict[str, Any]:
    """Normalised, JSON-safe dict of an adapter dataclass."""
    result = _jsonable(obj)
    if not isinstance(result, dict):
        raise TypeError(f"not a dataclass instance: {type(obj).__name__}")
    return result


def payload_hash(payload: dict[str, Any]) -> str:
    """SHA-256 over canonical JSON (sorted keys, no whitespace): equal payloads hash equal, always."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()
