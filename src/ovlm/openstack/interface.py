"""The adapter interface, in OVLM's vocabulary (architecture.md section 3, testing-strategy.md section 3.2).

``ReadClient`` is what inventory, readiness and planning use: it can only read (GET/HEAD) and is enforced twice,
by this interface having no write methods and by the request hook in ``guard`` (SEC-R-5).

``WriteClient`` is the write side (E5-2): the method set the renewal strategy needs (renewal-workflow.md,
openstack-integration.md sections 3, 4, 6, 7) and nothing more. ``write.GuardedWriteClient`` implements it with the
ownership guard; its backends (``sdk_write`` and the fake) implement it raw, behind the allowlist and fence gate.

Both are structural ``Protocol`` types; ``fake.FakeOpenStack`` implements both.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Protocol, runtime_checkable

from ovlm.openstack.types import (
    BlockStorageLimits,
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
    VolumeSnapshotInfo,
    VolumeTypeInfo,
)


@runtime_checkable
class ReadClient(Protocol):
    """Read-only view of ONE project. Listing methods return fully paged results (the SDK follows ``next`` links)."""

    def negotiated_versions(self) -> NegotiatedVersions:
        """Compute and block-storage microversions the cloud supports and this client uses.

        Raises ``UnsupportedCloudError`` when compute is below 2.52 (tags)."""
        ...

    def project_id(self) -> str:
        """The project the credential is scoped to (compared with the project record by the credential test)."""
        ...

    def list_servers(
        self,
        *,
        changes_since: datetime | None = None,
        tags: Iterable[str] = (),
        tags_any: Iterable[str] = (),
        name: str | None = None,
    ) -> list[ServerInfo]:
        """Servers of the project with details. With ``changes_since``, deleted servers are returned too, with
        status ``DELETED`` (tombstones, SV section 1). ``name`` is matched exactly: Nova's filter is a regex, so
        implementations anchor it and re-check equality. Metadata is never a filter (silently ignored for
        non-admins, LAB-OBSERVED): there is deliberately no parameter for it."""
        ...

    def get_server(self, server_id: str) -> ServerInfo: ...

    def list_server_volume_attachments(self, server_id: str) -> list[VolumeAttachmentInfo]: ...

    def list_volumes(self) -> list[VolumeInfo]: ...

    def get_volume(self, volume_id: str) -> VolumeInfo: ...

    def list_volume_types(self) -> list[VolumeTypeInfo]:
        """Volume types visible to the project. A cloud may have no default type (LAB-OBSERVED): preflight must
        check ``is_default`` or require an explicit type."""
        ...

    def list_ports(self) -> list[PortInfo]: ...

    def list_floating_ips(self) -> list[FloatingIpInfo]: ...

    def list_networks(self) -> list[NetworkInfo]: ...

    def list_images(self) -> list[ImageInfo]: ...

    def list_flavors(self) -> list[FlavorInfo]: ...


@runtime_checkable
class WriteClient(ReadClient, Protocol):
    """The write side (E5-2). Steps receive ``write.GuardedWriteClient``, which implements this protocol with the
    ownership guard in front of every mutating call, over a backend (``sdk_write`` or the fake) whose transport
    enforces the write allowlist and the fence gate on every mutating request.

    Methods are idempotent where the cloud allows it (check, then act): a call whose goal is already reached
    sends nothing. Asynchronous operations return once the cloud accepted them; the step polls."""

    def create_server(self, spec: CreateServerSpec) -> ServerInfo:
        """Create with tags set atomically (compute >= 2.52). No client token exists: callers persist the
        intended name and run id first and look up by tag afterwards (ADR-0005). Returns as soon as Nova
        accepted the request (status ``BUILD``): record the id at once."""
        ...

    def delete_server(self, server_id: str) -> None:
        """Delete a registered, deletable server; a server already gone (404) is success."""
        ...

    def stop_server(self, server_id: str) -> None: ...

    def start_server(self, server_id: str) -> None: ...

    def lock_server(self, server_id: str, reason: str | None = None) -> None:
        """``reason`` is the ``locked_reason`` (mv >= 2.73); OVLM's always start with ``ovlm:``."""
        ...

    def unlock_server(self, server_id: str) -> None:
        """Unlock only a lock OVLM set (reason ``ovlm:*``); an admin lock answers 403."""
        ...

    def add_server_tag(self, server_id: str, tag: str) -> None:
        """Per-tag add (``PUT /servers/{id}/tags/{tag}``), never replace-all (claim_resources, SEC-R-24)."""
        ...

    def add_floating_ip_tag(self, floating_ip_id: str, tag: str) -> None:
        """Per-tag add on a Neutron floating IP (claim_resources)."""
        ...

    def merge_volume_metadata(self, volume_id: str, items: Mapping[str, str]) -> None:
        """Cinder metadata **merge** (``POST /volumes/{id}/metadata``), never replace-all (claim_resources)."""
        ...

    def attach_volume(self, server_id: str, volume_id: str) -> None:
        """Asynchronous: poll the volume (``reserved`` -> ``attaching`` -> ``in-use``)."""
        ...

    def detach_volume(self, server_id: str, volume_id: str) -> None:
        """Asynchronous: poll the volume (``detaching`` -> ``available``, or back to ``in-use`` on refusal)."""
        ...

    def update_floating_ip(
        self, floating_ip_id: str, port_id: str, fixed_ip_address: str | None = None
    ) -> FloatingIpInfo:
        """Associate the FIP with ``port_id`` (one atomic Neutron update; no disassociation form exists in OVLM).
        The misleading 404 raises ``FloatingIpNoRouterPathError``."""
        ...

    def get_console_output(self, server_id: str, length: int | None = None) -> str:
        """Nova offers the console log only as a POST action (``os-getConsoleOutput``): allowlisted here.
        May return ``""`` (LAB-OBSERVED)."""
        ...

    def get_floating_ip(self, floating_ip_id: str) -> FloatingIpInfo: ...

    def get_port(self, port_id: str) -> PortInfo: ...

    def get_server_fault(self, server_id: str) -> str | None:
        """``fault.message`` of a server in ``ERROR`` (e.g. ``No valid host was found``), else None."""
        ...

    def write_microversions(self) -> dict[str, str | None]:
        """Microversions the write calls pin, and what the cloud offers; recorded in step evidence."""
        ...

    def create_volume_snapshot(
        self, volume_id: str, name: str, metadata: Mapping[str, str]
    ) -> VolumeSnapshotInfo:
        """Cinder snapshot of an ``available`` volume (W4), never ``force``. Asynchronous: returns ``creating``;
        poll :meth:`get_volume_snapshot`. There is no snapshot delete anywhere in OVLM."""
        ...

    def list_volume_snapshots(self, *, name: str | None = None) -> list[VolumeSnapshotInfo]:
        """The project's snapshots; ``name`` matched exactly (re-checked client side)."""
        ...

    def get_volume_snapshot(self, snapshot_id: str) -> VolumeSnapshotInfo: ...

    def block_storage_limits(self) -> BlockStorageLimits:
        """Cinder absolute limits (snapshots, gigabytes): the B1 quota pre-check of W4 (SRE-R-7)."""
        ...
