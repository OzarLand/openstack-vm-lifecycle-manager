"""The adapter interface, in OVLM's vocabulary (architecture.md section 3, testing-strategy.md section 3.2).

``ReadClient`` is what inventory, readiness and planning use: it can only read (GET/HEAD) and is enforced twice,
by this interface having no write methods and by the request hook in ``guard`` (SEC-R-5).

``WriteClient`` is a **stub** until E5-2 (ownership guard, write allowlist, fence gate, error mapping). The
method set below is what the renewal strategy needs (renewal-workflow.md, openstack-integration.md sections 3,
4, 6, 7); E5-2 may refine signatures. It is deliberately not implemented by the SDK client yet.

Both are structural ``Protocol`` types; ``fake.FakeOpenStack`` implements both.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Protocol, runtime_checkable

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
    """STUB (E5-2 implements it). Worker process and an active step context only; every call passes the fence
    gate and the (method, path) allowlist. Methods are idempotent where the cloud allows it (check, then act)."""

    def create_server(self, spec: CreateServerSpec) -> ServerInfo:
        """Create with tags set atomically (compute >= 2.52). No client token exists: callers persist the
        intended name and run id first and look up by tag afterwards (ADR-0005)."""
        ...

    def delete_server(self, server_id: str) -> None: ...

    def stop_server(self, server_id: str) -> None: ...

    def start_server(self, server_id: str) -> None: ...

    def lock_server(self, server_id: str, reason: str | None = None) -> None: ...

    def unlock_server(self, server_id: str) -> None: ...

    def add_server_tag(self, server_id: str, tag: str) -> None: ...

    def attach_volume(self, server_id: str, volume_id: str) -> None:
        """Asynchronous: poll the volume (``reserved`` -> ``attaching`` -> ``in-use``)."""
        ...

    def detach_volume(self, server_id: str, volume_id: str) -> None:
        """Asynchronous: poll the volume (``detaching`` -> ``available``, or back to ``in-use`` on refusal)."""
        ...

    def update_floating_ip(self, floating_ip_id: str, port_id: str | None) -> FloatingIpInfo:
        """Associate (or, with ``None``, disassociate). The misleading 404 raises
        ``FloatingIpNoRouterPathError``."""
        ...

    def get_console_output(self, server_id: str, length: int | None = None) -> str:
        """Nova offers the console log only as a POST action (``os-getConsoleOutput``): it cannot pass the
        read-only hook, so it lives here and E5-2 must allowlist it. May return ``""`` (LAB-OBSERVED)."""
        ...
