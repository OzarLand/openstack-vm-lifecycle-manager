"""Ownership guard: checked before every mutating call (security-model.md section 4.3, ADR-0005 section 5).

Safety argument
---------------
Rule 1 (**authority**): the target id is registered for this run in OVLM's database: blue, the data volume and
the FIP from the approved plan (``origin="preexisting"``), or a server this run created (``origin="created"``).
The guard asks an :class:`OwnershipRegistry` on **every** call; implementations must read the database each time
(no cache), so a registration removed mid-run takes effect at the next call.

Rule 2 (**divergence check, not authority**): the resource, re-read from OpenStack immediately before the call,
carries the OVLM marker: tag ``ovlm:managed`` on servers and floating IPs, metadata ``ovlm.managed=true`` on
volumes, plus ``ovlm:run:<run>`` on servers this run created. Any project member can set these markers, so rule 2
never grants anything a missing rule 1 refuses (SEC-R-24): the guard checks rule 1 first and stops there.

Rule 3 (**delete**): only ``delete_server`` exists. The registration must say ``deletable`` (green on rollback, or
the approved retirement target), a created server must carry this run's tag, and the attachments, re-read just
before the call, must contain no registered volume and no attachment whose ``delete_on_termination`` is not
exactly ``False`` (unknown counts as unsafe). So deleting a server can never delete a volume OVLM knows of, nor
any volume at all through ``delete_on_termination``.

Claim exception (``claim_resources``, B2, security sign-off ruling (b)): adding the marker to a pre-existing
resource cannot require the marker, so claims check rule 1 only. They are limited to **adding** one ``ovlm:*``
tag or **merging** ``ovlm.*`` metadata keys; the allowlist refuses every replace-all and delete form, so a claim
cannot remove or change anything that was there before (and the client reads back to prove it).

There is no method to delete or create a volume or a floating IP anywhere in the write client, and the write
allowlist refuses those requests independently.
"""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from ovlm.openstack.allowlist import (
    TAG_MANAGED,
    TAG_RUN_PREFIX,
    VOLUME_MARKER_KEY,
    VOLUME_MARKER_VALUE,
)
from ovlm.openstack.errors import NotFoundError, OwnershipViolationError
from ovlm.openstack.types import FloatingIpInfo, ServerInfo, VolumeAttachmentInfo, VolumeInfo


class ResourceKind(enum.StrEnum):
    SERVER = "server"
    VOLUME = "volume"
    FLOATING_IP = "floating_ip"


Origin = Literal["preexisting", "created"]


@dataclass(frozen=True)
class Registration:
    """What OVLM's database says about one resource for the current run."""

    kind: ResourceKind
    openstack_id: str
    origin: Origin
    #: The run may delete it: green on operator rollback/discard, or blue as the approved retirement target.
    deletable: bool = False


@runtime_checkable
class OwnershipRegistry(Protocol):
    """The DB view the guard consults. E5-4 provides the DB-backed implementation (ledger, plan, managed VM).

    Implementations must read the database on every call (no cache) and must only answer for ``run_id``.

    A server is recorded with ``origin="created"`` (which, with ``deletable``, lets rule 3 delete it) only when
    this run created it from an ``intended`` ledger row, or when a server found by
    ``GuardedWriteClient.find_run_server`` passed :func:`ovlm.openstack.write.adopt_checks` (SEC-R-23, SEC-C-10);
    never on the strength of its tags alone."""

    @property
    def run_id(self) -> str: ...

    def lookup(self, kind: ResourceKind, openstack_id: str) -> Registration | None:
        """The registration of this resource for this run, or None."""
        ...

    def is_intended_server_name(self, name: str) -> bool:
        """True when the run's ledger holds an ``intended`` server row with exactly this name (ADR-0005 s.3)."""
        ...


class InMemoryOwnershipRegistry:
    """Test and fake-run implementation of :class:`OwnershipRegistry`."""

    def __init__(self, run_id: str) -> None:
        self._run_id = run_id
        self._regs: dict[tuple[ResourceKind, str], Registration] = {}
        self._intended: set[str] = set()
        self._lock = threading.Lock()

    @property
    def run_id(self) -> str:
        return self._run_id

    def register(
        self,
        kind: ResourceKind,
        openstack_id: str,
        *,
        origin: Origin = "preexisting",
        deletable: bool = False,
    ) -> None:
        with self._lock:
            self._regs[(kind, openstack_id)] = Registration(kind, openstack_id, origin, deletable)

    def unregister(self, kind: ResourceKind, openstack_id: str) -> None:
        with self._lock:
            self._regs.pop((kind, openstack_id), None)

    def intend_server(self, name: str) -> None:
        with self._lock:
            self._intended.add(name)

    def lookup(self, kind: ResourceKind, openstack_id: str) -> Registration | None:
        with self._lock:
            return self._regs.get((kind, openstack_id))

    def is_intended_server_name(self, name: str) -> bool:
        with self._lock:
            return name in self._intended


def run_tag(run_id: str) -> str:
    return f"{TAG_RUN_PREFIX}{run_id}"


def _violation(message: str, reason: str) -> OwnershipViolationError:
    return OwnershipViolationError(f"ownership_violation: {message}", reason=reason)


class OwnershipGuard:
    """Pure checks over a registry and freshly read OpenStack state. Raises :class:`OwnershipViolationError`."""

    def __init__(self, registry: OwnershipRegistry) -> None:
        self.registry = registry

    @property
    def run_id(self) -> str:
        return self.registry.run_id

    # rule 1 ------------------------------------------------------------------------------------------------

    def registration(self, kind: ResourceKind, openstack_id: str, operation: str) -> Registration:
        if not openstack_id:
            raise _violation(f"{operation}: empty {kind} id", "not_registered")
        reg = self.registry.lookup(kind, openstack_id)
        if reg is None or reg.kind != kind or reg.openstack_id != openstack_id:
            raise _violation(
                f"{operation}: {kind} {openstack_id} is not registered for run {self.run_id}",
                "not_registered",
            )
        return reg

    # rule 2 ------------------------------------------------------------------------------------------------

    def check_server_marker(self, reg: Registration, server: ServerInfo, operation: str) -> None:
        if server.is_minimal_construct or server.is_deleted:
            raise _violation(
                f"{operation}: server {server.openstack_id} state unverifiable", "unverifiable"
            )
        if TAG_MANAGED not in server.tags:
            raise _violation(
                f"{operation}: server {server.openstack_id} lacks {TAG_MANAGED}", "marker_missing"
            )
        if reg.origin == "created" and run_tag(self.run_id) not in server.tags:
            raise _violation(
                f"{operation}: server {server.openstack_id} lacks {run_tag(self.run_id)}",
                "marker_missing",
            )

    def check_volume_marker(self, volume: VolumeInfo, operation: str) -> None:
        if volume.metadata.get(VOLUME_MARKER_KEY) != VOLUME_MARKER_VALUE:
            raise _violation(
                f"{operation}: volume {volume.openstack_id} lacks {VOLUME_MARKER_KEY}={VOLUME_MARKER_VALUE}",
                "marker_missing",
            )

    def check_floating_ip_marker(self, fip: FloatingIpInfo, operation: str) -> None:
        if TAG_MANAGED not in fip.tags:
            raise _violation(
                f"{operation}: floating IP {fip.openstack_id} lacks {TAG_MANAGED}", "marker_missing"
            )

    # create / delete ---------------------------------------------------------------------------------------

    def check_create(self, name: str, tags: tuple[str, ...]) -> None:
        if not self.registry.is_intended_server_name(name):
            raise _violation(
                f"create_server: no intended ledger row named {name!r}", "not_registered"
            )
        missing = {TAG_MANAGED, run_tag(self.run_id)} - set(tags)
        if missing:
            raise _violation(
                f"create_server: tags {sorted(missing)} missing at create", "marker_missing"
            )

    def check_delete(
        self,
        reg: Registration,
        server: ServerInfo,
        attachments: list[VolumeAttachmentInfo],
    ) -> None:
        if not reg.deletable:
            raise _violation(
                f"delete_server: {server.openstack_id} is not deletable in this run",
                "not_deletable",
            )
        self.check_server_marker(reg, server, "delete_server")
        # Two sources (os-volume_attachments and the server view); a volume is safe only if every source that
        # lists it says delete_on_termination is exactly False.
        dots: dict[str, list[bool | None]] = {}
        for a in attachments:
            dots.setdefault(a.volume_openstack_id, []).append(a.delete_on_termination)
        for v in server.attached_volumes:
            dots.setdefault(v.volume_id, []).append(v.delete_on_termination)
        for volume_id, values in sorted(dots.items()):
            if self.registry.lookup(ResourceKind.VOLUME, volume_id) is not None:
                raise _violation(
                    f"delete_server: registered volume {volume_id} is attached to {server.openstack_id}",
                    "volume_attached",
                )
            if not all(d is False for d in values):
                raise _violation(
                    f"delete_server: volume {volume_id} delete_on_termination={values!r} (must be false)",
                    "delete_on_termination",
                )


def is_gone(exc: BaseException) -> bool:
    """A plain 404 (not the FIP no-router 404, which is a NotFoundError subclass with another meaning)."""
    return type(exc) is NotFoundError
