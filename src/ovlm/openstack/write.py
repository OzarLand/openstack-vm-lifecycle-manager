"""``GuardedWriteClient``: the only write client steps receive (E5-2).

Layers, each independent of the others (a call must pass all of them):

1. **Ownership guard** (``ownership``), here, before every mutating call: rule 1 (registered for this run in the
   DB), rule 2 (marker on the freshly read resource), rule 3 for deletes; claims check rule 1 only and can only
   add or merge ``ovlm`` markers.
2. **Write allowlist** and **fence gate**, in the backend's transport, on every mutating request: the session hook
   of ``sdk_write`` (``allowlist.install_write_guard``) or the equivalent check in the fake. This client binds the
   step's gate for the duration of each call (``GateBinding``); without a binding the transport refuses.
3. **Idempotency**: every method re-reads the target first and sends nothing when the goal is already reached;
   creates look up by run tag + exact name first and never create a second server.

A ``GuardedWriteClient`` is built per step attempt with that attempt's gate (``ctx.gate``) and the run's
:class:`~ovlm.openstack.ownership.OwnershipRegistry`. Reads pass straight through to the backend.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from typing import Any, Protocol, cast, runtime_checkable

from ovlm.openstack.allowlist import (
    LOCK_REASON_PREFIX,
    SNAPSHOT_NAME_PREFIX,
    TAG_MANAGED,
    VOLUME_MARKER_KEY,
    VOLUME_MARKER_VALUE,
    Gate,
    GateBinding,
)
from ovlm.openstack.errors import (
    DuplicateResourceError,
    ForeignLockError,
    ForeignMarkerLossError,
    MarkerLimitError,
    NotFoundError,
    NoValidHostError,
    OwnershipViolationError,
    ServerBuildFailedError,
    VolumeAlreadyAttachedError,
    WriteNotAllowedError,
)
from ovlm.openstack.interface import WriteClient
from ovlm.openstack.lookup import find_server_by_tag_and_name
from ovlm.openstack.ownership import (
    OwnershipGuard,
    OwnershipRegistry,
    ResourceKind,
    is_gone,
    run_tag,
)
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

#: Nova allows 50 tags per server (OSI section 2, SV); Neutron 50 per resource.
MAX_TAGS = 50


@runtime_checkable
class WriteBackend(WriteClient, Protocol):
    """A raw write client whose transport enforces the allowlist and calls the bound gate per mutating request."""

    @property
    def gate_binding(self) -> GateBinding: ...


def _gated[F: Callable[..., Any]](fn: F) -> F:
    @wraps(fn)
    def wrapper(self: GuardedWriteClient, *args: Any, **kwargs: Any) -> Any:
        with self._backend.gate_binding.bind(self._gate):
            return fn(self, *args, **kwargs)

    return cast(F, wrapper)


#: Metadata key carrying the run id on the W4 snapshot (with ``ovlm.managed=true``).
SNAPSHOT_RUN_KEY = "ovlm.run"


def snapshot_name(run_id: str) -> str:
    """The only snapshot name a run may create: ``ovlm-prehandoff-<run uuid>`` (W4)."""
    return f"{SNAPSHOT_NAME_PREFIX}{run_id}"


#: Kinds of lock OVLM sets on blue: ``ovlm:retained:<run>`` (after cut-over), ``ovlm:restored:<run>`` (rollback).
LOCK_REASON_KINDS = ("retained", "restored")


def own_lock_reasons(run_id: str) -> frozenset[str]:
    """The full lock reasons of one run. Any other reason, ``ovlm:``-prefixed or not, is a foreign lock: a project
    member can set any reason, so a prefix proves nothing (SEC-C-6)."""
    return frozenset(f"{LOCK_REASON_PREFIX}{kind}:{run_id}" for kind in LOCK_REASON_KINDS)


@dataclass(frozen=True)
class AdoptionExpectation:
    """What a server found by ``find_run_server`` must match to be adopted as this run's green (SEC-R-23).

    ``image_id`` and ``flavor_name`` are the plan's ``resolved`` values (Nova >= 2.47 shows a server's flavor by
    name only). ``ledger_committed_at`` is the commit time of the run's ``intended`` ledger row. ``write_user_id``
    is the Keystone user of OVLM's write credential; ``None`` only when the lab showed that a member cannot see
    ``user_id`` and the check was dropped and recorded (renewal-workflow.md B3)."""

    run_id: str
    image_id: str
    flavor_name: str
    ledger_committed_at: datetime
    write_user_id: str | None


@dataclass(frozen=True)
class AdoptionVerdict:
    reasons: tuple[str, ...]  # empty: adoption allowed

    @property
    def ok(self) -> bool:
        return not self.reasons


def adopt_checks(
    server: ServerInfo,
    expected: AdoptionExpectation,
    attachments: Iterable[VolumeAttachmentInfo] = (),
) -> AdoptionVerdict:
    """Pure adoption check of a server this run may have created (SEC-R-23, SEC-C-10).

    Every check must pass; any refusal means ``needs_human`` "adoption refused", never adopt. The step may record
    the server as ``origin="created"`` in the ownership registry only when this returns ``ok``. ``attachments``
    is the server's attachment list, read with it (both sources must show no volume)."""
    reasons: list[str] = []
    if server.is_minimal_construct or server.is_deleted:
        reasons.append("the server is not readable (deleted or minimal construct)")
    if TAG_MANAGED not in server.tags or run_tag(expected.run_id) not in server.tags:
        reasons.append("the server does not carry ovlm:managed and this run's tag")
    if server.image_id != expected.image_id:
        reasons.append(f"image {server.image_id!r} is not the resolved image {expected.image_id!r}")
    if server.flavor_original_name != expected.flavor_name:
        reasons.append(
            f"flavor {server.flavor_original_name!r} is not the resolved flavor {expected.flavor_name!r}"
        )
    if server.created is None or server.created < expected.ledger_committed_at:
        reasons.append("the server was created before this run's ledger row was committed")
    if server.attached_volumes or any(True for _ in attachments):
        reasons.append("the server has attached volumes")
    if expected.write_user_id is not None and server.user_id != expected.write_user_id:
        reasons.append(
            "the server was not created by OVLM's write user"
            if server.user_id
            else "the server's user_id is not visible"
        )
    return AdoptionVerdict(tuple(reasons))


class GuardedWriteClient:
    """``WriteClient`` with the ownership guard in front of a backend. See the module docstring."""

    def __init__(self, backend: WriteBackend, registry: OwnershipRegistry, gate: Gate) -> None:
        if gate is None or not callable(gate):
            raise WriteNotAllowedError("a write client needs the step attempt's fence gate")
        self._backend = backend
        self._guard = OwnershipGuard(registry)
        self._gate = gate

    @property
    def run_id(self) -> str:
        return self._guard.run_id

    # --- reads (pass through) ------------------------------------------------------------------------------

    def negotiated_versions(self) -> NegotiatedVersions:
        return self._backend.negotiated_versions()

    def write_microversions(self) -> dict[str, str | None]:
        return self._backend.write_microversions()

    def project_id(self) -> str:
        return self._backend.project_id()

    def list_servers(
        self,
        *,
        changes_since: datetime | None = None,
        tags: Iterable[str] = (),
        tags_any: Iterable[str] = (),
        name: str | None = None,
    ) -> list[ServerInfo]:
        return self._backend.list_servers(
            changes_since=changes_since, tags=tags, tags_any=tags_any, name=name
        )

    def get_server(self, server_id: str) -> ServerInfo:
        return self._backend.get_server(server_id)

    def list_server_volume_attachments(self, server_id: str) -> list[VolumeAttachmentInfo]:
        return self._backend.list_server_volume_attachments(server_id)

    def list_volumes(self) -> list[VolumeInfo]:
        return self._backend.list_volumes()

    def get_volume(self, volume_id: str) -> VolumeInfo:
        return self._backend.get_volume(volume_id)

    def list_volume_types(self) -> list[VolumeTypeInfo]:
        return self._backend.list_volume_types()

    def list_ports(self) -> list[PortInfo]:
        return self._backend.list_ports()

    def list_floating_ips(self) -> list[FloatingIpInfo]:
        return self._backend.list_floating_ips()

    def list_networks(self) -> list[NetworkInfo]:
        return self._backend.list_networks()

    def list_images(self) -> list[ImageInfo]:
        return self._backend.list_images()

    def list_flavors(self) -> list[FlavorInfo]:
        return self._backend.list_flavors()

    def get_floating_ip(self, floating_ip_id: str) -> FloatingIpInfo:
        return self._backend.get_floating_ip(floating_ip_id)

    def get_port(self, port_id: str) -> PortInfo:
        return self._backend.get_port(port_id)

    def get_server_fault(self, server_id: str) -> str | None:
        return self._backend.get_server_fault(server_id)

    def list_volume_snapshots(self, *, name: str | None = None) -> list[VolumeSnapshotInfo]:
        return self._backend.list_volume_snapshots(name=name)

    def get_volume_snapshot(self, snapshot_id: str) -> VolumeSnapshotInfo:
        return self._backend.get_volume_snapshot(snapshot_id)

    def block_storage_limits(self) -> BlockStorageLimits:
        return self._backend.block_storage_limits()

    # --- lookups and build state ---------------------------------------------------------------------------

    def find_run_server(self, name: str) -> ServerInfo | None:
        """The server this run created with ``name``: by ``ovlm:run:<run>`` tag + exact name (ADR-0005 s.4).
        More than one: :class:`DuplicateResourceError`. A match is only a candidate: the step adopts it (registers
        it ``origin="created"``) only when :func:`adopt_checks` passes (SEC-R-23)."""
        return find_server_by_tag_and_name(self._backend, tag=run_tag(self.run_id), name=name)

    def build_state(self, server_id: str) -> ServerInfo | None:
        """``ACTIVE`` -> the server; still building -> None; ``ERROR`` -> :class:`ServerBuildFailedError`
        (:class:`NoValidHostError` when the fault says so), with ``fault.message`` in the error text (B4)."""
        server = self._backend.get_server(server_id)
        if server.status == "ERROR":
            fault = self._backend.get_server_fault(server_id) or ""
            cls = NoValidHostError if "no valid host" in fault.lower() else ServerBuildFailedError
            raise cls(f"server {server_id} is in ERROR: {fault or 'no fault message'}")
        if server.status == "ACTIVE" and server.task_state is None:
            return server
        return None

    # --- helpers -------------------------------------------------------------------------------------------

    def _owned_server(self, server_id: str, operation: str) -> ServerInfo:
        reg = self._guard.registration(ResourceKind.SERVER, server_id, operation)
        server = self._backend.get_server(server_id)
        self._guard.check_server_marker(reg, server, operation)
        return server

    def _owned_volume(self, volume_id: str, operation: str) -> VolumeInfo:
        self._guard.registration(ResourceKind.VOLUME, volume_id, operation)
        volume = self._backend.get_volume(volume_id)
        self._guard.check_volume_marker(volume, operation)
        return volume

    # --- create / delete -----------------------------------------------------------------------------------

    @_gated
    def create_server(self, spec: CreateServerSpec) -> ServerInfo:
        self._guard.check_create(spec.name, spec.tags)
        existing = self.find_run_server(spec.name)
        if (
            existing is not None
        ):  # the step must adopt (with SEC-R-23 checks) instead of creating again
            raise DuplicateResourceError(
                f"create_server: {existing.openstack_id} already has this run's tag and name {spec.name!r}",
                matches=(existing.openstack_id,),
            )
        return self._backend.create_server(spec)

    @_gated
    def delete_server(self, server_id: str) -> None:
        reg = self._guard.registration(ResourceKind.SERVER, server_id, "delete_server")
        try:
            server = self._backend.get_server(server_id)
            attachments = self._backend.list_server_volume_attachments(server_id)
        except NotFoundError as exc:
            if is_gone(exc):
                return  # already deleted
            raise
        self._guard.check_delete(reg, server, attachments)  # re-read immediately before the call
        try:
            self._backend.delete_server(server_id)
        except NotFoundError as exc:
            if not is_gone(exc):
                raise

    # --- power and lock ------------------------------------------------------------------------------------

    @_gated
    def stop_server(self, server_id: str) -> None:
        server = self._owned_server(server_id, "stop_server")
        if server.status == "SHUTOFF" and server.task_state is None:
            return
        self._backend.stop_server(server_id)

    @_gated
    def start_server(self, server_id: str) -> None:
        server = self._owned_server(server_id, "start_server")
        if server.status == "ACTIVE" and server.task_state is None:
            return
        self._backend.start_server(server_id)

    def own_lock_reasons(self) -> frozenset[str]:
        """The only lock reasons this run sets and recognises as its own (SEC-C-6)."""
        return own_lock_reasons(self.run_id)

    def _foreign_lock(self, server_id: str, server: ServerInfo) -> ForeignLockError:
        return ForeignLockError(
            f"server {server_id} is locked with reason {server.locked_reason!r}, not one of this run's",
            locked_reason=server.locked_reason,
        )

    @_gated
    def lock_server(self, server_id: str, reason: str | None = None) -> None:
        if reason not in self.own_lock_reasons():
            raise WriteNotAllowedError(
                f"lock_server: the reason must be one of this run's ({sorted(self.own_lock_reasons())})"
            )
        server = self._owned_server(server_id, "lock_server")
        if server.locked:
            if server.locked_reason == reason:
                return
            if server.locked_reason not in self.own_lock_reasons():
                raise self._foreign_lock(server_id, server)
        self._backend.lock_server(server_id, reason)

    @_gated
    def unlock_server(self, server_id: str) -> None:
        server = self._owned_server(server_id, "unlock_server")
        if not server.locked:
            return
        if server.locked_reason not in self.own_lock_reasons():
            raise self._foreign_lock(server_id, server)
        self._backend.unlock_server(server_id)

    # --- claim_resources: add / merge only (rule 1 only, see ownership.py) ---------------------------------

    @staticmethod
    def _claim_tag_ok(tag: str) -> None:
        if not tag.startswith("ovlm:") or len(tag) > 60 or "," in tag or "/" in tag:
            raise WriteNotAllowedError(f"claim: only valid ovlm:* tags may be added, got {tag!r}")

    @_gated
    def add_server_tag(self, server_id: str, tag: str) -> None:
        self._claim_tag_ok(tag)
        self._guard.registration(ResourceKind.SERVER, server_id, "add_server_tag")
        before = self._backend.get_server(server_id)
        if before.is_minimal_construct or before.is_deleted:
            raise NotFoundError(f"server {server_id} is not readable", status=404)
        if tag in before.tags:
            return
        if len(before.tags) >= MAX_TAGS:
            raise MarkerLimitError(
                f"server {server_id} already has {len(before.tags)} tags (limit {MAX_TAGS})"
            )
        self._backend.add_server_tag(server_id, tag)
        after = self._backend.get_server(server_id)
        lost = set(before.tags) - set(after.tags)
        if lost or tag not in after.tags:
            raise ForeignMarkerLossError(
                f"server {server_id}: tags {sorted(lost)} lost, or {tag} missing"
            )

    @_gated
    def add_floating_ip_tag(self, floating_ip_id: str, tag: str) -> None:
        self._claim_tag_ok(tag)
        self._guard.registration(ResourceKind.FLOATING_IP, floating_ip_id, "add_floating_ip_tag")
        before = self._backend.get_floating_ip(floating_ip_id)
        if tag in before.tags:
            return
        if len(before.tags) >= MAX_TAGS:
            raise MarkerLimitError(
                f"floating IP {floating_ip_id} already has {len(before.tags)} tags"
            )
        self._backend.add_floating_ip_tag(floating_ip_id, tag)
        after = self._backend.get_floating_ip(floating_ip_id)
        lost = set(before.tags) - set(after.tags)
        if lost or tag not in after.tags:
            raise ForeignMarkerLossError(f"floating IP {floating_ip_id}: tags {sorted(lost)} lost")

    @_gated
    def merge_volume_metadata(self, volume_id: str, items: Mapping[str, str]) -> None:
        items = dict(items)
        if not items or not all(k.startswith("ovlm.") for k in items):
            raise WriteNotAllowedError("claim: only ovlm.* volume metadata keys may be merged")
        self._guard.registration(ResourceKind.VOLUME, volume_id, "merge_volume_metadata")
        before = self._backend.get_volume(volume_id).metadata
        if all(before.get(k) == v for k, v in items.items()):
            return
        self._backend.merge_volume_metadata(volume_id, items)
        after = self._backend.get_volume(volume_id).metadata
        foreign_changed = sorted(
            k for k, v in before.items() if k not in items and after.get(k) != v
        )
        if foreign_changed or any(after.get(k) != v for k, v in items.items()):
            raise ForeignMarkerLossError(
                f"volume {volume_id}: keys {foreign_changed} changed by the merge"
            )

    # --- volume handoff ------------------------------------------------------------------------------------

    @staticmethod
    def _attached_to(volume: VolumeInfo, server_id: str) -> bool:
        return any(a.server_openstack_id == server_id for a in volume.attachments)

    @_gated
    def attach_volume(self, server_id: str, volume_id: str) -> None:
        self._owned_server(server_id, "attach_volume")
        volume = self._owned_volume(volume_id, "attach_volume")
        if self._attached_to(volume, server_id) and volume.status == "in-use":
            return
        try:
            self._backend.attach_volume(server_id, volume_id)
        except VolumeAlreadyAttachedError:
            if self._attached_to(self._backend.get_volume(volume_id), server_id):
                return  # "already attached to the target server" is success (OSI s.3)
            raise

    @_gated
    def detach_volume(self, server_id: str, volume_id: str) -> None:
        server = self._owned_server(server_id, "detach_volume")
        volume = self._owned_volume(volume_id, "detach_volume")
        listed = any(v.volume_id == volume_id for v in server.attached_volumes)
        if not self._attached_to(volume, server_id) and not listed:
            return
        if volume.status == "detaching":
            return  # in progress: the step polls
        try:
            self._backend.detach_volume(server_id, volume_id)
        except NotFoundError as exc:
            if not is_gone(exc):
                raise

    # --- W4 pre-handoff snapshot (create only; OVLM has no snapshot delete) ----------------------------------

    @_gated
    def create_volume_snapshot(
        self, volume_id: str, name: str, metadata: Mapping[str, str] | None = None
    ) -> VolumeSnapshotInfo:
        """Snapshot the registered data volume while it is ``available`` (detached) under this run's one name.

        Rule 1 and 2 on the volume; the name must be exactly :func:`snapshot_name` of this run; a snapshot with
        that name already present is never duplicated (:class:`DuplicateResourceError`: the step adopts it after
        its own checks). The metadata is OVLM's marker and run id only. A snapshot cannot change the volume."""
        if name != snapshot_name(self.run_id):
            raise WriteNotAllowedError(
                f"create_volume_snapshot: the name must be {snapshot_name(self.run_id)!r}"
            )
        if metadata and any(not k.startswith("ovlm.") for k in metadata):
            raise WriteNotAllowedError("create_volume_snapshot: only ovlm.* metadata")
        volume = self._owned_volume(volume_id, "create_volume_snapshot")
        if volume.status != "available" or volume.attachments:
            raise WriteNotAllowedError(
                f"create_volume_snapshot: volume {volume_id} is {volume.status}, not available and detached"
            )
        existing = self._backend.list_volume_snapshots(name=name)
        if existing:
            raise DuplicateResourceError(
                f"create_volume_snapshot: {len(existing)} snapshot(s) named {name!r} already exist",
                matches=tuple(x.openstack_id for x in existing),
            )
        md = {
            **dict(metadata or {}),
            VOLUME_MARKER_KEY: VOLUME_MARKER_VALUE,
            SNAPSHOT_RUN_KEY: self.run_id,
        }
        return self._backend.create_volume_snapshot(volume_id, name, md)

    # --- cutover -------------------------------------------------------------------------------------------

    @_gated
    def update_floating_ip(
        self, floating_ip_id: str, port_id: str, fixed_ip_address: str | None = None
    ) -> FloatingIpInfo:
        if not port_id:
            raise WriteNotAllowedError("update_floating_ip: OVLM never disassociates a floating IP")
        self._guard.registration(ResourceKind.FLOATING_IP, floating_ip_id, "update_floating_ip")
        fip = self._backend.get_floating_ip(floating_ip_id)
        self._guard.check_floating_ip_marker(fip, "update_floating_ip")
        port = self._backend.get_port(port_id)
        if not port.device_id:
            raise self._port_violation(port_id, "is not bound to a server")
        self._owned_server(
            port.device_id, "update_floating_ip"
        )  # the port belongs to blue or green
        if fip.port_id == port_id and (
            fixed_ip_address is None or fip.fixed_ip_address == fixed_ip_address
        ):
            return fip
        return self._backend.update_floating_ip(floating_ip_id, port_id, fixed_ip_address)

    @staticmethod
    def _port_violation(port_id: str, why: str) -> Exception:
        return OwnershipViolationError(
            f"ownership_violation: port {port_id} {why}", reason="port_not_owned"
        )

    # --- console (POST, but not a mutation) ----------------------------------------------------------------

    @_gated
    def get_console_output(self, server_id: str, length: int | None = None) -> str:
        self._guard.registration(ResourceKind.SERVER, server_id, "get_console_output")
        return self._backend.get_console_output(server_id, length)


__all__ = ["MAX_TAGS", "TAG_MANAGED", "GuardedWriteClient", "WriteBackend"]
