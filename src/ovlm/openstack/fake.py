"""Hand-written in-memory fake of OpenStack behind OVLM's adapter interface (testing-strategy.md section 3).

Implements ``ReadClient`` and ``WriteClient``. It is a state machine driven by an explicit clock:
asynchronous things (volume attach and detach, stop and start, server build, floating IP status) advance only
when a test calls ``tick(seconds)``, so tests control timing and can stop mid-transition.

Modelled behaviours and their source tags (openstack-integration.md, "OSI"; EXP-01 = lab, Felcloud 2026-11-04).
Every behaviour is **UNCONFIRMED** against the SDK client until a contract run on a real cloud exists, except
where the lab tag says otherwise:

| Behaviour | Source |
|---|---|
| Volume attach ``available -> reserved -> attaching -> in-use``; detach ``in-use -> detaching -> available``; a refused detach rolls back to ``in-use`` after the timeout; attach failure leaves ``attaching`` with attachment ``error_attaching`` | OSI s.4 (SV); states LAB-OBSERVED (EXP-01 Q3) |
| Attach of a volume that is not ``available``: 400 | OSI s.4 (SV); LAB-OBSERVED ("already attached") |
| Locked server refuses stop, start, attach, detach, delete: 409 ``Instance is locked``; the owner can unlock; an admin lock cannot be unlocked by a non-admin | OSI s.7 (SV); LAB-OBSERVED (EXP-01 Q6) |
| ``list_servers(metadata=...)`` is **ignored for non-admins** and returns every server; tag filters work | OSI s.1, s.2 (SV); LAB-OBSERVED (EXP-01 Q5) |
| Server names are not unique | OSI s.3 (SV) |
| ``changes_since`` listing includes deleted servers (tombstones); a plain listing does not | OSI s.1 (SV) |
| Minimal construct (status ``UNKNOWN``, few fields) for a server in an unreachable cell | OSI s.1 (DU) |
| Floating IP update without a router path: **404** ``External network ... is not reachable from subnet ...`` | OSI s.6.1 (SV) |
| Floating IP whose target port already has one on that network: 409 | OSI s.6.1 (SV) |
| Empty floating IP pool: 400 ``Unable to find any IP address on external network`` although the quota is free | LAB-OBSERVED (EXP-01) |
| No default volume type: ``create_volume`` without a type is a 500 (``__DEFAULT__`` not found) | LAB-OBSERVED (EXP-01) |
| Console output may be empty (HTTP 200, ``""``) | LAB-OBSERVED (EXP-01b) |
| Tags at create need compute >= 2.52; a ``reader`` credential cannot mutate (403) | OSI s.2, s.8 (SV) |
| At most 50 tags per server / floating IP: 400 beyond | OSI s.2 (SV) |
| Cinder metadata ``POST`` merges (keys not in the request stay) | AS (verb semantics, SEC-R-24: lab with foreign metadata) |
| Server in ``ERROR`` exposes ``fault.message`` (e.g. ``No valid host was found.``) | OSI s.7 (SV) |

Write boundary (E5-2): every operation in ``allowlist.WRITE_OPERATIONS`` calls the fence gate bound on
``gate_binding`` **before** it touches state, like the SDK session hook does before sending. With no gate bound the
call proceeds unless ``strict_gate`` is set (direct fake tests); ``GuardedWriteClient`` always binds one. Fault
rules (``fail``) apply after the gate, so a refused gate never consumes an injected fault.

Extensions beyond the Protocols (cloud-side operations OVLM itself never performs, needed to model the cloud):
``list_servers(metadata=...)``, ``create_volume``, ``allocate_floating_ip``.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from ovlm.openstack.allowlist import WRITE_OPERATIONS, GateBinding
from ovlm.openstack.errors import (
    BadRequestError,
    ConflictError,
    FloatingIpNoRouterPathError,
    FloatingIpPortAlreadyAssociatedError,
    ForbiddenError,
    InstanceLockedError,
    NoFloatingIpAvailableError,
    NotFoundError,
    OpenStackError,
    QuotaExceededError,
    ServerError,
    UnsupportedCloudError,
    VolumeAlreadyAttachedError,
    WriteNotAllowedError,
)
from ovlm.openstack.types import (
    COMPUTE_TAGS_AT_CREATE,
    STATUS_DELETED,
    STATUS_UNKNOWN,
    AttachedVolume,
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

Role = Literal["reader", "member", "admin"]
_MUTATING = frozenset(
    {
        "create_server", "delete_server", "stop_server", "start_server", "lock_server", "unlock_server",
        "add_server_tag", "attach_volume", "detach_volume", "update_floating_ip", "get_console_output",
        "add_floating_ip_tag", "merge_volume_metadata", "create_volume", "allocate_floating_ip",
    }
)  # fmt: skip
_ATTACHABLE_VM_STATES = frozenset(
    {"active", "paused", "stopped", "resized", "soft-delete", "shelved"}
)
_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass
class _Server:
    id: str
    name: str
    status: str = "ACTIVE"
    vm_state: str = "active"
    task_state: str | None = None
    power_state: int = 1
    created: datetime = _EPOCH
    launched_at: datetime | None = _EPOCH
    updated: datetime = _EPOCH
    flavor_name: str = "m1.small"
    image_id: str | None = "img-1"
    availability_zone: str = "az1"
    locked: bool = False
    locked_by: str = "owner"
    locked_reason: str | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    host_id: str = "hash-1"
    attached: dict[str, bool] = field(default_factory=dict)  # volume id -> delete_on_termination
    minimal: bool = False
    deleted: bool = False
    host_down: bool = False
    guest_refuses_detach: bool = False
    console: str = ""
    fault: str | None = None


@dataclass
class _Attachment:
    server_id: str
    device: str
    attachment_id: str
    attach_status: str  # reserved, attaching, attached, error_attaching


@dataclass
class _Volume:
    id: str
    name: str
    status: str = "available"
    size: int = 1
    bootable: bool = False
    multiattach: bool = False
    availability_zone: str = "az1"
    volume_type: str | None = "ssd"
    metadata: dict[str, str] = field(default_factory=dict)
    attachments: dict[str, _Attachment] = field(default_factory=dict)  # by server id
    attach_fails: bool = False


@dataclass
class _Rule:
    op: str
    error: Exception
    when: Literal["before", "after_apply"]
    nth: int
    times: int
    fired: int = 0


class FakeOpenStack:
    """In-memory cloud for one project. See the module docstring for what it models."""

    # Simulated durations in seconds (EXP-01b order of magnitude); tests may overwrite them.
    reserve_delay = 1.0
    attach_delay = 5.0
    detach_delay = 4.0
    detach_refusal_timeout = 160.0
    stop_delay = 12.0
    start_delay = 12.0
    build_delay = 30.0
    fip_status_delay = 1.0

    def __init__(
        self,
        *,
        project_id: str = "00000000-0000-0000-0000-00000000f001",
        role: Role = "member",
        compute_max: tuple[int, int] = (2, 100),
        block_storage_max: tuple[int, int] = (3, 71),
        now: datetime | None = None,
    ) -> None:
        self._project_id = project_id
        self.role: Role = role
        self.compute_max = compute_max
        self.block_storage_max = block_storage_max
        self.now = now or _EPOCH
        self.keep_tombstones = True
        self.quota_instances: int | None = None
        self.default_volume_type: str | None = (
            None  # None: the cloud has no default type (LAB-OBSERVED)
        )
        self.force_no_valid_host = False
        self.calls: list[str] = []
        #: Fence gate binding (see the module docstring); ``strict_gate`` refuses writes with no gate bound.
        self.gate_binding = GateBinding()
        self.strict_gate = False
        self._servers: dict[str, _Server] = {}
        self._volumes: dict[str, _Volume] = {}
        self._volume_types: dict[str, str] = {}
        self._ports: dict[str, PortInfo] = {}
        self._fips: dict[str, FloatingIpInfo] = {}
        self._networks: dict[str, NetworkInfo] = {}
        self._images: dict[str, ImageInfo] = {}
        self._flavors: dict[str, FlavorInfo] = {}
        self._router_paths: set[tuple[str, str]] = set()  # (port network id, external network id)
        self._fip_pool_free: dict[str, int] = {}
        self._events: list[tuple[datetime, int, Callable[[], None]]] = []
        self._seq = 0
        self._ids = 0
        self._rules: list[_Rule] = []
        self._counts: Counter[str] = Counter()
        self._hidden: set[str] = set()

    # --- clock ---------------------------------------------------------------------------------------------

    def tick(self, seconds: float) -> None:
        """Advance the clock; run every scheduled transition that falls due, in time order."""
        target = self.now + timedelta(seconds=seconds)
        while self._events and min(self._events)[0] <= target:
            self._events.sort(key=lambda e: (e[0], e[1]))
            due, _, fn = self._events.pop(0)
            self.now = max(self.now, due)
            fn()
        self.now = target

    def _later(self, seconds: float, fn: Callable[[], None]) -> None:
        self._seq += 1
        self._events.append((self.now + timedelta(seconds=seconds), self._seq, fn))

    def _new_id(self) -> str:
        self._ids += 1
        return str(uuid.UUID(int=self._ids))

    # --- fault injection (testing-strategy.md section 3.4) -------------------------------------------------

    def fail(
        self,
        op: str,
        error: Exception | None = None,
        *,
        when: Literal["before", "after_apply"] = "before",
        nth: int = 1,
        times: int = 1,
    ) -> None:
        """Make the ``nth`` call of ``op`` raise ``error`` (``times`` times). ``after_apply``: the cloud applied
        the change but the response is lost (the key idempotency case: a create succeeded, the id is unknown)."""
        self._rules.append(
            _Rule(op, error or OpenStackError(f"injected failure of {op}"), when, nth, times)
        )

    @contextmanager
    def _call(self, op: str) -> Iterator[None]:
        if (
            op in WRITE_OPERATIONS
        ):  # the transport boundary: allowlisted op, gate before anything happens
            if self.gate_binding.bound:
                self.gate_binding.check(op)
            elif self.strict_gate:
                raise WriteNotAllowedError(f"refused {op}: no fence gate bound")
        self.calls.append(op)
        self._counts[op] += 1
        if op in _MUTATING and self.role == "reader":
            raise ForbiddenError(f"policy does not allow {op} for role reader", status=403)
        rule = next(
            (
                r
                for r in self._rules
                if r.op == op and self._counts[op] >= r.nth and r.fired < r.times
            ),
            None,
        )
        if rule and rule.when == "before":
            rule.fired += 1
            raise rule.error
        yield
        if rule and rule.when == "after_apply":
            rule.fired += 1
            raise rule.error

    # --- test helpers (build the cloud) --------------------------------------------------------------------

    def add_image(self, name: str = "ubuntu", *, visibility: str = "public") -> str:
        i = self._new_id()
        self._images[i] = ImageInfo(i, name, "active", visibility, self._project_id)
        return i

    def add_flavor(
        self, name: str = "m1.small", *, vcpus: int = 1, ram: int = 1024, disk: int = 10
    ) -> str:
        i = self._new_id()
        self._flavors[i] = FlavorInfo(i, name, vcpus, ram, disk, 0, True)
        return i

    def add_network(
        self, name: str = "net", *, external: bool = False, shared: bool = False
    ) -> str:
        i = self._new_id()
        self._networks[i] = NetworkInfo(i, name, "ACTIVE", external, shared, ())
        return i

    def add_volume_type(self, name: str, *, default: bool = False) -> str:
        i = self._new_id()
        self._volume_types[i] = name
        if default:
            self.default_volume_type = name
        return i

    def add_port(
        self,
        network_id: str,
        *,
        device_id: str | None = None,
        ip: str = "10.0.0.5",
        subnet: str = "sub-1",
    ) -> str:
        i = self._new_id()
        self._ports[i] = PortInfo(
            i, "", network_id, device_id, "compute:az1" if device_id else None,
            ((ip, subnet),), "fa:16:3e:00:00:01", (), "ACTIVE",
        )  # fmt: skip
        return i

    def add_floating_ip(
        self, external_network_id: str, *, address: str = "192.0.2.10", tags: Iterable[str] = ()
    ) -> str:
        i = self._new_id()
        self._fips[i] = FloatingIpInfo(
            i, address, None, None, None, external_network_id, "DOWN", tuple(tags)
        )
        return i

    def add_router_path(self, network_id: str, external_network_id: str) -> None:
        """A router joins ``network_id`` and ``external_network_id``: associations on that path succeed."""
        self._router_paths.add((network_id, external_network_id))

    def set_floating_ip_pool(self, external_network_id: str, free: int) -> None:
        self._fip_pool_free[external_network_id] = free

    def add_server(
        self,
        name: str = "vm",
        *,
        status: str = "ACTIVE",
        tags: Iterable[str] = (),
        metadata: dict[str, str] | None = None,
        image_id: str | None = "img-1",
        flavor: str = "m1.small",
        locked: bool = False,
        locked_by: str = "owner",
        minimal: bool = False,
        host_down: bool = False,
        guest_refuses_detach: bool = False,
        launched: bool = True,
    ) -> str:
        sid = self._new_id()
        vm_state, power = {
            "ACTIVE": ("active", 1), "SHUTOFF": ("stopped", 4), "BUILD": ("building", 0),
            "ERROR": ("error", 0), STATUS_UNKNOWN: ("active", 1),
        }[status]  # fmt: skip
        self._servers[sid] = _Server(
            id=sid, name=name, status=status, vm_state=vm_state, power_state=power,
            created=self.now, launched_at=self.now if launched and status != "BUILD" else None,
            updated=self.now, flavor_name=flavor, image_id=image_id, locked=locked, locked_by=locked_by,
            tags=list(tags), metadata=dict(metadata or {}), minimal=minimal or status == STATUS_UNKNOWN,
            host_down=host_down, guest_refuses_detach=guest_refuses_detach,
        )  # fmt: skip
        return sid

    def add_volume(
        self,
        name: str = "vol",
        *,
        size: int = 1,
        status: str = "available",
        volume_type: str | None = "ssd",
        attach_fails: bool = False,
        multiattach: bool = False,
        metadata: dict[str, str] | None = None,
    ) -> str:
        vid = self._new_id()
        self._volumes[vid] = _Volume(
            vid,
            name,
            status,
            size,
            volume_type=volume_type,
            attach_fails=attach_fails,
            multiattach=multiattach,
            metadata=dict(metadata or {}),
        )
        return vid

    def set_host_down(self, server_id: str, down: bool = True) -> None:
        self._server_raw(server_id).host_down = down

    def set_console(self, server_id: str, text: str) -> None:
        self._server_raw(server_id).console = text

    def touch_server(self, server_id: str, **changes: object) -> None:
        """Change a server out of band (another user did it) and bump ``updated``."""
        s = self._server_raw(server_id)
        for k, v in changes.items():
            setattr(s, k, v)
        s.updated = self.now

    def hide_server(self, server_id: str, hidden: bool = True) -> None:
        """A listing omits the server (a partial listing, a cell hiccup) without a tombstone or a minimal
        construct. Not a documented Nova behaviour: used to test ``gone`` marking and reappearance."""
        (self._hidden.add if hidden else self._hidden.discard)(server_id)

    def remove_volume(self, volume_id: str) -> None:
        """Remove a volume without trace (Cinder has no tombstones)."""
        self._volumes.pop(volume_id)

    def purge_tombstones(self) -> None:
        """The operator's archive/purge job ran: deleted servers are no longer listed by ``changes_since``."""
        self._servers = {k: s for k, s in self._servers.items() if not s.deleted}

    def admin_reset(self, volume_id: str, status: str = "available") -> None:
        """An admin fixed a stuck volume (reset-state, force-detach)."""
        v = self._volumes[volume_id]
        v.status = status
        if status == "available":
            for sid in list(v.attachments):
                self._server_raw(sid).attached.pop(volume_id, None)
            v.attachments.clear()

    def snapshot(self) -> dict[str, dict[str, object]]:
        """Plain-data view for invariant checks."""
        return {
            "servers": {
                s.id: {
                    "status": s.status,
                    "locked": s.locked,
                    "volumes": sorted(s.attached),
                    "tags": sorted(s.tags),
                }
                for s in self._servers.values()
            },
            "volumes": {
                v.id: {"status": v.status, "attached_to": sorted(v.attachments)}
                for v in self._volumes.values()
            },
            "floating_ips": {f.openstack_id: f.port_id for f in self._fips.values()},
        }

    # --- lookups ---------------------------------------------------------------------------------------------

    def _server_raw(self, server_id: str) -> _Server:
        s = self._servers.get(server_id)
        if s is None:
            raise NotFoundError(f"Instance {server_id} could not be found.", status=404)
        return s

    def _live_server(self, server_id: str) -> _Server:
        s = self._server_raw(server_id)
        if s.deleted:
            raise NotFoundError(f"Instance {server_id} could not be found.", status=404)
        return s

    def _volume_raw(self, volume_id: str) -> _Volume:
        v = self._volumes.get(volume_id)
        if v is None:
            raise NotFoundError(f"Volume {volume_id} could not be found.", status=404)
        return v

    # --- conversion ------------------------------------------------------------------------------------------

    def _server_info(self, s: _Server) -> ServerInfo:
        if s.minimal:  # compute 2.69: minimal construct of an unreachable cell
            return ServerInfo(
                openstack_id=s.id,
                name=None,
                status=STATUS_UNKNOWN,
                created=s.created,
                is_minimal_construct=True,
            )
        if s.deleted:
            return ServerInfo(
                openstack_id=s.id,
                name=s.name,
                status=STATUS_DELETED,
                updated=s.updated,
                created=s.created,
            )
        flavor = next((f for f in self._flavors.values() if f.name == s.flavor_name), None)
        return ServerInfo(
            openstack_id=s.id, name=s.name, status=s.status, vm_state=s.vm_state, task_state=s.task_state,
            power_state=s.power_state, created=s.created, launched_at=s.launched_at, updated=s.updated,
            flavor_original_name=s.flavor_name, flavor_vcpus=flavor.vcpus if flavor else 1,
            flavor_ram=flavor.ram if flavor else 1024, flavor_disk=flavor.disk if flavor else 10,
            image_id=s.image_id, availability_zone=s.availability_zone, locked=s.locked,
            locked_reason=s.locked_reason, tags=tuple(s.tags), metadata=dict(s.metadata), host_id=s.host_id,
            attached_volumes=tuple(AttachedVolume(v, d) for v, d in sorted(s.attached.items())),
        )  # fmt: skip

    def _volume_info(self, v: _Volume) -> VolumeInfo:
        return VolumeInfo(
            openstack_id=v.id, name=v.name, status=v.status, size=v.size, bootable=v.bootable,
            multiattach=v.multiattach, availability_zone=v.availability_zone, volume_type=v.volume_type,
            metadata=dict(v.metadata),
            attachments=tuple(
                VolumeAttachmentInfo(a.server_id, v.id, a.device, a.attachment_id,
                                     self._servers[a.server_id].attached.get(v.id))
                for a in v.attachments.values()
            ),
        )  # fmt: skip

    # --- ReadClient ------------------------------------------------------------------------------------------

    def negotiated_versions(self) -> NegotiatedVersions:
        if self.compute_max < COMPUTE_TAGS_AT_CREATE:
            raise UnsupportedCloudError(
                f"compute microversion {self.compute_max[0]}.{self.compute_max[1]} is below 2.52 (server tags)"
            )
        return NegotiatedVersions(
            self.compute_max, min(self.compute_max, (2, 100)),
            self.block_storage_max, min(self.block_storage_max, (3, 71)),
        )  # fmt: skip

    def project_id(self) -> str:
        return self._project_id

    def list_servers(
        self,
        *,
        changes_since: datetime | None = None,
        tags: Iterable[str] = (),
        tags_any: Iterable[str] = (),
        name: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> list[ServerInfo]:
        """``metadata`` is a **fake-only** parameter: like Nova, it is ignored unless the role is ``admin``
        (OSI s.1, LAB-OBSERVED), so a non-admin gets every server of the project back, without an error."""
        with self._call("list_servers"):
            need, any_of = set(tags), set(tags_any)
            out: list[ServerInfo] = []
            for s in self._servers.values():
                if s.id in self._hidden:
                    continue
                if s.deleted and changes_since is None:
                    continue
                if changes_since is not None and s.updated < changes_since:
                    continue
                if need and not need <= set(s.tags):
                    continue
                if any_of and not any_of & set(s.tags):
                    continue
                if name is not None and s.name != name:
                    continue
                if metadata and self.role == "admin" and not metadata.items() <= s.metadata.items():
                    continue
                out.append(self._server_info(s))
            return out

    def get_server(self, server_id: str) -> ServerInfo:
        with self._call("get_server"):
            return self._server_info(self._live_server(server_id))

    def list_server_volume_attachments(self, server_id: str) -> list[VolumeAttachmentInfo]:
        with self._call("list_server_volume_attachments"):
            s = self._live_server(server_id)
            return [
                VolumeAttachmentInfo(server_id, vid, self._volumes[vid].attachments[server_id].device,
                                     self._volumes[vid].attachments[server_id].attachment_id, dot)
                for vid, dot in sorted(s.attached.items())
            ]  # fmt: skip

    def list_volumes(self) -> list[VolumeInfo]:
        with self._call("list_volumes"):
            return [self._volume_info(v) for v in self._volumes.values()]

    def get_volume(self, volume_id: str) -> VolumeInfo:
        with self._call("get_volume"):
            return self._volume_info(self._volume_raw(volume_id))

    def list_volume_types(self) -> list[VolumeTypeInfo]:
        with self._call("list_volume_types"):
            return [
                VolumeTypeInfo(i, n, is_default=n == self.default_volume_type)
                for i, n in self._volume_types.items()
            ]

    def list_ports(self) -> list[PortInfo]:
        with self._call("list_ports"):
            return list(self._ports.values())

    def list_floating_ips(self) -> list[FloatingIpInfo]:
        with self._call("list_floating_ips"):
            return list(self._fips.values())

    def list_networks(self) -> list[NetworkInfo]:
        with self._call("list_networks"):
            return list(self._networks.values())

    def list_images(self) -> list[ImageInfo]:
        with self._call("list_images"):
            return list(self._images.values())

    def list_flavors(self) -> list[FlavorInfo]:
        with self._call("list_flavors"):
            return list(self._flavors.values())

    # --- WriteClient -----------------------------------------------------------------------------------------

    def _require_unlocked(self, s: _Server) -> None:
        if s.locked and self.role != "admin":
            raise InstanceLockedError(f"Instance {s.id} is locked", status=409)

    def _require_idle(self, s: _Server, states: frozenset[str] | None = None) -> None:
        if s.task_state is not None or (states is not None and s.vm_state not in states):
            raise ConflictError(
                f"Cannot operate on instance {s.id} while it is in vm_state {s.vm_state}, task_state {s.task_state}",
                status=409,
            )

    def create_server(self, spec: CreateServerSpec) -> ServerInfo:
        with self._call("create_server"):
            if spec.tags and self.compute_max < COMPUTE_TAGS_AT_CREATE:
                raise BadRequestError(
                    "Additional properties are not allowed ('tags' was unexpected)", status=400
                )
            live = sum(1 for s in self._servers.values() if not s.deleted)
            if self.quota_instances is not None and live >= self.quota_instances:
                raise QuotaExceededError(
                    "Quota exceeded for instances: Requested 1, but already used", status=403
                )
            if spec.image_id not in self._images or spec.flavor_id not in self._flavors:
                raise BadRequestError("Invalid imageRef or flavorRef provided.", status=400)
            sid = self.add_server(
                spec.name, status="BUILD", tags=spec.tags, metadata=dict(spec.metadata),
                image_id=spec.image_id, flavor=self._flavors[spec.flavor_id].name,
            )  # fmt: skip
            s = self._servers[sid]
            s.task_state = "spawning"
            if spec.availability_zone:
                s.availability_zone = spec.availability_zone

            def built() -> None:
                if self.force_no_valid_host:  # quota was fine; the scheduler found no host
                    s.status, s.vm_state, s.fault = "ERROR", "error", "No valid host was found."
                else:
                    s.status, s.vm_state, s.power_state = "ACTIVE", "active", 1
                    s.launched_at = self.now
                s.task_state, s.updated = None, self.now

            self._later(self.build_delay, built)
            return self._server_info(s)

    def delete_server(self, server_id: str) -> None:
        with self._call("delete_server"):
            s = self._live_server(server_id)
            self._require_unlocked(s)
            self._require_idle(s)
            for vid, delete_on_termination in list(s.attached.items()):
                v = self._volumes[vid]
                v.attachments.pop(server_id, None)
                if delete_on_termination:
                    del self._volumes[vid]
                else:
                    v.status = "available" if not v.attachments else "in-use"
            s.attached.clear()
            if self.keep_tombstones:
                s.deleted, s.updated = True, self.now
            else:
                del self._servers[server_id]

    def stop_server(self, server_id: str) -> None:
        with self._call("stop_server"):
            s = self._live_server(server_id)
            self._require_unlocked(s)
            self._require_idle(s, frozenset({"active", "error"}))
            s.task_state, s.updated = "powering-off", self.now

            def stopped() -> None:
                s.status, s.vm_state, s.power_state, s.task_state, s.updated = (
                    "SHUTOFF",
                    "stopped",
                    4,
                    None,
                    self.now,
                )

            self._later(self.stop_delay, stopped)

    def start_server(self, server_id: str) -> None:
        with self._call("start_server"):
            s = self._live_server(server_id)
            self._require_unlocked(s)
            self._require_idle(s, frozenset({"stopped"}))
            s.task_state, s.updated = "powering-on", self.now

            def started() -> None:
                s.status, s.vm_state, s.power_state, s.task_state, s.updated = (
                    "ACTIVE",
                    "active",
                    1,
                    None,
                    self.now,
                )

            self._later(self.start_delay, started)

    def lock_server(self, server_id: str, reason: str | None = None) -> None:
        with self._call("lock_server"):
            s = self._live_server(server_id)
            s.locked, s.locked_reason, s.updated = True, reason, self.now
            s.locked_by = "admin" if self.role == "admin" else "owner"

    def unlock_server(self, server_id: str) -> None:
        with self._call("unlock_server"):
            s = self._live_server(server_id)
            if s.locked and s.locked_by == "admin" and self.role != "admin":
                raise ForbiddenError(
                    "Policy doesn't allow os_compute_api:os-lock-server:unlock:unlock_override",
                    status=403,
                )
            s.locked, s.locked_reason, s.updated = False, None, self.now

    def add_server_tag(self, server_id: str, tag: str) -> None:
        with self._call("add_server_tag"):
            s = self._live_server(server_id)
            if not tag or len(tag) > 60 or "," in tag or "/" in tag:
                raise BadRequestError("Invalid tag", status=400)
            if tag not in s.tags and len(s.tags) >= 50:
                raise BadRequestError(
                    "The number of tags exceeded the per-server limit 50", status=400
                )
            if tag not in s.tags:
                s.tags.append(tag)
                s.updated = self.now

    def attach_volume(self, server_id: str, volume_id: str) -> None:
        with self._call("attach_volume"):
            s = self._live_server(server_id)
            v = self._volume_raw(volume_id)
            self._require_unlocked(s)
            self._require_idle(s, _ATTACHABLE_VM_STATES)
            if volume_id in s.attached or (server_id in v.attachments and not v.multiattach):
                raise VolumeAlreadyAttachedError(
                    f"volume {volume_id} is already attached to instance {server_id}", status=400
                )
            if v.status != "available":
                raise BadRequestError(
                    f"Volume {volume_id} status must be available or downloading to reserve, "
                    f"but the current status is {v.status}.",
                    status=400,
                )
            att = _Attachment(server_id, "/dev/vdb", self._new_id(), "reserved")
            v.status = "reserved"
            v.attachments[server_id] = att

            def attaching() -> None:
                v.status, att.attach_status = "attaching", "attaching"

            def attached() -> None:
                if v.attach_fails:  # volume stays attaching, attachment error_attaching (OSI s.4)
                    att.attach_status = "error_attaching"
                    return
                v.status, att.attach_status = "in-use", "attached"
                s.attached[volume_id] = False  # delete_on_termination defaults to false for attach
                s.updated = self.now

            self._later(self.reserve_delay, attaching)
            self._later(self.reserve_delay + self.attach_delay, attached)

    def detach_volume(self, server_id: str, volume_id: str) -> None:
        with self._call("detach_volume"):
            s = self._live_server(server_id)
            v = self._volume_raw(volume_id)
            self._require_unlocked(s)
            self._require_idle(s, _ATTACHABLE_VM_STATES)
            if volume_id not in s.attached:
                raise NotFoundError(
                    f"Instance {server_id} has no attachment for volume {volume_id}", status=404
                )
            if s.host_down:
                raise ConflictError("Compute service of the instance's host is down", status=409)
            if v.status != "in-use":
                raise BadRequestError("Invalid volume: Volume status must be 'in-use'", status=400)
            v.status = "detaching"

            def detached() -> None:
                if s.guest_refuses_detach:  # rolled back to in-use, not an error state (OSI s.4)
                    v.status = "in-use"
                    return
                v.attachments.pop(server_id, None)
                s.attached.pop(volume_id, None)
                v.status = "available" if not v.attachments else "in-use"
                s.updated = self.now

            self._later(
                self.detach_refusal_timeout if s.guest_refuses_detach else self.detach_delay,
                detached,
            )

    def update_floating_ip(
        self, floating_ip_id: str, port_id: str | None, fixed_ip_address: str | None = None
    ) -> FloatingIpInfo:
        """``port_id=None`` (disassociate) is modelled because the cloud allows it; OVLM never sends it."""
        with self._call("update_floating_ip"):
            fip = self._fips.get(floating_ip_id)
            if fip is None:
                raise NotFoundError(f"Floating IP {floating_ip_id} could not be found", status=404)
            if port_id is None:
                new = FloatingIpInfo(
                    fip.openstack_id,
                    fip.floating_ip_address,
                    None,
                    None,
                    None,
                    fip.floating_network_id,
                    "DOWN",
                    fip.tags,
                )
                self._fips[fip.openstack_id] = new
                return new
            port = self._ports.get(port_id)
            if port is None:
                raise NotFoundError(f"Port {port_id} could not be found.", status=404)
            ext = fip.floating_network_id or ""
            subnet = port.fixed_ips[0][1] if port.fixed_ips else None
            if (port.network_id or "", ext) not in self._router_paths:
                # The misleading 404 (OSI s.6.1): looks like "floating IP not found", means "no router path".
                raise FloatingIpNoRouterPathError(
                    f"External network {ext} is not reachable from subnet {subnet}. "
                    f"Therefore, cannot associate Port {port_id} with a Floating IP.",
                    status=404,
                )
            for other in self._fips.values():
                if (
                    other.openstack_id != fip.openstack_id
                    and other.port_id == port_id
                    and other.floating_network_id == ext
                ):
                    raise FloatingIpPortAlreadyAssociatedError(
                        f"Cannot associate floating IP with port {port_id}: FloatingIPPortAlreadyAssociated",
                        status=409,
                    )
            if fixed_ip_address is None and len(port.fixed_ips) > 1:
                raise BadRequestError(
                    f"Port {port_id} has multiple fixed IPv4 addresses", status=400
                )
            if fixed_ip_address is not None and fixed_ip_address not in [
                ip for ip, _ in port.fixed_ips
            ]:
                raise BadRequestError(
                    f"Port {port_id} does not have fixed ip {fixed_ip_address}", status=400
                )
            router_id = "router-1"
            fixed = fixed_ip_address or (port.fixed_ips[0][0] if port.fixed_ips else None)
            new = FloatingIpInfo(
                fip.openstack_id, fip.floating_ip_address, port_id, fixed,
                router_id, ext, "DOWN", fip.tags,
            )  # fmt: skip
            self._fips[fip.openstack_id] = new

            def active() -> None:  # the L3 agent applies it asynchronously
                cur = self._fips[fip.openstack_id]
                if cur.port_id == port_id:
                    self._fips[fip.openstack_id] = FloatingIpInfo(
                        cur.openstack_id, cur.floating_ip_address, cur.port_id, cur.fixed_ip_address,
                        cur.router_id, cur.floating_network_id, "ACTIVE", cur.tags,
                    )  # fmt: skip

            self._later(self.fip_status_delay, active)
            return new

    def get_console_output(self, server_id: str, length: int | None = None) -> str:
        with self._call("get_console_output"):
            text = self._live_server(server_id).console
            return text if length is None else "\n".join(text.splitlines()[-length:])

    def add_floating_ip_tag(self, floating_ip_id: str, tag: str) -> None:
        with self._call("add_floating_ip_tag"):
            fip = self._fip_raw(floating_ip_id)
            if not tag or len(tag) > 255:
                raise BadRequestError("Invalid tag", status=400)
            if tag in fip.tags:
                return
            if len(fip.tags) >= 50:
                raise BadRequestError("Tag limit 50 exceeded", status=400)
            self._fips[floating_ip_id] = dataclasses.replace(fip, tags=(*fip.tags, tag))

    def merge_volume_metadata(self, volume_id: str, items: Mapping[str, str]) -> None:
        """Cinder ``POST /volumes/{id}/metadata``: keys in ``items`` are set, every other key stays."""
        with self._call("merge_volume_metadata"):
            v = self._volume_raw(volume_id)
            v.metadata.update({str(k): str(val) for k, val in items.items()})

    def get_floating_ip(self, floating_ip_id: str) -> FloatingIpInfo:
        with self._call("get_floating_ip"):
            return self._fip_raw(floating_ip_id)

    def get_port(self, port_id: str) -> PortInfo:
        with self._call("get_port"):
            port = self._ports.get(port_id)
            if port is None:
                raise NotFoundError(f"Port {port_id} could not be found.", status=404)
            return port

    def get_server_fault(self, server_id: str) -> str | None:
        with self._call("get_server_fault"):
            s = self._live_server(server_id)
            return s.fault if s.status == "ERROR" else None

    def write_microversions(self) -> dict[str, str | None]:
        if self.compute_max < (2, 79):
            raise UnsupportedCloudError(
                f"compute microversion {self.compute_max[0]}.{self.compute_max[1]} is below 2.79"
            )
        return {
            "compute_write": "2.79",
            "compute_max": f"{self.compute_max[0]}.{self.compute_max[1]}",
            "block_storage_write": "3.0",
            "block_storage_max": f"{self.block_storage_max[0]}.{self.block_storage_max[1]}",
            "network": None,
        }

    def _fip_raw(self, floating_ip_id: str) -> FloatingIpInfo:
        fip = self._fips.get(floating_ip_id)
        if fip is None:
            raise NotFoundError(f"Floating IP {floating_ip_id} could not be found", status=404)
        return fip

    # --- fake-only cloud operations (OVLM never performs these; they model the cloud) -----------------------

    def create_volume(self, size: int, *, name: str = "vol", volume_type: str | None = None) -> str:
        """Without a type on a cloud with no default type: HTTP 500 (LAB-OBSERVED). OVLM creates no volume."""
        with self._call("create_volume"):
            if volume_type is None and self.default_volume_type is None:
                raise ServerError(
                    "Volume type with name __DEFAULT__ could not be found.", status=500
                )
            return self.add_volume(
                name, size=size, volume_type=volume_type or self.default_volume_type
            )

    def allocate_floating_ip(self, external_network_id: str) -> FloatingIpInfo:
        """Empty pool: 400 although the quota is unlimited (LAB-OBSERVED). OVLM never allocates."""
        with self._call("allocate_floating_ip"):
            if self._fip_pool_free.get(external_network_id, 0) <= 0:
                raise NoFloatingIpAvailableError(
                    f"Unable to find any IP address on external network {external_network_id}.",
                    status=400,
                )
            self._fip_pool_free[external_network_id] -= 1
            fid = self.add_floating_ip(
                external_network_id, address=f"192.0.2.{100 + len(self._fips)}"
            )
            return self._fips[fid]
