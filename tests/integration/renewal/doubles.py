"""Test doubles of the renewal ports: a guest that follows the fake cloud, snapshots, and the cloud port.

``FakeGuest`` models what matters for data safety: the data volume's content marker travels with the volume; a
guest's mount and units follow its power state (a boot remounts by fstab if the volume is attached and starts the
enabled units, SRE-R-1); ``data_attach`` refuses a volume that is not attached to that guest; the external probe
answers from whichever server holds the FIP's port, with that server's id as identity.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ovlm.openstack.fake import FakeOpenStack
from ovlm.openstack.ownership import OwnershipRegistry
from ovlm.openstack.types import CreateServerSpec, ServerInfo
from ovlm.openstack.write import GuardedWriteClient
from ovlm.renewal.ports import (
    Bootstrap,
    ExternalResult,
    FenceLike,
    GuestProbe,
    GuestRef,
    HostKeyResult,
    PhaseResult,
    SnapshotInfo,
)

SUBNET = "00000000-0000-0000-0000-0000000005b1"


class RenewalFake(FakeOpenStack):
    """The fake cloud, plus what Nova does on create that the base fake omits: a port on the network."""

    green_ip = "10.0.0.9"

    def create_server(self, spec: CreateServerSpec) -> ServerInfo:
        info = super().create_server(spec)
        self.add_port(
            spec.network_id or "", device_id=info.openstack_id, ip=self.green_ip, subnet=SUBNET
        )
        return info


@dataclass
class GuestState:
    mounted: bool = False
    units: bool = False
    down: bool = False


@dataclass
class FakeGuest:
    cloud: RenewalFake
    volume_id: str | None
    fs_uuid: str = "11111111-2222-3333-4444-555555555555"
    marker: str = "marker-v1"
    phases: set[str] = field(default_factory=lambda: {"preflight"})
    #: phase -> list of classifications returned by the next calls (consumed first).
    failures: dict[str, list[str]] = field(default_factory=dict)
    #: SSH to green answers only after this many pin attempts (EXP-01b: ACTIVE != reachable).
    ssh_after: int = 0
    state: dict[str, GuestState] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    hooks: dict[str, Callable[[], None]] = field(default_factory=dict)
    pin_attempts: int = 0
    external_down: bool = False

    def g(self, sid: str) -> GuestState:
        return self.state.setdefault(sid, GuestState())

    def sync(self) -> None:
        snap = self.cloud.snapshot()
        for sid, s in snap["servers"].items():  # type: ignore[union-attr]
            st = self.g(sid)
            if s["status"] == "SHUTOFF":
                st.mounted = st.units = False
                st.down = True
            elif s["status"] == "ACTIVE" and st.down:
                st.down = False
                st.mounted = self.volume_id in s["volumes"]
                st.units = True

    def _fail(self, phase: str) -> str | None:
        queue = self.failures.get(phase) or []
        return queue.pop(0) if queue else None

    def _active(self, sid: str) -> bool:
        snap = self.cloud.snapshot()
        return snap["servers"].get(sid, {}).get("status") == "ACTIVE"  # type: ignore[union-attr]

    # -- GuestPort --------------------------------------------------------------------------------------

    def prepare(
        self, run_id: str, automation: Mapping[str, Any], fence: FenceLike
    ) -> Mapping[str, Any]:
        self.calls.append(("prepare", run_id))
        return {"sha": automation.get("sha"), "lint": "ok"}

    def has_phase(self, run_id: str, phase: str) -> bool:
        return phase in self.phases

    def run_phase(
        self, *, run_id: str, step_id: str, attempt: int, phase: str, target: GuestRef, timeout: float,
        fence: FenceLike, data_volume: Mapping[str, Any] | None = None, expected_marker: str | None = None,
        expected_fs_uuid: str | None = None,
    ) -> PhaseResult:  # fmt: skip
        fence.check(f"spawn:{phase}")
        self.sync()
        self.calls.append((phase, target.server_id))
        if phase in self.hooks:
            self.hooks.pop(phase)()
        forced = self._fail(phase)
        if forced:
            return PhaseResult(forced, f"injected {forced}")  # type: ignore[arg-type]
        if not self._active(target.server_id):
            return PhaseResult(
                "retryable" if phase not in ("quiesce", "data_attach") else "needs_human",
                "unreachable",
            )
        st = self.g(target.server_id)
        if phase in ("preflight", "configure", "rollback_hooks"):
            return PhaseResult("ok", "ok")
        if phase == "quiesce":
            st.units = st.mounted = False
            return PhaseResult("ok", "quiesced", {"marker_checksum": self.marker})
        if phase == "data_attach":
            assert data_volume is not None and data_volume["first_use"] is False
            vol = self.cloud.snapshot()["volumes"][data_volume["id"]]
            if vol["attached_to"] != [target.server_id] or vol["status"] != "in-use":  # type: ignore[index]
                return PhaseResult("needs_human", "device not found")
            st.mounted = True
            return PhaseResult(
                "ok", "mounted", {"fs_uuid": self.fs_uuid, "marker_checksum": self.marker}
            )
        if phase == "start_service":
            if self.volume_id and not st.mounted:
                return PhaseResult("needs_human", "not mounted")
            st.units = True
            return PhaseResult("ok", "started")
        if phase == "healthcheck":
            if st.units and (st.mounted or not self.volume_id):
                return PhaseResult("ok", "healthy", {"marker_checksum": self.marker})
            return PhaseResult("retryable", "unhealthy")
        raise AssertionError(phase)

    def bootstrap(self, run_id: str, policy: str) -> Bootstrap:
        return Bootstrap(
            "#cloud-config\n# bootstrap host key (secret)\n",
            "ssh-ed25519 AAAAbootstrap",
            "k-" + run_id[-4:],
        )

    def pin_host_key(
        self, *, target: GuestRef, policy: str, bootstrap_public: str | None, accept: tuple[str, ...],
        console: str | None, fence: FenceLike,
    ) -> HostKeyResult:  # fmt: skip
        self.pin_attempts += 1
        if not self._active(target.server_id) or self.pin_attempts <= self.ssh_after:
            return HostKeyResult(False, "unreachable")
        if policy == "injected" and not bootstrap_public:
            return HostKeyResult(False, "no bootstrap key")
        return HostKeyResult(True, "ok", accept or ("ssh-ed25519 AAAArotated",), "rotated")

    def probe(
        self, target: GuestRef, *, mount_point: str | None, units: tuple[str, ...]
    ) -> GuestProbe:
        self.sync()
        if not self._active(target.server_id):
            return GuestProbe(False)
        st = self.g(target.server_id)
        return GuestProbe(True, st.mounted if mount_point else None, st.units, True, "running")

    def external_probe(self, address: str, check: Mapping[str, Any]) -> ExternalResult:
        self.sync()
        if self.external_down:
            return ExternalResult(False, None, "injected")
        port_id = next(iter(p for f, p in self.cloud.snapshot()["floating_ips"].items()))  # type: ignore[call-overload]
        if port_id is None:
            return ExternalResult(False, None, "no port")
        server = self.cloud.get_port(port_id).device_id
        if server is None or not self._active(server) or not self.g(server).units:
            return ExternalResult(False, None, "no answer")
        return ExternalResult(True, server)


@dataclass
class FakeSnapshots:
    fail_create: bool = False
    stuck: bool = False
    snaps: dict[str, SnapshotInfo] = field(default_factory=dict)
    deleted: list[str] = field(default_factory=list)

    def find_snapshot(self, name: str) -> SnapshotInfo | None:
        return next((s for s in self.snaps.values() if s.name == name), None)

    def get_snapshot(self, snapshot_id: str) -> SnapshotInfo | None:
        return self.snaps.get(snapshot_id)

    def create_snapshot(
        self, volume_id: str, name: str, gate: Callable[[str], None]
    ) -> SnapshotInfo:
        gate("openstack:create_snapshot")
        status = "error" if self.fail_create else ("creating" if self.stuck else "available")
        info = SnapshotInfo(f"snap-{len(self.snaps) + 1}", name, status, volume_id)
        self.snaps[info.openstack_id] = info
        return info

    def delete_snapshot(self, snapshot_id: str, gate: Callable[[str], None]) -> None:
        gate("openstack:delete_snapshot")
        self.deleted.append(snapshot_id)
        self.snaps.pop(snapshot_id, None)


@dataclass
class FakeCloudPort:
    cloud: RenewalFake
    snaps: FakeSnapshots | None = None
    credential_expires: datetime | None = None
    token_expires: datetime | None = None

    def write_client(
        self, registry: OwnershipRegistry, gate: Callable[[str], None]
    ) -> GuardedWriteClient:
        return GuardedWriteClient(self.cloud, registry, gate)

    def write_credential_expires_at(self) -> datetime | None:
        return self.credential_expires

    def write_user_id(self) -> str | None:
        return self.cloud.user_id

    def token_expires_at(self) -> datetime | None:
        return self.token_expires

    def snapshots(self) -> FakeSnapshots | None:
        return self.snaps
