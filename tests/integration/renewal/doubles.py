"""Test doubles of the renewal ports: a guest that follows the fake cloud, and the cloud port.

``FakeGuest`` models what matters for data safety: the data volume's content marker travels with the volume; a
guest's mount and units follow its power state (a boot remounts by fstab if the volume is attached and starts the
enabled units, SRE-R-1); ``data_attach`` refuses a volume that is not attached to that guest; the external probe
answers from whichever server holds the FIP's port, with that server's id as identity. ``quiesce`` behaves like the
reference role (contract 3.4): a guest with the volume not mounted and no earlier quiesce record (on its root disk)
is refused as "state unknown" (needs_human), unless OVLM passed ``quiesce_allow_unmounted`` (restore S2, role new):
then it is ok with ``was_mounted: false`` and no marker (lab finding AA).
Result facts use the contract's names (automation-contract 3.7, ``marker_sha256``), the same as the reference
roles: a double with its own spelling would hide a field-name mismatch (defect AB; ``tests/unit/test_marker_contract.py``
checks both).
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
)

SUBNET = "00000000-0000-0000-0000-0000000005b1"


class RenewalFake(FakeOpenStack):
    """The fake cloud, plus what Nova does on create that the base fake omits: a port on the network."""

    green_ip = "10.0.0.9"

    def snapshot(self) -> Any:  # typed loosely for the tests' invariant checks
        return super().snapshot()

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
    #: marker checksum the last quiesce recorded on this guest's root disk (survives reboots, like the real record)
    quiesce_record: str | None = None
    #: the data device is mounted at another path than the profile's mount point (only the by-id probe sees it)
    mounted_elsewhere: bool = False


@dataclass
class FakeGuest:
    cloud: RenewalFake
    volume_id: str | None
    fs_uuid: str = "11111111-2222-3333-4444-555555555555"
    #: blkid LABEL of the data filesystem (contract 3.3 rule 7); a label profile names it instead of the UUID
    fs_label: str | None = "app-data"
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
    #: (server id, quiesce_allow_unmounted) of every quiesce call that reached the guest
    quiesce_calls: list[tuple[str, bool]] = field(default_factory=list)
    #: (phase, expected_marker) of every phase call that reached the guest: what OVLM asked the playbook to compare
    expected_markers: list[tuple[str, str | None]] = field(default_factory=list)
    #: The pinned repository predates lab fix AA: its quiesce role does not know ``quiesce_allow_unmounted`` and
    #: refuses "not mounted, no earlier quiesce record" on green too (lab finding D-8).
    pre_aa_role: bool = False
    #: (server id, data_volume_id) of every read-only probe: the fixed command list, never a mutation
    probes: list[tuple[str, str | None]] = field(default_factory=list)

    def g(self, sid: str) -> GuestState:
        return self.state.setdefault(sid, GuestState())

    def sync(self) -> None:
        snap = self.cloud.snapshot()
        for sid, s in snap["servers"].items():
            st = self.g(sid)
            if s["status"] == "SHUTOFF":
                st.mounted = st.units = st.mounted_elsewhere = False
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
        return bool(snap["servers"].get(sid, {}).get("status") == "ACTIVE")

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
        expected_fs_uuid: str | None = None, quiesce_allow_unmounted: bool = False,
    ) -> PhaseResult:  # fmt: skip
        fence.check(f"spawn:{phase}")
        assert not quiesce_allow_unmounted or (phase == "quiesce" and target.role == "new"), (
            phase,
            target.role,
        )
        self.sync()
        self.calls.append((phase, target.server_id))
        self.expected_markers.append((phase, expected_marker))
        if phase in self.hooks:
            self.hooks.pop(phase)()
        forced = self._fail(phase)
        if forced:
            # an injected failure models the playbook's own failed result.json (it ran and reported this class)
            return PhaseResult(
                forced,  # type: ignore[arg-type]
                f"injected {forced}",
                reported=forced if forced != "ok" else None,
            )
        if not self._active(target.server_id):
            return PhaseResult(
                "retryable" if phase not in ("quiesce", "data_attach") else "needs_human",
                "unreachable",
            )
        st = self.g(target.server_id)
        if phase in ("preflight", "configure", "rollback_hooks"):
            return PhaseResult("ok", "ok")
        if phase == "quiesce":
            self.quiesce_calls.append((target.server_id, quiesce_allow_unmounted))
            st.units = False
            if st.mounted:
                st.mounted = False
                st.quiesce_record = self.marker
                return PhaseResult(
                    "ok", "quiesced", {"marker_sha256": self.marker, "was_mounted": True}
                )
            if st.quiesce_record is not None:
                return PhaseResult(
                    "ok", "quiesced", {"marker_sha256": st.quiesce_record, "was_mounted": False}
                )
            if quiesce_allow_unmounted and target.role == "new" and not self.pre_aa_role:
                return PhaseResult(
                    "ok", "nothing to quiesce", {"marker_sha256": None, "was_mounted": False}
                )
            return PhaseResult("needs_human", "not mounted and no earlier quiesce record: state is unknown",
                               {"error_kind": "planned"}, reported="needs_human")  # fmt: skip
        if phase == "data_attach":
            assert data_volume is not None and data_volume["first_use"] is False
            vol = self.cloud.snapshot()["volumes"][data_volume["id"]]
            if vol["attached_to"] != [target.server_id] or vol["status"] != "in-use":
                return PhaseResult("needs_human", "device not found")
            st.mounted = True
            return PhaseResult(
                "ok",
                "mounted",
                {"fs_uuid": self.fs_uuid, "fs_label": self.fs_label, "marker_sha256": self.marker},
            )
        if phase == "start_service":
            if self.volume_id and not st.mounted:
                return PhaseResult("needs_human", "not mounted")
            st.units = True
            return PhaseResult("ok", "started")
        if phase == "healthcheck":
            if st.units and (st.mounted or not self.volume_id):
                return PhaseResult("ok", "healthy", {"marker_sha256": self.marker})
            return PhaseResult("retryable", "unhealthy")
        raise AssertionError(phase)

    def bootstrap(self, run_id: str, policy: str) -> Bootstrap:
        return Bootstrap(
            "#cloud-config\n# bootstrap host key (secret)\n",
            "ssh-ed25519 AAAAbootstrap",
            "k-" + run_id[-4:],
        )

    def pin_host_key(
        self, *, run_id: str, target: GuestRef, policy: str, bootstrap_public: str | None, accept: tuple[str, ...],
        console: str | None, fence: FenceLike,
    ) -> HostKeyResult:  # fmt: skip
        self.pin_attempts += 1
        if not self._active(target.server_id) or self.pin_attempts <= self.ssh_after:
            return HostKeyResult(False, "unreachable")
        # a re-run after a recorded pin: only the pinned keys, never the bootstrap key (REN-2)
        if accept:
            return HostKeyResult(True, "ok", accept, "rotated")
        if policy == "injected" and not bootstrap_public:
            return HostKeyResult(False, "no bootstrap key")
        return HostKeyResult(True, "ok", accept or ("ssh-ed25519 AAAArotated",), "rotated")

    def probe(
        self, run_id: str, target: GuestRef, *, mount_point: str | None, units: tuple[str, ...],
        data_volume_id: str | None = None,
    ) -> GuestProbe:  # fmt: skip
        self.sync()
        self.probes.append((target.server_id, data_volume_id))
        if not self._active(target.server_id):
            return GuestProbe(False)
        st = self.g(target.server_id)
        device_mounted: bool | None = None
        where: tuple[str, ...] = ()
        if data_volume_id is not None:
            vol = self.cloud.snapshot()["volumes"].get(data_volume_id) or {}
            # no by-id device in the guest without the attachment: unknown
            if target.server_id in (vol.get("attached_to") or []):
                mounts = (
                    (mount_point or "/srv/data", st.mounted),
                    ("/mnt/other", st.mounted_elsewhere),
                )
                where = tuple(p for p, on in mounts if on)
                device_mounted = bool(where)
        # Like production: no unit names, no ``systemctl is-active`` call, so the unit state is unknown (None).
        return GuestProbe(
            True, st.mounted if mount_point else None, st.units if units else None, True, "running",
            {u: ("active" if st.units else "inactive") for u in units} if units else None, device_mounted, where,
        )  # fmt: skip

    def external_probe(
        self, address: str, check: Mapping[str, Any], candidates: Mapping[str, str | None]
    ) -> ExternalResult:
        self.sync()
        if self.external_down:
            return ExternalResult(False, None, "injected")
        port_id = next(iter(p for f, p in self.cloud.snapshot()["floating_ips"].items()))
        if port_id is None:
            return ExternalResult(False, None, "no port")
        server = self.cloud.get_port(port_id).device_id
        if server is None or not self._active(server) or not self.g(server).units:
            return ExternalResult(False, None, "no answer")
        return ExternalResult(True, server)


@dataclass
class FakeCloudPort:
    cloud: RenewalFake
    credential_expires: datetime | None = None
    token_expires: datetime | None = None
    unavailable: str | None = None
    projects: list[str] = field(default_factory=list)

    def unavailable_reason(self, project: str) -> str | None:
        return self.unavailable

    def write_client(
        self, registry: OwnershipRegistry, gate: Callable[[str], None], *, project: str
    ) -> GuardedWriteClient:
        self.projects.append(project)
        return GuardedWriteClient(self.cloud, registry, gate)

    def write_credential_expires_at(self, project: str) -> datetime | None:
        return self.credential_expires

    def write_user_id(self, project: str) -> str | None:
        return self.cloud.user_id

    def token_expires_at(self, project: str) -> datetime | None:
        return self.token_expires
