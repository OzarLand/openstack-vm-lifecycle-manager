"""What the renewal steps need from the outside world, as narrow protocols (worker only).

* :class:`CloudPort` builds the per-attempt :class:`~ovlm.openstack.write.GuardedWriteClient` (ownership guard +
  allowlist + fence gate) for a run, and reports credential/token expiry for the W1 claim checks.
* :class:`GuestPort` is the guest side: the automation runner phases (contract section 3), the B5 host-key
  bootstrap (ADR-0006), the fixed OVLM-owned read-only probe command list (SEC-R-36) and the external HTTP probe.
* :class:`SnapshotPort` is the Cinder snapshot of W4. **The write client of this release has no snapshot
  operation** (allowlist and backends); ``CloudPort.snapshots()`` returns ``None`` in production, and B1 refuses a
  plan with ``snapshot_before_handoff`` instead of failing inside the outage (reported).

Production adapters: ``ovlm.renewal.production``. Tests: ``tests/renewal_doubles.py``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol

from ovlm.openstack.ownership import OwnershipRegistry
from ovlm.openstack.write import GuardedWriteClient

Gate = Callable[[str], None]


class FenceLike(Protocol):
    def check(self, action: str) -> None: ...

    def add_revoke_callback(self, cb: Callable[[str], None]) -> Callable[[], None]: ...


class CloudPort(Protocol):
    def write_client(self, registry: OwnershipRegistry, gate: Gate) -> GuardedWriteClient: ...

    def write_credential_expires_at(self) -> datetime | None:
        """``expires_at`` of the write application credential (entered by the admin); ``None`` if unknown."""
        ...

    def write_user_id(self) -> str | None:
        """Keystone user of the write credential (B3 adoption: ``user_id`` must match, SEC-R-23)."""
        ...

    def token_expires_at(self) -> datetime | None:
        """Expiry of a Keystone token obtained now (pre-warmed before the W1 claim transaction, SRE-R-28 b)."""
        ...

    def snapshots(self) -> SnapshotPort | None: ...


@dataclass(frozen=True)
class SnapshotInfo:
    openstack_id: str
    name: str
    status: str
    volume_id: str


class SnapshotPort(Protocol):
    def find_snapshot(self, name: str) -> SnapshotInfo | None: ...

    def get_snapshot(self, snapshot_id: str) -> SnapshotInfo | None: ...

    def create_snapshot(self, volume_id: str, name: str, gate: Gate) -> SnapshotInfo: ...

    def delete_snapshot(self, snapshot_id: str, gate: Gate) -> None: ...


Role = Literal["old", "new"]


@dataclass(frozen=True)
class GuestRef:
    """A guest OVLM may SSH to. ``host_keys`` are pinned public keys (green after B5); ``fingerprint`` is blue's
    confirmed fingerprint (registration, ADR-0006)."""

    server_id: str
    address: str
    role: Role
    host_keys: tuple[str, ...] = ()
    fingerprint: str | None = None


@dataclass(frozen=True)
class PhaseResult:
    classification: Literal["ok", "retryable", "needs_human", "fatal"]
    reason: str
    facts: Mapping[str, Any] = field(default_factory=dict)
    evidence: Mapping[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.classification == "ok"


@dataclass(frozen=True)
class Bootstrap:
    """cloud-init user-data for green (the ``ovlm`` user key and, under ``injected``, a per-run bootstrap host key
    pair). ``user_data`` holds a private key: never logged, never stored; only ``public_key`` is persisted."""

    user_data: str = field(repr=False)
    public_key: str | None
    key_id: str | None


@dataclass(frozen=True)
class HostKeyResult:
    ok: bool
    reason: str
    pinned: tuple[str, ...] = ()
    #: ``rotated`` when the bootstrap key was replaced and removed; ``console``/``tofu`` for the other policies.
    mode: str = ""


@dataclass(frozen=True)
class GuestProbe:
    """Result of the fixed read-only command list (``findmnt``, ``systemctl is-active``, ``systemctl is-enabled``,
    ``cloud-init status``, ``systemctl is-system-running``). ``reachable=False``: SSH failed."""

    reachable: bool
    mounted: bool | None = None
    units_active: bool | None = None
    cloud_init_done: bool | None = None
    system_state: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "reachable": self.reachable,
            "mounted": self.mounted,
            "units_active": self.units_active,
            "cloud_init_done": self.cloud_init_done,
            "system_state": self.system_state,
        }


@dataclass(frozen=True)
class ExternalResult:
    ok: bool
    #: Identity/marker reported by the responding guest (the server id it runs on), to prove who answered.
    identity: str | None
    detail: str = ""


class GuestPort(Protocol):
    def prepare(
        self, run_id: str, automation: Mapping[str, Any], fence: FenceLike
    ) -> Mapping[str, Any]:
        """B6: one verified clone + lint per run (re-verified by SHA on rerun). Raises on a fatal problem."""
        ...

    def run_phase(
        self,
        *,
        run_id: str,
        step_id: str,
        attempt: int,
        phase: str,
        target: GuestRef,
        timeout: float,
        fence: FenceLike,
        data_volume: Mapping[str, Any] | None = None,
        expected_marker: str | None = None,
        expected_fs_uuid: str | None = None,
    ) -> PhaseResult: ...

    def has_phase(self, run_id: str, phase: str) -> bool:
        """Whether the prepared repository has the optional playbook (``preflight``, ``rollback_hooks``)."""
        ...

    def bootstrap(self, run_id: str, policy: str) -> Bootstrap: ...

    def pin_host_key(
        self,
        *,
        target: GuestRef,
        policy: str,
        bootstrap_public: str | None,
        accept: tuple[str, ...],
        console: str | None,
        fence: FenceLike,
    ) -> HostKeyResult:
        """B5 (ADR-0006). ``accept``: keys a re-run may accept (the bootstrap key or the keys pinned in evidence
        when a rotation was interrupted); anything else fails "host key unverifiable"."""
        ...

    def probe(
        self, target: GuestRef, *, mount_point: str | None, units: tuple[str, ...]
    ) -> GuestProbe: ...

    def external_probe(self, address: str, check: Mapping[str, Any]) -> ExternalResult: ...
