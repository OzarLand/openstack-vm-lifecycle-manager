"""The ``host_key_scan`` workflow (worker only): read the current VM's SSH host key so an operator can confirm it.

ADR-0006 "Blue": the fingerprint is recorded at registration by a worker scan and **confirmed by an operator**
(:mod:`ovlm.registry.host_keys`). This single step:

* finds the address the renewal itself uses to reach blue, by the same rule (:mod:`ovlm.registry.ssh_target`,
  review IS-3): ``fixed_ips[0]`` of the service floating IP's port, from the inventory;
* runs ``ssh-keyscan`` (no authentication, no credential, nothing sent but the SSH handshake);
* writes the preferred key's SHA-256 fingerprint (ed25519, then ECDSA, then RSA) to
  ``managed_vm.ssh_host_key_fingerprint``. All scanned fingerprints are kept in the step evidence.

The scan proves nothing by itself: the trust comes from the operator's comparison with the VM's console. A scan
never replaces a **confirmed** fingerprint; a different key fails the run (``host key changed``) and leaves the
confirmed one in place. No key answered: the run fails with ``unreachable`` (re-scan later).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import Any, ClassVar
from uuid import UUID

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.dbutil import rowcount
from ovlm.automation.hostkeys import PublicKey
from ovlm.registry.host_keys import KIND, STRATEGY, STRATEGY_VERSION
from ovlm.registry.ssh_target import NoSshTargetError, blue_ssh_target
from ovlm.workflow.contract import (
    Act,
    Admission,
    Decision,
    Defer,
    Done,
    ErrorClass,
    Fail,
    Outcome,
    Reject,
    Step,
    StepContext,
    StepSpec,
    Transition,
    TxContext,
    WorkflowDefinition,
)

log = logging.getLogger("ovlm.registry.host_key_scan")

SCAN = "scan"
SSH_PORT = 22
#: Preferred first: the fingerprint an operator most likely reads on the console.
KEY_PREFERENCE = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
)

Keyscan = Callable[[str, int], list[PublicKey]]


def preferred(keys: list[PublicKey]) -> PublicKey | None:
    ranked = sorted(
        (k for k in keys if k.type in KEY_PREFERENCE), key=lambda k: KEY_PREFERENCE.index(k.type)
    )
    return ranked[0] if ranked else None


def _vm(conn: Any, managed_vm_id: str) -> Any:
    return conn.execute(
        text(
            "SELECT m.id, m.ssh_host_key_fingerprint, m.host_key_confirmed_at, s.project_connection_id "
            "FROM managed_vm m JOIN service s ON s.id = m.service_id WHERE m.id = :v"
        ),
        {"v": managed_vm_id},
    ).first()


class ScanStep(Step):
    key: ClassVar[str] = SCAN

    def __init__(self, engine: Engine, keyscan: Keyscan) -> None:
        self.engine, self.keyscan = engine, keyscan

    def probe(self, ctx: StepContext) -> Any:
        return ctx.previous_evidence

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        vm_id = ctx.run.subject.get("managed_vm_id")
        if not vm_id:
            return Fail(ErrorClass.FATAL, "the run names no managed VM")
        if observed and observed.get("recorded"):
            return Done(dict(observed))
        return Act({"managed_vm_id": vm_id})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        vm_id = str(intent["managed_vm_id"])
        with self.engine.connect() as c:
            vm = _vm(c, vm_id)
            if vm is None:
                raise _ScanFailed("the managed VM no longer exists")
            try:
                target = blue_ssh_target(c, vm_id)
            except NoSshTargetError as exc:
                raise _ScanFailed(str(exc)) from None
        address = target.address
        keys = self.keyscan(address, SSH_PORT)
        key = preferred(keys)
        if key is None:
            raise _ScanFailed(
                f"unreachable: no SSH host key answered at {address}:{SSH_PORT} from the worker"
            )
        scanned = sorted({f"{k.type} {k.fingerprint}" for k in keys})
        ctx.gate("managed_vm:host_key")
        with Session(self.engine) as s, s.begin():
            n = rowcount(
                s.execute(
                    text(
                        "UPDATE managed_vm SET ssh_host_key_fingerprint = :fp, updated_at = now() WHERE id = :v "
                        "AND (host_key_confirmed_at IS NULL OR ssh_host_key_fingerprint = :fp)"
                    ),
                    {"fp": key.fingerprint, "v": vm_id},
                )
            )
            changed = n != 1
            audit.record(
                s, action="managed_vm.host_key_scan", target_type="managed_vm_host_key", target_id=vm_id,
                result="failure" if changed else "success", principal_type="worker", auth_method="none",
                run_id=UUID(ctx.run.id), project_scope=f"project:{vm.project_connection_id}",
                after={"managed_vm_id": vm_id, "fingerprint": key.fingerprint, "key_type": key.type,
                       "address": address, "port_id": target.port_id, "floating_ip_id": target.floating_ip_id},
            )  # fmt: skip
        if changed:
            raise _ScanFailed(
                f"host key changed: the VM presents {key.fingerprint}, not the confirmed fingerprint "
                f"{vm.ssh_host_key_fingerprint}. Nothing was changed. Check the VM's console; if it was rebuilt, "
                "unregister and register it again"
            )
        ctx.checkpoint(
            evidence={"recorded": True, "fingerprint": key.fingerprint, "key_type": key.type,
                      "address": address, "port_id": target.port_id, "floating_ip_id": target.floating_ip_id,
                      "target_source": target.source, "scanned": scanned}
        )  # fmt: skip

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        with self.engine.connect() as c:
            vm = _vm(c, str(intent["managed_vm_id"]))
        if vm is None or vm.ssh_host_key_fingerprint is None:
            return Fail(ErrorClass.RETRYABLE, "scan not recorded")
        return Done({"recorded": True, "fingerprint": vm.ssh_host_key_fingerprint,
                     "confirmed": vm.host_key_confirmed_at is not None})  # fmt: skip

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        if isinstance(exc, _ScanFailed):
            return Fail(ErrorClass.FATAL, str(exc)[:500])
        return super().classify(ctx, exc)


class _ScanFailed(Exception):
    pass


class HostKeyScanDefinition(WorkflowDefinition):
    kind: ClassVar[str] = KIND
    strategy: ClassVar[str] = STRATEGY
    version: ClassVar[str] = STRATEGY_VERSION

    def __init__(self, engine: Engine, keyscan: Keyscan) -> None:
        self._steps = {SCAN: ScanStep(engine, keyscan)}

    @property
    def steps(self) -> Mapping[str, Step]:
        return self._steps

    def admit(self, ctx: TxContext) -> Admission | Reject | Defer:
        vm_id = ctx.run.subject.get("managed_vm_id")
        if not vm_id or _vm(ctx.conn, str(vm_id)) is None:
            return Reject("the managed VM no longer exists")
        return Admission(StepSpec(SCAN, timeout=300.0))

    def next(self, ctx: TxContext, done: Done) -> Transition:
        return Transition(run_state="completed")

    def validate_signal(self, ctx: TxContext) -> str | None:
        return "host-key scans accept no signals"
