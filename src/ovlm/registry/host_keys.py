"""Blue's SSH host key: scan request and operator confirmation (ADR-0006 "Blue", api-design.md 3.3). Api side.

The renewal reaches the current VM (blue) over SSH with ``StrictHostKeyChecking=yes`` and accepts only keys whose
SHA-256 fingerprint equals ``managed_vm.ssh_host_key_fingerprint`` **confirmed** by an operator
(``host_key_confirmed_at``); a plan is refused without it. The trust comes from the human comparison, not the scan:

1. Registration (or ``POST /managed-vms/{id}/host-key-scans``) queues a ``host_key_scan`` run (worker,
   :mod:`ovlm.registry.host_key_scan`): ``ssh-keyscan`` of the VM's fixed address from the inventory, the
   preferred key's fingerprint written to ``ssh_host_key_fingerprint``.
2. The operator compares it with a fingerprint obtained out of band (the VM's console, cloud-init's
   ``-----BEGIN SSH HOST KEY FINGERPRINTS-----`` block, or ``ssh-keygen -lf`` run on the VM) and confirms it:
   ``POST /managed-vms/{id}/host-key/confirm {"fingerprint": "SHA256:..."}``, a human session only, audited. The
   confirmation names the fingerprint, so a key that changed after the operator looked at it is never confirmed.

A re-scan never replaces a **confirmed** fingerprint: a different key then fails the scan (the VM was rebuilt or
something answers in its place); the operator unregisters and registers the VM again to start over.

No OpenStack, SSH or automation import here: the api imports this module. Transactions belong to the caller.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.dbutil import rowcount
from ovlm.registry.errors import DomainError
from ovlm.workflow.requests import request_run

KIND = STRATEGY = "host_key_scan"
STRATEGY_VERSION = "1"
_TERMINAL = ("rejected", "cancelled", "failed", "completed", "rolled_back")
# Scans (worker) and confirmations (api) are audited by fingerprint and address only.
audit.register_entity(
    "managed_vm_host_key", ["managed_vm_id", "fingerprint", "key_type", "address"]
)

#: OpenSSH's SHA-256 fingerprint form: ``SHA256:`` + 43 characters of unpadded base64.
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


def _run_dict(r: Any) -> dict[str, Any]:
    return {
        "id": str(r.id), "state": r.state, "end_reason": r.end_reason,
        "requested_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
    }  # fmt: skip


_COLS = (
    "id, state, started_at, finished_at, COALESCE(end_reason, (SELECT s.error->>'reason' FROM workflow_step s "
    "WHERE s.run_id = workflow_run.id AND s.error IS NOT NULL ORDER BY s.seq DESC LIMIT 1)) AS end_reason"
)


def scan_runs(session: Session, managed_vm_id: UUID, *, limit: int = 5) -> list[dict[str, Any]]:
    rows = session.execute(
        text(
            f"SELECT {_COLS} FROM workflow_run WHERE kind = :k AND subject->>'managed_vm_id' = :v "  # noqa: S608
            "ORDER BY started_at DESC, id DESC LIMIT :n"
        ),
        {"k": KIND, "v": str(managed_vm_id), "n": limit},
    ).all()
    return [_run_dict(r) for r in rows]


def request_scan(
    session: Session, managed_vm: dict[str, Any], *, requested_by: UUID | None
) -> tuple[dict[str, Any], bool]:
    """Queue a scan of the VM. Returns ``(run, created)``; a queued or running scan is returned instead of a new one."""
    vm_id = str(managed_vm["id"])
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"host_key_scan:{vm_id}"}
    )
    row = session.execute(
        text(
            f"SELECT {_COLS} FROM workflow_run WHERE kind = :k AND subject->>'managed_vm_id' = :v "  # noqa: S608
            "AND state NOT IN :t ORDER BY started_at DESC LIMIT 1"
        ).bindparams(bindparam("t", expanding=True)),
        {"k": KIND, "v": vm_id, "t": list(_TERMINAL)},
    ).first()
    if row is not None:
        return _run_dict(row), False
    run_id = request_run(
        session.connection(), kind=KIND, strategy=STRATEGY, strategy_version=STRATEGY_VERSION,
        subject={"managed_vm_id": vm_id}, service_id=str(managed_vm["service_id"]),
        started_by=str(requested_by) if requested_by else None,
    )  # fmt: skip
    row = session.execute(
        text(f"SELECT {_COLS} FROM workflow_run WHERE id = :i"),  # noqa: S608 - fixed column list
        {"i": run_id},
    ).one()
    return _run_dict(row), True


def confirm(
    session: Session, managed_vm_id: UUID, fingerprint: str, *, actor_id: UUID
) -> dict[str, Any]:
    """Record the operator's confirmation of the scanned fingerprint. Idempotent for the same fingerprint."""
    if not FINGERPRINT.match(fingerprint):
        raise DomainError(422, "invalid-fingerprint", "Invalid fingerprint",
                          "A fingerprint looks like SHA256: followed by 43 base64 characters.",
                          "Copy it from ssh-keygen -lf or the VM's console.")  # fmt: skip
    row = session.execute(
        text(
            "SELECT ssh_host_key_fingerprint, host_key_confirmed_at FROM managed_vm WHERE id = :i"
        ),
        {"i": managed_vm_id},
    ).first()
    if row is None:
        raise DomainError(
            404, "managed-vm-not-found", "Managed VM not found", "No such managed VM."
        )
    if row.ssh_host_key_fingerprint is None:
        raise DomainError(409, "host-key-not-scanned", "Host key not scanned yet",
                          "No host key has been scanned for this VM yet.",
                          "Wait for the scan run, or start one: POST /api/v1/managed-vms/{id}/host-key-scans.")  # fmt: skip
    if row.ssh_host_key_fingerprint != fingerprint:
        raise DomainError(409, "host-key-mismatch", "Fingerprint does not match the scan",
                          "The fingerprint you confirmed is not the one the worker scanned. Do not confirm a key "
                          "you cannot match: something else may answer at the VM's address.",
                          "Check the VM's console; if the VM was rebuilt, start a new scan.")  # fmt: skip
    if row.host_key_confirmed_at is not None:
        return {"fingerprint": fingerprint, "already_confirmed": True}
    # The fingerprint is part of the WHERE: a concurrent re-scan that changed it makes this a no-op (409 below).
    updated = session.execute(
        text(
            "UPDATE managed_vm SET host_key_confirmed_by = :by, host_key_confirmed_at = now() "
            "WHERE id = :i AND ssh_host_key_fingerprint = :fp AND host_key_confirmed_at IS NULL"
        ),
        {"by": actor_id, "i": managed_vm_id, "fp": fingerprint},
    )
    if rowcount(updated) != 1:
        raise DomainError(409, "host-key-changed", "Host key changed meanwhile",
                          "The scanned fingerprint changed while you were confirming it.",
                          "Read the VM again and compare the new fingerprint.")  # fmt: skip
    return {"fingerprint": fingerprint, "already_confirmed": False}
