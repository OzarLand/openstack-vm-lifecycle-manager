"""Renewal plans: resolution from the latest inventory, the plan hash, requester sets, typed confirmation (api-safe).

The plan hash (security-model.md 7.1) is SHA-256 over canonical JSON of: the ``resolved`` document, the profile
version id and ``spec_hash``, the automation SHA, the target ids, and the **policy version with every field the
renewal acts on**, and the active lint waivers of the profile version (SF-13; only when there are some, so a plan
without waivers keeps the hash it always had). The worker never trusts ``renewal_plan.plan_hash``: :func:`load_facts` recomputes it from the
live ``profile_version`` and ``policy`` rows, so an edited policy (new version) or a different profile version
makes every approval bound to the old hash invalid (renewal-workflow.md 3.1 check 1).

Used by the api (plan creation, approval decisions) and by the worker (evidence re-validation). Imports nothing from
``openstack``/``automation``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, RowMapping, text

from ovlm import audit  # noqa: E402
from ovlm.auth.sod import RequesterSet, WaiverRecord
from ovlm.profiles.waivers import active_waivers, hash_binding, waiver_records
from ovlm.registry.errors import DomainError
from ovlm.renewal.config import RenewalConfig

audit.register_entity(
    "renewal_run",
    ["trigger", "step_key", "error_class", "reason", "outcome", "approval_id", "snapshot_id", "truth", "rule",
     "kind", "signal_id", "plan_id", "run_id"],
)  # fmt: skip
audit.register_entity("renewal_plan", ["managed_vm_id", "state", "policy_version", "run_id"])
audit.register_entity(
    "approval",
    ["subject_type", "subject_id", "decision", "self_approved", "operator_confirmed", "expires_at"],
)

STRATEGY = "bluegreen_fip_v1"
STRATEGY_VERSION = "1"
KIND = "renewal"

_POLICY_COLS = (
    "id, version, windows, approvals, require_distinct_approvers, snapshot_retain_after_restore, "
    "auto_restore_in_window, max_window_duration_seconds, retention_period_seconds, last_edited_by"
)


def canonical(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256(doc: Any) -> str:
    return hashlib.sha256(canonical(doc).encode()).hexdigest()


def tc_of(name: str | None, openstack_id: str) -> str:
    """Typed confirmation of a server: its name plus the last 6 characters of its id (security-model.md 7.1)."""
    return f"{name or ''} {openstack_id[-6:]}".strip()


def policy_binding(row: Mapping[Any, Any]) -> dict[str, Any]:
    """The policy fields bound into the plan hash (the policy version and what the renewal acts on)."""
    return {
        "id": str(row["id"]),
        "version": int(row["version"]),
        "windows": row["windows"],
        "approvals": row["approvals"],
        "require_distinct_approvers": bool(row["require_distinct_approvers"]),
        "snapshot_retain_after_restore": row["snapshot_retain_after_restore"],
        "auto_restore_in_window": bool(row["auto_restore_in_window"]),
        "max_window_duration_seconds": int(row["max_window_duration_seconds"]),
        "retention_period_seconds": row["retention_period_seconds"],
    }


def compute_plan_hash(
    *,
    resolved: Mapping[str, Any],
    profile_version_id: str,
    spec_hash: str,
    automation_sha: str | None,
    policy: Mapping[str, Any],
    lint_waivers: list[dict[str, str]] | None = None,
) -> str:
    extra: dict[str, Any] = {"lint_waivers": lint_waivers} if lint_waivers else {}
    return sha256(
        {
            **extra,
            "strategy": f"{STRATEGY}/{STRATEGY_VERSION}",
            "resolved": resolved,
            "profile_version_id": profile_version_id,
            "spec_hash": spec_hash,
            "automation_sha": automation_sha,
            "targets": {
                "blue": resolved.get("blue", {}).get("server_id"),
                "volume": (resolved.get("data_volume") or {}).get("volume_id"),
                "floating_ip": resolved.get("floating_ip", {}).get("id"),
            },
            "policy": policy,
        }
    )


@dataclass(frozen=True)
class PlanFacts:
    """A plan as the worker re-derives it (never from ``renewal_plan.plan_hash``)."""

    plan_id: str
    plan: Mapping[str, Any]
    resolved: Mapping[str, Any]
    policy: Mapping[str, Any] | None
    #: Recomputed from the live profile version and policy rows; ``None`` when a source row is gone.
    recomputed_hash: str | None
    profile_author: UUID | None
    policy_editor: UUID | None
    #: The active lint waivers of the plan's profile version, as bound into the hash (SF-13).
    lint_waivers: tuple[dict[str, str], ...] = ()
    #: The same waivers as raw facts, for the worker's provenance checks (review SFR-1).
    waiver_records: tuple[WaiverRecord, ...] = ()

    @property
    def scope(self) -> str:
        return str(self.resolved["scope"])

    def requester_set(
        self, *, run_starter: UUID | None, approval_requester: UUID | None
    ) -> RequesterSet:
        return RequesterSet(
            profile_version_author=self.profile_author,
            plan_creator=self.plan.get("created_by"),
            run_starter=run_starter,
            policy_editor=self.policy_editor,
            approval_requester=approval_requester,
        )


def load_facts(conn: Connection, plan_id: str | UUID) -> PlanFacts:
    plan = (
        conn.execute(text("SELECT * FROM renewal_plan WHERE id = :id"), {"id": str(plan_id)})
        .mappings()
        .first()
    )
    if plan is None:
        raise LookupError(f"renewal plan {plan_id} not found")
    pv = (
        conn.execute(
            text(
                "SELECT spec_hash, automation_sha, created_by FROM profile_version WHERE id = :id"
            ),
            {"id": plan["profile_version_id"]},
        )
        .mappings()
        .first()
    )
    pol = (
        conn.execute(
            text(f"SELECT {_POLICY_COLS} FROM policy WHERE id = :id"),  # noqa: S608 - fixed column list
            {"id": plan["policy_id"]},
        )
        .mappings()
        .first()
    )
    policy = policy_binding(pol) if pol else None
    waivers = hash_binding(active_waivers(conn, plan["profile_version_id"]))
    recomputed = None
    if pv is not None and policy is not None:
        recomputed = compute_plan_hash(
            resolved=plan["resolved"],
            profile_version_id=str(plan["profile_version_id"]),
            spec_hash=pv["spec_hash"],
            automation_sha=pv["automation_sha"],
            policy=policy,
            lint_waivers=waivers,
        )
    return PlanFacts(
        plan_id=str(plan["id"]),
        plan=dict(plan),
        resolved=plan["resolved"],
        policy=policy,
        recomputed_hash=recomputed,
        profile_author=pv["created_by"] if pv else None,
        policy_editor=pol["last_edited_by"] if pol else None,
        lint_waivers=tuple(waivers),
        waiver_records=waiver_records(conn, plan["profile_version_id"]),
    )


# --- resolution (api, at plan creation) ---------------------------------------------------------------------------


def _err(status: int, code: str, title: str, detail: str, nxt: str | None = None) -> DomainError:
    return DomainError(status, code, title, detail, nxt)


def _observed(conn: Connection, table: str, pc: Any, openstack_id: str) -> RowMapping | None:
    return (
        conn.execute(
            text(
                f"SELECT * FROM observed_{table} WHERE project_connection_id = :pc AND openstack_id = :id "  # noqa: S608 - fixed table names
                "AND status = 'present'"
            ),
            {"pc": pc, "id": openstack_id},
        )
        .mappings()
        .first()
    )


def resolve_plan(
    conn: Connection, managed_vm_id: UUID, cfg: RenewalConfig, *, policy_row: Mapping[Any, Any]
) -> dict[str, Any]:
    """Resolve the profile against the latest inventory (no OpenStack call in the api; the run re-validates live).

    Raises :class:`DomainError` (422/409) with a ``next_action`` on any ambiguity: unique image match, existing
    flavor, FIP on blue's port, volume present, config keys set.
    """
    vm = (
        conn.execute(text("SELECT * FROM managed_vm WHERE id = :id"), {"id": managed_vm_id})
        .mappings()
        .first()
    )
    if vm is None or vm["role"] != "current":
        raise _err(
            409,
            "not-current-vm",
            "Not the current VM",
            "Only the service's current VM can be renewed.",
        )
    if not vm["ssh_host_key_fingerprint"] or vm["host_key_confirmed_at"] is None:
        # Blue is reached over SSH with StrictHostKeyChecking against this fingerprint only (ADR-0006): without
        # a confirmed one, the run would stop at its first step on blue ("host key unverifiable").
        raise _err(
            409, "host-key-unconfirmed", "Host key not confirmed",
            "The current VM's SSH host-key fingerprint has not been scanned and confirmed.",
            "Wait for the host-key scan started at registration (or POST /api/v1/managed-vms/{id}/host-key-scans), "
            "compare the fingerprint with the VM's console, then POST /api/v1/managed-vms/{id}/host-key/confirm.",
        )  # fmt: skip
    svc = (
        conn.execute(text("SELECT * FROM service WHERE id = :id"), {"id": vm["service_id"]})
        .mappings()
        .one()
    )
    pc = svc["project_connection_id"]
    prof = (
        conn.execute(text("SELECT * FROM profile WHERE service_id = :s"), {"s": svc["id"]})
        .mappings()
        .first()
    )
    if prof is None or not prof["latest_version"]:
        raise _err(
            409,
            "no-profile",
            "No profile",
            "The service has no profile version.",
            "Create a profile.",
        )
    pv = (
        conn.execute(
            text("SELECT * FROM profile_version WHERE profile_id = :p AND number = :n"),
            {"p": prof["id"], "n": prof["latest_version"]},
        )
        .mappings()
        .one()
    )
    spec = pv["spec"]
    blue = _observed(conn, "server", pc, vm["openstack_server_id"])
    if blue is None:
        raise _err(
            409, "blue-not-observed", "VM not in inventory", "Sync the project inventory first."
        )

    img_rule = spec["image"]
    if img_rule.get("properties"):
        raise _err(
            422, "image-properties-unsupported", "Image match by properties",
            "This release can match images by name only (image properties are not in the inventory).",
            "Use image.name in the profile.",
        )  # fmt: skip
    images = (
        conn.execute(
            text(
                "SELECT openstack_id, name, owner_id, visibility FROM observed_image WHERE project_connection_id = :pc "
                "AND status = 'present' AND image_status = 'active' AND name = :n"
            ),
            {"pc": pc, "n": img_rule["name"]},
        )
        .mappings()
        .all()
    )
    if len(images) != 1:
        raise _err(
            422, "image-ambiguous", "Image not unique",
            f"{len(images)} active images match the profile's image name; exactly one is required (SEC-R-29).",
            "Make the image name unique or change the profile.",
        )  # fmt: skip
    flavors = (
        conn.execute(
            text(
                "SELECT openstack_id, name, disk FROM observed_flavor WHERE project_connection_id = :pc "
                "AND status = 'present' AND name = :n"
            ),
            {"pc": pc, "n": spec["flavor"]},
        )
        .mappings()
        .all()
    )
    if len(flavors) != 1:
        raise _err(
            422,
            "flavor-ambiguous",
            "Flavor not unique",
            f"{len(flavors)} flavors match the profile.",
        )
    if not flavors[0]["disk"]:
        raise _err(
            422,
            "flavor-zero-disk",
            "Flavor has no disk",
            "Green boots from image: flavor disk must be > 0.",
        )

    fip_id = str(spec["cutover"]["floating_ip_id"])
    fip = _observed(conn, "floating_ip", pc, fip_id)
    blue_ports = (
        conn.execute(
            text(
                "SELECT openstack_id FROM observed_port WHERE project_connection_id = :pc AND status = 'present' "
                "AND device_id = :d"
            ),
            {"pc": pc, "d": vm["openstack_server_id"]},
        )
        .scalars()
        .all()
    )
    if fip is None or fip["port_id"] not in blue_ports:
        raise _err(
            409,
            "fip-not-on-blue",
            "Floating IP not on the VM",
            "The cutover FIP must be on the VM's port.",
        )

    data_volume = None
    az = blue["availability_zone"]
    if spec.get("data_volume"):
        dv = spec["data_volume"]
        vol = _observed(conn, "volume", pc, str(dv["volume_id"]))
        if vol is None:
            raise _err(
                409,
                "volume-not-observed",
                "Data volume not in inventory",
                "Sync the inventory first.",
            )
        az = (
            vol["availability_zone"]
            if spec.get("availability_zone", "from_volume") == "from_volume"
            else az
        )
        data_volume = {
            "volume_id": str(dv["volume_id"]),
            "fs_type": dv["fs_type"],
            "fs_uuid": str(dv["fs_uuid"]) if dv.get("fs_uuid") else None,
            "label": dv.get("label"),
            "mount_point": dv["mount_point"],
            "snapshot_before_handoff": bool(dv.get("snapshot_before_handoff", False)),
            "size": vol["size"],
        }
    elif spec.get("availability_zone", "from_volume") != "from_volume":
        az = spec["availability_zone"]
    snapshot = bool(data_volume and data_volume["snapshot_before_handoff"])
    stateless = data_volume is None
    missing = cfg.missing(snapshot=snapshot)
    if missing:
        raise _err(
            409, "renewal-config-incomplete", "Renewal configuration incomplete",
            "These configuration keys have no value (defaults are set from lab measurements): "
            + ", ".join(missing), "Ask an admin to set them in the OVLM configuration.",
        )  # fmt: skip
    units = spec["automation"].get("inventory_vars", {}).get("service_units", [])
    return {
        "scope": f"project:{pc}",
        "service": {"id": str(svc["id"]), "slug": svc["slug"], "project_connection_id": str(pc)},
        "blue": {
            "managed_vm_id": str(vm["id"]),
            "server_id": vm["openstack_server_id"],
            "name": blue["name"],
            "port_id": fip["port_id"],
            "host_key_fingerprint": vm["ssh_host_key_fingerprint"],
        },
        "image": {
            "id": images[0]["openstack_id"],
            "name": images[0]["name"],
            "owner": images[0]["owner_id"],
            "visibility": images[0]["visibility"],
        },
        "flavor": {"id": flavors[0]["openstack_id"], "name": flavors[0]["name"]},
        "network_id": str(spec["network"]["network_id"]),
        "subnet_id": str(spec["network"]["subnet_id"]),
        # Names, not ids: the adapter has no security-group read and creates by name (reported deviation).
        "security_groups": list(spec["security_groups"]),
        "availability_zone": az,
        "floating_ip": {"id": fip_id, "address": fip["floating_ip_address"]},
        "data_volume": data_volume,
        "stateless": stateless,
        "service_units": [str(u) for u in units] if isinstance(units, list) else [],
        "automation": {
            k: spec["automation"].get(k)
            for k in ("repo", "sha", "playbook_dir", "requirements", "store_diffs")
        },
        "guest_access": spec["guest_access"],
        "health_check": spec["health_check"],
        "first_use": False,
        "auto_restore_in_window": bool(policy_row["auto_restore_in_window"]),
        "max_window_duration_seconds": int(policy_row["max_window_duration_seconds"]),
        "worst_case_window_seconds": cfg.worst_case_window(snapshot=snapshot, stateless=stateless),
        "profile_version": {
            "id": str(pv["id"]),
            "number": pv["number"],
            "spec_hash": pv["spec_hash"],
        },
    }


def green_name(resolved: Mapping[str, Any], run_id: str) -> str:
    """Intended name of green (ADR-0005 s.3): the service slug and the run id, unique per run."""
    return f"{resolved['service']['slug']}-ovlm-{run_id[-12:]}"


def blast_radius(resolved: Mapping[str, Any], gate: str) -> dict[str, Any]:
    """What the approver sees and approves (api-design.md 4, renewal-workflow.md 3)."""
    snap = bool((resolved.get("data_volume") or {}).get("snapshot_before_handoff"))
    out: dict[str, Any] = {
        "service": resolved["service"]["slug"],
        "vms": [
            {
                "role": "blue",
                "name": resolved["blue"]["name"],
                "openstack_id": resolved["blue"]["server_id"],
            }
        ],
        "volume": (resolved.get("data_volume") or {}).get("volume_id"),
        "floating_ip": resolved["floating_ip"]["address"],
    }
    if gate == "cutover":
        out |= {
            "outage_start": "at quiesce of the current VM (step W1), after green is proven ready (B9)",
            "worst_case_window_seconds": resolved["worst_case_window_seconds"],
            "max_window_duration_seconds": resolved["max_window_duration_seconds"],
            "snapshot": "yes: a pre-handoff snapshot is taken (a manual way back; OVLM never deletes it)"
            if snap
            else "no: revert carries green's writes forward",
            "automatic_restore": (
                "on a failure listed in the closed table OVLM automatically restores service to blue (stop green, "
                "move volume and FIP back, start blue); "
                + (
                    "after the service starts on green a failure is restored automatically; the pre-handoff "
                    "snapshot is kept"
                    if snap
                    else "after the service starts on green a failure stops and pages an operator"
                )
            )
            if resolved["auto_restore_in_window"]
            else "automatic restore is off: every failure in the window stops and pages an operator",
        }
    return out


def now_db(conn: Connection) -> datetime:
    value: datetime = conn.execute(text("SELECT now()")).scalar_one()
    return value


def tc_target(
    conn: Connection, run_id: str, kind: str, phase: str, resolved: Mapping[str, Any]
) -> str:
    """TC of the VM a run action affects: green in the build phase (once it exists) and for discard; blue
    otherwise (api-design.md 4). Shared by the api (checked on request) and the worker (re-validated)."""
    g = (
        conn.execute(
            text(
                "SELECT intended_name, openstack_id FROM owned_resource WHERE run_id = :r AND role = 'green' "
                "ORDER BY created_at DESC LIMIT 1"
            ),
            {"r": run_id},
        )
        .mappings()
        .first()
    )
    green_tc = (
        tc_of(g["intended_name"], g["openstack_id"])
        if g is not None and g["openstack_id"]
        else None
    )
    phase = effective_phase(phase, *outage_marks(conn, run_id))
    if kind == "discard" or (kind in ("rollback", "abort") and phase == "build" and green_tc):
        return green_tc or ""
    return tc_of(resolved["blue"]["name"], resolved["blue"]["server_id"])


def outage_marks(conn: Connection, run_id: str) -> tuple[Any, Any]:
    """``(downtime_started_at, downtime_ended_at)`` of the run."""
    row = conn.execute(
        text("SELECT downtime_started_at, downtime_ended_at FROM workflow_run WHERE id = :r"),
        {"r": run_id},
    ).first()
    return (None, None) if row is None else (row[0], row[1])


def effective_phase(phase: str | None, downtime_started_at: Any, downtime_ended_at: Any) -> str:
    """The phase a run action must be judged in (REN-1). Once W1 claimed (``downtime_started_at`` written, in the
    same transaction that precedes the quiesce play), the run is inside the outage until ``downtime_ended_at``: a
    stored ``build`` phase there is never trusted (blue may be quiesced), so it reads as ``window`` and every
    rollback/abort restores blue instead of discarding green. Shared by the api (actions, TC) and the worker."""
    p = phase or "build"
    if p == "build" and downtime_started_at is not None and downtime_ended_at is None:
        return "window"
    return p
