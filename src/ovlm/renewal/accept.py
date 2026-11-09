"""``accept-step``: an approver accepts a parked restore step without running its playbook (ADR-0008, roadmap P0-2).

A run pins its automation repository; nothing can change the pin inside the window. When the pinned playbook of a
restore step refuses a state that is safe (lab finding D-8: an old ``quiesce.yml`` that refuses "never mounted"),
retry-step and mark-resolved re-run the same playbook and reprepare-automation re-clones the same SHA: no OVLM path
is left. accept-step is that path, kept narrow:

* **Steps**: allowlist in code, :data:`STEP_KEYS` = S2 ``quiesce_green`` only (maintainer decision Q2). Phase
  ``restore`` (effective) only; never a window step, never a step that moves the volume or the FIP.
* **Parked reason**: the step's own playbook ran and refused (:func:`applies_to`: ``quiesce_green_failed`` with the
  classification the playbook reported, ``needs_human`` or ``fatal``). Not ``data_phase_interrupted`` (retry-step is
  the exit, Q3), not a lost or unverifiable checkout (reprepare-automation), not approval, ownership, lock, fence or
  ``api_unreachable`` refusals.
* **Who**: an approver in the run's scope, human interactive session, never the run's requester (run starter, plan
  creator), whatever ``auth.allow_operator_approver`` says; consumed password+TOTP step-up bound to
  :data:`STEPUP_ACTION` and the run; typed confirmation of green; an attestation of 20 to 2,000 characters.
* **OVLM verifies**: its own read-only probe (:func:`evaluate`) must meet S2's postcondition: green ``ACTIVE`` with no
  task state, the data volume ``in-use`` with exactly one attachment, on green; over SSH (fixed command list, never
  repository code) green reachable, the data device (by-id) mounted nowhere, the mount point not a mount, every
  service unit ``inactive`` or ``failed``. The probe shown to the approver (:data:`TRUTH_KEY` in the run's current
  truth, with its id, the DB time it **started** and its duration, review PMR-4) must be at most
  :data:`FRESH_SECONDS` old at commit, and the worker's own probe, taken
  just before the transaction, must show the same facts.
* **Effect** (worker, one transaction): the step is closed ``succeeded`` with ``resolution = accepted`` (playbook not
  run), compare-and-set on ``(needs_human, attempt)``, the parked attempt's fencing token is retired; the run goes on
  with the next restore step (S3 stops green). Once per (run, step); one pending accept per run. Pin, plan hash,
  approvals, locks and leases are unchanged; no git contact; no guest mutation.

Every decision of the worker is a ``step_acceptance`` row (append-only) and an audit row ``run.accept_step.accepted``
or ``run.accept_step.refused`` (with its code); the api audits ``run.accept_step.requested``.

Imported by the api (available actions, request checks) and the worker; no adapter import here.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.workflow.ids import new_id

#: Steps accept-step may close (maintainer decision Q2: S2 only).
STEP_KEYS = frozenset({"quiesce_green"})
#: The parked step's ``error.reason`` when its playbook ran and failed.
REFUSED_REASON: Mapping[str, str] = {"quiesce_green": "quiesce_green_failed"}
#: Classifications a playbook reports when it refuses (contract section 6); ``retryable`` is not a refusal.
PLAYBOOK_REFUSALS = frozenset({"needs_human", "fatal"})
FRESH_SECONDS = 60.0
ATTESTATION_MIN, ATTESTATION_MAX = 20, 2000
STEPUP_ACTION = "run.accept_step"
#: Key of the accept probe in ``workflow_run.current_truth``.
TRUTH_KEY = "accept_probe"
STOPPED_UNIT_STATES = frozenset({"inactive", "failed"})
ENTITY = "step_acceptance"

# Refusal codes (api problem codes and ``step_acceptance.refusal_code``).
FORBIDDEN = "forbidden"
SOD = "sod-violation"
NOT_APPLICABLE = "not-applicable"
ALREADY = "already-accepted"
PENDING = "accept-pending"
ATTESTATION = "attestation-invalid"
CONFIRMATION = "confirmation-mismatch"
STEPUP = "stepup-invalid"
PROBE_STALE = "probe-stale"
PROBE_MISMATCH = "probe-mismatch"
POSTCONDITION = "postcondition-not-met"

audit.register_entity(
    ENTITY,
    [
        "run_id", "step_key", "attempt", "approver", "signal_id", "outcome", "refusal_code", "refusal",
        "pinned_sha", "parked_reason", "refused_result_sha256", "probe_id", "probe_summary", "auth_method",
    ],
)  # fmt: skip


# --- applicability ----------------------------------------------------------------------------------------------


def applies_to(step_key: str | None, error: Mapping[str, Any] | None) -> bool:
    """Whether a parked step is an allowlisted step stopped because **its playbook ran and refused**."""
    if step_key not in STEP_KEYS or not isinstance(error, Mapping):
        return False
    return (
        error.get("reason") == REFUSED_REASON[step_key]
        and error.get("playbook_reported") in PLAYBOOK_REFUSALS
    )


def not_applicable(
    *, run_state: str | None, step_key: str | None, step_state: str | None, phase: str,
    error: Mapping[str, Any] | None,
) -> str | None:  # fmt: skip
    """Why accept-step does not apply to the run as it stands (``None``: it applies)."""
    if run_state != "needs_human" or step_state != "needs_human" or not step_key:
        return "the run is not stopped on a parked step"
    if phase != "restore":
        return f"accept-step applies only in the restore phase (the run is in {phase}); there the exit is rollback"
    if step_key not in STEP_KEYS:
        return f"accept-step is not allowed for step {step_key} (allowed: S2 quiesce_green)"
    if not applies_to(step_key, error):
        reason = (error or {}).get("reason") if isinstance(error, Mapping) else None
        return (
            f"the step is parked on {reason or 'an unknown reason'}, not because its playbook ran and refused; "
            "accept-step applies only to a playbook refusal"
        )
    return None


def attestation_problem(value: str | None) -> str | None:
    n = len((value or "").strip())
    if n < ATTESTATION_MIN or n > ATTESTATION_MAX:
        return (
            f"the attestation must be {ATTESTATION_MIN} to {ATTESTATION_MAX} characters: say what you checked "
            "and why the playbook's refusal is wrong"
        )
    return None


def refused_result_sha256(error: Mapping[str, Any] | None) -> str:
    """SHA-256 of the refused phase result as the step recorded it (its ``error``), canonical JSON."""
    raw = json.dumps(dict(error or {}), sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


# --- the postcondition --------------------------------------------------------------------------------------------


def evaluate(
    *,
    cloud: Mapping[str, Any],
    guest: Mapping[str, Any],
    green_id: str | None,
    units: Sequence[str],
) -> list[dict[str, Any]]:
    """S2's postcondition, check by check, from OVLM's own read-only probe. Every unknown counts as not met."""
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    green = cloud.get("green") or {}
    vol = cloud.get("volume") or {}
    check("cloud_reachable", bool(cloud.get("api_reachable")), "OpenStack answered the read calls")
    check("green_active", bool(green_id) and green.get("status") == "ACTIVE" and green.get("task_state") is None,
          f"green {green.get('status')}, task state {green.get('task_state')}")  # fmt: skip
    attached = list(vol.get("attached_to") or [])
    check("volume_on_green_only", bool(vol) and vol.get("status") == "in-use" and attached == [green_id],
          f"volume {vol.get('status')}, attached to {attached or 'nothing'}")  # fmt: skip
    check("guest_reachable", guest.get("reachable") is True, "green answered over SSH")
    dev = guest.get("device_mounted")
    where = ", ".join(guest.get("device_mountpoints") or ()) or "nowhere"
    check("data_device_mounted_nowhere", dev is False,
          "data device state unknown" if dev is None else f"data device mounted {where}")  # fmt: skip
    mp = guest.get("mount_point_mounted")
    check("mount_point_not_a_mount", mp is False,
          f"{guest.get('mount_point')}: " + ("unknown" if mp is None else ("a mount" if mp else "not a mount")))  # fmt: skip
    states = dict(guest.get("unit_states") or {})
    bad = {u: states.get(u, "unknown") for u in units if states.get(u) not in STOPPED_UNIT_STATES}
    check("service_units_stopped", not bad,
          "every unit inactive or failed" if not bad else "; ".join(f"{u} {s}" for u, s in bad.items()))  # fmt: skip
    return checks


def failing(probe: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(probe, Mapping):
        return ["no probe"]
    return [
        f"{c['check']}: {c['detail']}" for c in probe.get("checks") or () if not c.get("ok")
    ] or ([] if probe.get("ok") else ["probe failed"])


def facts(probe: Mapping[str, Any]) -> dict[str, Any]:
    """What two probes must agree on (the probe shown to the approver and the worker's fresh one)."""
    return {"cloud": probe.get("cloud"), "guest": probe.get("guest")}


def shown_probe(truth: Any) -> Mapping[str, Any] | None:
    if not isinstance(truth, Mapping):
        return None
    probe = truth.get(TRUTH_KEY)
    return probe if isinstance(probe, Mapping) else None


def probe_age(probe: Mapping[str, Any] | None, now: datetime) -> float | None:
    """Seconds since the probe started (its ``at``, DB clock read before the first read call, review PMR-4);
    ``None`` when it has no time."""
    if not isinstance(probe, Mapping) or not probe.get("at"):
        return None
    try:
        at = datetime.fromisoformat(str(probe["at"]))
    except ValueError:
        return None
    return (now - at).total_seconds()


def summary(probe: Mapping[str, Any] | None) -> str:
    """One line for the audit row and the badge."""
    if not isinstance(probe, Mapping):
        return "no probe"
    if probe.get("ok"):
        g = probe.get("guest") or {}
        return (
            f"volume attached to green only, data device mounted nowhere, {g.get('mount_point')} not a mount, "
            "units inactive"
        )
    return "; ".join(failing(probe))[:500]


def effect(probe: Mapping[str, Any], volume_id: str | None, step_key: str) -> str:
    return (
        f"accept {step_key} without running quiesce.yml. OVLM checked at {probe.get('at')} (probe "
        f"{str(probe.get('id'))[:8]}): volume {volume_id} attached to green only, mounted nowhere on green, units "
        "inactive. Next: S3 stops green, S4 detaches the volume, S5 attaches it to blue"
    )


# --- rows ------------------------------------------------------------------------------------------------------


def pending(c: Any, run_id: str, kind: str = "accept_step") -> bool:
    """A request of ``kind`` (``accept_step``, or ``probe``: PMR-1) of the run not yet applied by the worker (one
    pending accept, and one pending probe, per run)."""
    return (
        c.execute(
            text(
                "SELECT 1 FROM run_signal WHERE run_id = :r AND kind = :k AND consumed_at IS NULL"
            ),
            {"r": run_id, "k": kind},
        ).first()
        is not None
    )


def already_accepted(c: Any, run_id: str, step_key: str) -> bool:
    return (
        c.execute(
            text(
                "SELECT 1 FROM step_acceptance WHERE run_id = :r AND step_key = :k AND outcome = 'accepted'"
            ),
            {"r": run_id, "k": step_key},
        ).first()
        is not None
    )


def accepted(c: Any, run_id: str) -> list[dict[str, Any]]:
    """The run's accepted steps with who and when (the run summary and the step badge). ``c``: Connection or
    Session."""
    rows = c.execute(
        text("SELECT a.id, a.step_id, a.step_key, a.attempt, a.approver_id, u.username AS approver, a.created_at, "
             "a.attestation, a.probe_id, a.refused_result_sha256 FROM step_acceptance a "
             "LEFT JOIN app_user u ON u.id = a.approver_id "
             "WHERE a.run_id = :r AND a.outcome = 'accepted' ORDER BY a.created_at"),
        {"r": run_id},
    ).mappings().all()  # fmt: skip
    return [
        {k: (v.isoformat() if isinstance(v, datetime) else (str(v) if isinstance(v, UUID) else v))
         for k, v in r.items()}
        for r in rows
    ]  # fmt: skip


def record(
    c: Connection, *, outcome: str, run_id: str, signal_id: str, approver_id: str, step_id: str | None,
    step_key: str | None, attempt: int | None, attestation: str, pinned_sha: str | None = None,
    parked_reason: str | None = None, refused_sha256: str | None = None, probe: Mapping[str, Any] | None = None,
    probe_id: str | None = None, probe_elapsed: float = 0.0, refusal_code: str | None = None,
    refusal: str | None = None,
) -> str:  # fmt: skip
    """Append one ``step_acceptance`` row and its audit row, in the signal's transaction."""
    aid = new_id()
    c.execute(
        text("INSERT INTO step_acceptance (id, run_id, signal_id, step_id, step_key, attempt, approver_id, pinned_sha, "
             "parked_reason, refused_result_sha256, probe_id, probe, probed_at, attestation, outcome, refusal_code, "
             "refusal) VALUES (:i, :r, :s, :st, :k, :att, :a, :sha, :pr, :rs, :pid, CAST(:p AS jsonb), "
             "CASE WHEN CAST(:p AS jsonb) IS NULL THEN NULL ELSE now() - make_interval(secs => :el) END, "
             ":txt, :o, :code, :why)"),
        {"i": aid, "r": run_id, "s": signal_id, "st": step_id, "k": step_key, "att": attempt, "a": approver_id,
         "sha": pinned_sha, "pr": parked_reason, "rs": refused_sha256, "pid": probe_id,
         "p": json.dumps(dict(probe), default=str) if probe is not None else None, "el": min(max(float(probe_elapsed), 0.0), 86400.0),
         "txt": (attestation or "")[:ATTESTATION_MAX], "o": outcome, "code": refusal_code,
         "why": (refusal or "")[:500] or None},
    )  # fmt: skip
    ok = outcome == "accepted"
    with Session(bind=c) as s:
        audit.record(
            s, action="run.accept_step." + ("accepted" if ok else "refused"), target_type=ENTITY, target_id=aid,
            result="success" if ok else "denied", actor_id=UUID(approver_id), principal_type="human",
            auth_method="password+totp", run_id=UUID(run_id), step_id=UUID(step_id) if step_id else None,
            authority_ref=f"run_signal:{signal_id}",
            after={"run_id": run_id, "step_key": step_key, "attempt": attempt, "approver": approver_id,
                   "signal_id": signal_id, "outcome": outcome, "refusal_code": refusal_code,
                   "refusal": (refusal or "")[:200] or None, "pinned_sha": pinned_sha, "parked_reason": parked_reason,
                   "refused_result_sha256": refused_sha256, "probe_id": probe_id,
                   "probe_summary": summary(probe) if probe is not None else None, "auth_method": "password+totp"},
        )  # fmt: skip
    return aid
