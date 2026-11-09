"""Renewal plans, approvals, runs and run actions for the api (api-design.md 3.6, 3.7, 4). Api-safe module.

The api never acts on OpenStack: it inserts a plan, approval rows, a run in ``requested`` and ``run_signal`` rows,
and the worker re-validates everything before acting (SEC-R-1). What the api checks here is what it can check for
a clear early answer: scope, role, human session, the single-use TOTP step-up bound to (action, target), the typed
confirmation against current DB values (``422 confirmation-mismatch``), SoD (``403 sod-violation``), the bound hash
(``409 approval-voided``). Every write is audited in the same transaction.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.authz import authorize
from ovlm.auth.errors import ProblemError
from ovlm.auth.events import record_independent
from ovlm.auth.principal import Principal
from ovlm.auth.sod import Gate, account_provenance, check_approval_eligibility
from ovlm.auth.stepup import consume_stepup
from ovlm.policies.service import effective_policy
from ovlm.profiles.waivers import active_waivers, for_display, hash_binding
from ovlm.registry.errors import DomainError
from ovlm.renewal import accept, downtime, reprepare
from ovlm.renewal.config import RenewalConfig
from ovlm.renewal.evidence import APPROVAL_STEPUP_ACTION, CUTOVER_STEPUP_ACTION
from ovlm.renewal.plans import (
    KIND,
    STRATEGY,
    STRATEGY_VERSION,
    blast_radius,
    compute_plan_hash,
    effective_phase,
    load_facts,
    policy_binding,
    resolve_plan,
    tc_of,
    tc_target,
)
from ovlm.workflow.ids import new_id
from ovlm.workflow.requests import request_run, send_signal

TERMINAL = ("rejected", "cancelled", "failed", "completed", "rolled_back")
#: action path segment -> (signal kind, needs TC + step-up + human session)
ACTIONS: Mapping[str, tuple[str, bool]] = {
    "probe": ("probe", False),
    "retry-step": ("retry_step", False),
    "abort": ("abort", True),
    "rollback": ("rollback", True),
    "revert": ("revert", True),
    "discard": ("discard", True),
    "mark-resolved": ("mark_resolved", True),
    "reprepare-automation": ("reprepare_automation", True),
    "accept-step": ("accept_step", True),
}


def not_found(what: str) -> DomainError:
    return DomainError(
        404, f"{what}-not-found", f"{what.capitalize()} not found", f"No such {what}."
    )


def _audit(
    s: Session,
    who: Principal,
    action: str,
    target_type: str,
    target_id: str,
    scope: str | None,
    **after: Any,
) -> None:
    audit.record(
        s, action=action, target_type=target_type, target_id=target_id, actor_id=who.user_id,
        principal_type=who.principal_type, auth_method=who.auth_method, source_ip=who.source_ip,
        project_scope=scope, after=after or None,
    )  # fmt: skip


def _iso(v: Any) -> Any:
    return v.isoformat() if isinstance(v, datetime) else (str(v) if isinstance(v, UUID) else v)


def _row(r: Mapping[Any, Any]) -> dict[str, Any]:
    return {str(k): _iso(v) for k, v in r.items()}


# --- idempotency (api-design.md 1) ----------------------------------------------------------------------------


def body_hash(body: Any) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def replay(
    s: Session, who: Principal, key: str | None, method: str, path: str, bhash: str
) -> dict[str, Any] | None:
    if not key or not 8 <= len(key) <= 200:
        raise DomainError(400, "idempotency-key-required", "Idempotency-Key required",
                          "POSTs that start work need an Idempotency-Key header (8-200 characters).")  # fmt: skip
    row = s.execute(
        text(
            "SELECT method, path, body_hash, response FROM api_idempotency WHERE principal_id = :p AND key = :k"
        ),
        {"p": who.user_id, "k": key},
    ).first()
    if row is None:
        return None
    if (row.method, row.path, row.body_hash) != (method, path, bhash):
        raise DomainError(409, "idempotency-key-reuse", "Idempotency-Key reused",
                          "This key was used for a different request.")  # fmt: skip
    stored: dict[str, Any] = row.response
    return stored


def remember(
    s: Session, who: Principal, key: str, method: str, path: str, bhash: str, resp: Any
) -> None:
    s.execute(
        text("INSERT INTO api_idempotency (principal_id, key, method, path, body_hash, status, response) "
             "VALUES (:p, :k, :m, :path, :h, 202, CAST(:r AS jsonb))"),
        {"p": who.user_id, "k": key, "m": method, "path": path, "h": bhash, "r": json.dumps(resp, default=str)},
    )  # fmt: skip


# --- plans ------------------------------------------------------------------------------------------------------


def plan_scope(s: Session, plan_id: UUID, who: Principal) -> Mapping[Any, Any]:
    row = (
        s.execute(text("SELECT * FROM renewal_plan WHERE id = :i"), {"i": plan_id})
        .mappings()
        .first()
    )
    if row is None or not authorize(who, "viewer", row["resolved"]["scope"]):
        raise not_found("plan")
    return row


def plan_body(s: Session, row: Mapping[Any, Any]) -> dict[str, Any]:
    out = _row(row)
    out["blast_radius"] = blast_radius(row["resolved"], "plan")
    return out


def create_plan(
    s: Session, who: Principal, cfg: RenewalConfig, managed_vm_id: UUID, window: datetime | None
) -> dict[str, Any]:
    vm = s.execute(
        text("SELECT v.service_id, sv.project_connection_id FROM managed_vm v JOIN service sv ON sv.id = v.service_id "
             "WHERE v.id = :i"), {"i": managed_vm_id}).first()  # fmt: skip
    scope = f"project:{vm.project_connection_id}" if vm else None
    if vm is None or not authorize(who, "operator", scope):
        raise not_found("managed-vm")
    eff = effective_policy(s, vm.service_id)
    if not eff or not eff["policy"]:
        raise DomainError(
            409, "no-policy", "No policy", "No policy applies to this service (FR-POL-4)."
        )
    prow = (
        s.execute(text("SELECT * FROM policy WHERE id = :i"), {"i": eff["policy"]["id"]})
        .mappings()
        .one()
    )
    conn = s.connection()
    resolved = resolve_plan(conn, managed_vm_id, cfg, policy_row=prow)
    pv = resolved["profile_version"]
    sha = s.execute(
        text("SELECT automation_sha FROM profile_version WHERE id = :i"), {"i": pv["id"]}
    ).scalar()
    phash = compute_plan_hash(resolved=resolved, profile_version_id=pv["id"], spec_hash=pv["spec_hash"],
                              automation_sha=sha, policy=policy_binding(prow),
                              lint_waivers=hash_binding(active_waivers(conn, pv["id"])))  # fmt: skip
    prev = s.execute(
        text("SELECT pl.resolved -> 'automation' ->> 'sha' FROM renewal_plan pl WHERE pl.service_id = :s "
             "AND pl.state IN ('approved', 'started') ORDER BY pl.created_at DESC LIMIT 1"),
        {"s": vm.service_id}).scalar()  # fmt: skip
    diff = {"previous_approved_sha": prev, "sha": sha,
            "summary": "first approval of this repo" if prev is None else ("unchanged" if prev == sha else "changed"),
            "changed_files": None, "note": "file-level diff is a worker job not in this release"}  # fmt: skip
    pid = new_id()
    s.execute(
        text("INSERT INTO renewal_plan (id, managed_vm_id, service_id, profile_version_id, policy_id, policy_version, "
             "resolved, automation_diff, plan_hash, planned_window_start, state, created_by) VALUES (:i, :vm, :s, "
             ":pv, :pol, :pver, CAST(:r AS jsonb), CAST(:d AS jsonb), :h, :w, 'draft', :u)"),
        {"i": pid, "vm": managed_vm_id, "s": vm.service_id, "pv": pv["id"], "pol": prow["id"],
         "pver": prow["version"], "r": json.dumps(resolved), "d": json.dumps(diff), "h": phash, "w": window,
         "u": who.user_id},
    )  # fmt: skip
    _audit(s, who, "plan.create", "renewal_plan", pid, scope, managed_vm_id=str(managed_vm_id),
           policy_version=prow["version"])  # fmt: skip
    return plan_body(
        s, s.execute(text("SELECT * FROM renewal_plan WHERE id = :i"), {"i": pid}).mappings().one()
    )


def request_approval(
    s: Session, who: Principal, *, gate: Gate, plan_id: str, run_id: str | None, scope: str
) -> dict[str, Any]:
    facts = load_facts(s.connection(), plan_id)
    if facts.recomputed_hash is None or facts.recomputed_hash != facts.plan["plan_hash"]:
        raise DomainError(409, "plan-stale", "Plan is stale", "The plan's profile version or policy changed.",
                          "Create a new plan.")  # fmt: skip
    starter = None
    if run_id:
        starter = s.execute(
            text("SELECT started_by FROM workflow_run WHERE id = :r"), {"r": run_id}
        ).scalar()
    rs = facts.requester_set(run_starter=starter, approval_requester=who.user_id, gate=gate)
    conflicts = rs.waiver_granter_conflicts()
    if conflicts:  # review SFR-3: whoever waived the lint does not also ask for the work it eases
        _audit(s, who, "approval.request.refused", "renewal_plan", plan_id, scope, subject_type=gate.value,
               reason="sod-waiver-granter: " + ", ".join(conflicts))  # fmt: skip
        s.commit()
        raise ProblemError(403, "sod-violation", "Separation of duties",
                           f"A lint waiver on this plan's profile version was granted by its {', '.join(conflicts)}: "
                           "whoever waives the lint must not also ask for the work it eases.",
                           next_action="Ask someone who granted no waiver on this version to create the plan and "
                           "request the approval, or revoke the waiver.")  # fmt: skip
    aid = new_id()
    subject = plan_id if gate is Gate.PLAN else run_id
    try:
        with s.begin_nested():
            s.execute(
                text("INSERT INTO approval (id, subject_type, subject_id, plan_id, run_id, scope, bound_hash, "
                     "hash_inputs, requester_set, requested_by) VALUES (:i, :t, :s, :p, :r, :scope, :h, "
                     "CAST(:hi AS jsonb), CAST(:rs AS uuid[]), :u)"),
                {"i": aid, "t": gate.value, "s": subject, "p": plan_id, "r": run_id, "scope": scope,
                 "h": facts.recomputed_hash, "u": who.user_id,
                 "hi": json.dumps({"resolved": facts.resolved, "policy": facts.policy,
                                   "automation_diff": facts.plan.get("automation_diff"),
                                   "lint_waivers": for_display(
                                       active_waivers(s.connection(), facts.plan["profile_version_id"]),
                                       facts.lint_waivers)}, default=str),
                 "rs": "{" + ",".join(str(u) for u in rs.members()) + "}"},
            )  # fmt: skip
    except Exception:  # unique index: one open request per subject
        raise DomainError(409, "approval-open", "Approval already requested",
                          "An open approval request exists for this subject.") from None  # fmt: skip
    if gate is Gate.PLAN:
        s.execute(text("UPDATE renewal_plan SET state = 'awaiting_approval', updated_at = now(), version = version + 1 "
                       "WHERE id = :p AND state = 'draft'"), {"p": plan_id})  # fmt: skip
    _audit(
        s,
        who,
        "approval.request",
        "approval",
        aid,
        scope,
        subject_type=gate.value,
        subject_id=str(subject),
    )
    return approval_body(s, aid)


def approval_body(s: Session, aid: str | UUID) -> dict[str, Any]:
    row = s.execute(text("SELECT * FROM approval WHERE id = :i"), {"i": aid}).mappings().one()
    plan = s.execute(
        text("SELECT resolved FROM renewal_plan WHERE id = :p"), {"p": row["plan_id"]}
    ).scalar_one()
    out = _row(row)
    out["blast_radius"] = blast_radius(plan, row["subject_type"])
    out["requester_set"] = [str(u) for u in row["requester_set"]]
    return out


def decide(
    s: Session, who: Principal, cfg: RenewalConfig, aid: UUID, *, decision: str, typed: str | None,
    comment: str | None, stepup_id: UUID,
) -> dict[str, Any]:  # fmt: skip
    row = (
        s.execute(text("SELECT * FROM approval WHERE id = :i FOR UPDATE"), {"i": aid})
        .mappings()
        .first()
    )
    if row is None or not authorize(who, "viewer", row["scope"]):
        raise not_found("approval")
    if row["decision"] is not None or row["void_reason"] is not None:
        raise DomainError(
            409,
            "approval-closed",
            "Approval closed",
            "This approval was already decided or voided.",
        )
    gate = Gate(row["subject_type"])
    facts = load_facts(s.connection(), str(row["plan_id"]))
    if facts.recomputed_hash != row["bound_hash"]:
        s.execute(text("UPDATE approval SET void_reason = 'bound hash changed', version = version + 1 WHERE id = :i"),
                  {"i": aid})  # fmt: skip
        _audit(s, who, "approval.voided", "approval", str(aid), row["scope"], decision="voided")
        s.commit()
        raise DomainError(409, "approval-voided", "Approval voided", "What it approved changed (plan hash).",
                          "Request a new approval.")  # fmt: skip
    starter = None
    if row["run_id"]:
        starter = s.execute(
            text("SELECT started_by FROM workflow_run WHERE id = :r"), {"r": row["run_id"]}
        ).scalar()
    prior: set[UUID] = set()
    if gate is not Gate.PLAN:
        for earlier in (Gate.PLAN, Gate.CUTOVER):
            if earlier is gate:
                break
            subj = row["plan_id"] if earlier is Gate.PLAN else row["run_id"]
            d = s.execute(
                text("SELECT decided_by FROM approval WHERE subject_type = :t AND subject_id = :s AND decision = "
                     "'approved' AND NOT operator_confirmed ORDER BY decided_at DESC LIMIT 1"),
                {"t": earlier.value, "s": subj}).scalar()  # fmt: skip
            if d:
                prior.add(d)
    elig = check_approval_eligibility(
        s, who, gate=gate, scope=row["scope"],
        requester_set=facts.requester_set(run_starter=starter, approval_requester=row["requested_by"], gate=gate),
        prior_gate_deciders=prior,
        require_distinct_approvers=bool((facts.policy or {}).get("require_distinct_approvers")),
    )  # fmt: skip
    if not elig.allowed:
        _audit(
            s, who, "approval.decide.refused", "approval", str(aid), row["scope"], decision=decision
        )
        s.commit()
        raise elig.problem()
    if gate is not Gate.PLAN and decision == "approved":
        expected = tc_of(facts.resolved["blue"]["name"], facts.resolved["blue"]["server_id"])
        if not hmac.compare_digest(" ".join((typed or "").split()), expected):
            raise DomainError(422, "confirmation-mismatch", "Typed confirmation does not match",
                              "Type the server name and the last 6 characters of its id.")  # fmt: skip
    consume_stepup(s, who, stepup_id, action=APPROVAL_STEPUP_ACTION, target_id=str(aid))
    validity = {Gate.PLAN: cfg.validity_plan, Gate.CUTOVER: cfg.validity_cutover}.get(
        gate, cfg.validity_retirement
    )
    if validity is None:
        raise DomainError(409, "renewal-config-incomplete", "Configuration incomplete",
                          "approval.validity.retirement is not configured.")  # fmt: skip
    s.execute(
        text("UPDATE approval SET decided_by = :u, decision = :d, typed_confirmation = :tc, auth_method = :am, "
             "stepup_id = :su, self_approved = :sa, account_provenance = CAST(:prov AS jsonb), comment = :c, "
             "decided_at = now(), expires_at = now() + make_interval(secs => :v), version = version + 1 "
             "WHERE id = :i"),
        {"u": who.user_id, "d": decision, "tc": typed, "am": who.auth_method, "su": stepup_id,
         "sa": elig.self_approved, "prov": json.dumps(account_provenance(s, who.user_id)), "c": comment,
         "v": float(validity), "i": aid},
    )  # fmt: skip
    if gate is Gate.PLAN and decision == "approved":
        s.execute(text("UPDATE renewal_plan SET state = 'approved', updated_at = now(), version = version + 1 "
                       "WHERE id = :p"), {"p": row["plan_id"]})  # fmt: skip
    if gate is not Gate.PLAN and row["run_id"]:
        send_signal(
            s.connection(),
            str(row["run_id"]),
            "approve",
            actor_id=str(who.user_id),
            approval_id=str(aid),
        )
    _audit(s, who, "approval.decide", "approval", str(aid), row["scope"], subject_type=gate.value,
           decision=decision, self_approved=elig.self_approved)  # fmt: skip
    return approval_body(s, aid)


def start(s: Session, who: Principal, plan_id: UUID) -> dict[str, Any]:
    plan = (
        s.execute(text("SELECT * FROM renewal_plan WHERE id = :i FOR UPDATE"), {"i": plan_id})
        .mappings()
        .first()
    )
    if plan is None or not authorize(who, "operator", plan["resolved"]["scope"]):
        raise not_found("plan")
    scope = plan["resolved"]["scope"]
    facts = load_facts(s.connection(), plan_id)
    if facts.recomputed_hash != plan["plan_hash"]:
        raise DomainError(
            409, "plan-stale", "Plan is stale", "The profile version or policy changed."
        )
    if ((facts.policy or {}).get("approvals") or {}).get("plan"):
        ok = s.execute(
            text("SELECT 1 FROM approval WHERE subject_type = 'plan' AND subject_id = :p AND decision = 'approved' "
                 "AND void_reason IS NULL AND expires_at > now() AND bound_hash = :h"),
            {"p": plan_id, "h": plan["plan_hash"]}).first()  # fmt: skip
        if ok is None:
            raise DomainError(
                409,
                "approval-missing",
                "Plan not approved",
                "A valid plan approval (G1) is required.",
            )
    level = s.execute(
        text("SELECT level FROM readiness_assessment WHERE managed_vm_id = :v ORDER BY created_at DESC LIMIT 1"),
        {"v": plan["managed_vm_id"]}).scalar()  # fmt: skip
    if level != "ready":
        raise DomainError(409, "readiness-not-ready", "VM not ready", f"Latest readiness level: {level or 'none'}.",
                          "Run a readiness assessment and fix the blockers.")  # fmt: skip
    busy = s.execute(
        text("SELECT id FROM workflow_run WHERE kind = :k AND service_id = :s AND NOT (state = ANY(:t))"),
        {"k": KIND, "s": plan["service_id"], "t": list(TERMINAL)}).scalar()  # fmt: skip
    if busy is not None:
        raise DomainError(
            409, "resource-locked", "Service busy", f"Run {busy} of this service is not finished."
        )
    run_id = request_run(
        s.connection(), kind=KIND, strategy=STRATEGY, strategy_version=STRATEGY_VERSION,
        service_id=str(plan["service_id"]), renewal_plan_id=str(plan_id), started_by=str(who.user_id),
    )  # fmt: skip
    _audit(s, who, "run.start", "renewal_run", run_id, scope, plan_id=str(plan_id))
    return run_body(s, run_id)


# --- runs ------------------------------------------------------------------------------------------------------


def run_row(s: Session, run_id: UUID | str, who: Principal) -> tuple[Mapping[Any, Any], Any]:
    run = (
        s.execute(
            text("SELECT * FROM workflow_run WHERE id = :i AND kind = :k"), {"i": run_id, "k": KIND}
        )
        .mappings()
        .first()
    )
    if run is None:
        raise not_found("run")
    resolved = s.execute(
        text("SELECT resolved FROM renewal_plan WHERE id = :p"), {"p": run["renewal_plan_id"]}
    ).scalar()
    if resolved is None or not authorize(who, "viewer", resolved["scope"]):
        raise not_found("run")
    return run, resolved


def _snapshot_id(s: Any, run_id: str) -> str | None:
    """The W4 snapshot of the run, once W4 succeeded (ledger ``present`` and the step ``succeeded``)."""
    value = s.execute(
        text("SELECT o.openstack_id FROM owned_resource o JOIN workflow_step w ON w.run_id = o.run_id "
             "AND w.step_key = 'snapshot_volume' AND w.state = 'succeeded' "
             "WHERE o.run_id = :r AND o.role = 'snapshot' AND o.state = 'present' LIMIT 1"),
        {"r": run_id},
    ).scalar()  # fmt: skip
    return str(value) if value else None


def _retire_sent(s: Any, run_id: str) -> bool:
    """X1 persisted its unlock + delete intent (REN-4): revert is no longer possible."""
    return (
        s.execute(
            text(
                "SELECT 1 FROM workflow_step WHERE run_id = :r AND step_key = 'retire_old' AND intent IS NOT NULL "
                "LIMIT 1"
            ),
            {"r": run_id},
        ).first()  # fmt: skip
        is not None
    )


def available_actions(
    run: Mapping[Any, Any],
    step: Mapping[Any, Any] | None,
    resolved: Mapping[str, Any],
    snapshot_id: str | None = None,
    *,
    retire_sent: bool = False,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Each action with the role it needs and its concrete effect from the current state (SRE-R-9). The phase is the
    effective one (REN-1): with the outage open a stored ``build`` phase reads ``window``, so the page offers the
    restore of blue, never "delete green"."""
    state, key = run["state"], step["step_key"] if step else None
    phase = effective_phase(
        run["phase"], run.get("downtime_started_at"), run.get("downtime_ended_at")
    )
    out: list[dict[str, Any]] = []
    if state == "requested":
        return [
            {
                "action": "abort",
                "role": "operator",
                "effect": "waiting for worker admission; abort cancels it",
            }
        ]
    if state in TERMINAL:
        return []
    out.append(
        {
            "action": "probe",
            "role": "operator or approver",
            "effect": "read-only re-probe; refreshes the current truth",
        }
    )
    if state == "needs_human":
        out.append(
            {
                "action": "retry-step",
                "role": "operator",
                "effect": f"re-run {key} (starts with a probe)",
            }
        )
        out.append({"action": "mark-resolved",
                    "role": "operator (+approver if the current or next step is destructive)",
                    "effect": f"state the manual fix for {key}; the engine re-probes"})  # fmt: skip
        if step is not None and reprepare.applies_to(step.get("error")):
            out.append({"action": "reprepare-automation",
                        "role": "approver (not the run's requester) + TC",
                        "effect": f"authorize ONE re-clone of the pinned SHA inside the window (the only git contact "
                                  f"allowed there); its tree must match B6's digest; {key} is retried"})  # fmt: skip
        if (offer := _accept_offer(run, step, phase, now)) is not None:
            out.append(offer)
    snap = bool((resolved.get("data_volume") or {}).get("snapshot_before_handoff"))
    if phase == "build":
        out.append(
            {
                "action": "rollback",
                "role": "operator + TC",
                "effect": "delete green; blue keeps serving",
            }
        )
        out.append(
            {
                "action": "abort",
                "role": "operator + TC",
                "effect": "stop at the step boundary; delete green",
            }
        )
    elif phase == "window":
        # renewal-workflow.md 4.1 (D-1): name the snapshot when one reached ``available`` in W4, else say none exists
        consequence = ("stop green, attach the volume to blue, start blue, move the FIP back to blue; "
                       + (f"the pre-handoff snapshot {snapshot_id} is kept as a manual way back (OVLM never "
                          "deletes it)" if snap and snapshot_id else
                          "blue will start on data the new VM may have changed; no snapshot exists"))  # fmt: skip
        out.append({"action": "rollback", "role": "operator + TC", "effect": consequence})
        out.append(
            {
                "action": "abort",
                "role": "operator + TC",
                "effect": "current step finishes, then " + consequence,
            }
        )
    elif phase in ("retained", "retire") and retire_sent:
        out.append({"action": "revert", "role": "unavailable",
                    "effect": "revert impossible: X1 has sent (or may have sent) the delete of the old VM; "
                              "retry-step lets X1 finish"})  # fmt: skip
    elif phase in ("retained", "retire"):
        out.append({"action": "revert", "role": "operator + TC",
                    "effect": "restore to blue (FIP and volume back); voids any retirement approval"})  # fmt: skip
    elif key == "await_discard":
        out.append(
            {
                "action": "discard",
                "role": "operator + TC of green",
                "effect": "delete the stopped green",
            }
        )
    return out


def _accept_offer(
    run: Mapping[Any, Any], step: Mapping[Any, Any] | None, phase: str, now: datetime | None
) -> dict[str, Any] | None:
    """accept-step (ADR-0008): absent unless the run is parked on an allowlisted restore step whose playbook ran and
    refused; then offered only while OVLM's last probe of the postcondition is fresh and meets it, otherwise listed
    as unavailable with the reason (press Probe, or the failing check)."""
    if step is None or accept.not_applicable(
        run_state=run["state"], step_key=step.get("step_key"), step_state=step.get("state"), phase=phase,
        error=step.get("error"),
    ) is not None:  # fmt: skip
        return None
    role = "approver (not the run's requester) + TC of green + attestation"
    probe = accept.shown_probe(run.get("current_truth"))
    age = accept.probe_age(probe, now) if (probe is not None and now is not None) else None
    why = None
    if (
        probe is None
        or str(probe.get("step_id")) != str(step.get("id"))
        or probe.get("attempt") != step.get("attempt")
    ):
        why = (f"press Probe first: accept-step needs OVLM's own read-only probe of {step['step_key']}'s "
               f"postcondition, at most {int(accept.FRESH_SECONDS)} s old")  # fmt: skip
    elif age is None or age > accept.FRESH_SECONDS:
        why = f"the last probe is {int(age or 0)} s old: press Probe (it must be at most {int(accept.FRESH_SECONDS)} s old)"
    elif not probe.get("ok"):
        why = "not offered: OVLM's probe does not show the postcondition: " + "; ".join(
            accept.failing(probe)
        )
    if why is not None:
        return {"action": "accept-step", "role": role, "available": False, "effect": why}
    assert probe is not None  # noqa: S101 - checked above
    return {"action": "accept-step", "role": role, "available": True,
            "effect": accept.effect(probe, probe.get("volume_id"), step["step_key"]),
            "probe_id": str(probe.get("id")), "step_id": str(step.get("id"))}  # fmt: skip


def run_body(s: Session, run_id: UUID | str) -> dict[str, Any]:
    run = (
        s.execute(text("SELECT * FROM workflow_run WHERE id = :i"), {"i": run_id}).mappings().one()
    )
    resolved = s.execute(
        text("SELECT resolved FROM renewal_plan WHERE id = :p"), {"p": run["renewal_plan_id"]}
    ).scalar_one()
    step = s.execute(
        text("SELECT id, step_key, state, attempt, lease_owner, lease_expires_at, heartbeat_at, deadline_at, error "
             "FROM workflow_step WHERE run_id = :r AND state IN ('ready','running','waiting','needs_human')"),
        {"r": run_id}).mappings().first()  # fmt: skip
    locks = s.execute(text("SELECT resource_type, resource_key FROM resource_lock WHERE holder_run_id = :r"),
                      {"r": run_id}).all()  # fmt: skip
    pending = s.execute(text("SELECT kind, actor_id, created_at FROM run_signal WHERE run_id = :r AND consumed_at IS "
                             "NULL ORDER BY created_at"), {"r": run_id}).mappings().all()  # fmt: skip
    hb = s.execute(text("SELECT max(last_seen_at) FROM worker_heartbeat")).scalar()
    now = s.execute(text("SELECT now()")).scalar_one()
    body = _row(run)
    body |= {
        "downtime": downtime_body(s, run),
        "current_step": _row(step) if step else None,
        "locks": [{"resource_type": t, "resource_key": k} for t, k in locks],
        "pending_signals": [_row(p) for p in pending],
        "worst_case_window_seconds": resolved["worst_case_window_seconds"],
        "max_window_duration_seconds": resolved["max_window_duration_seconds"],
        # ADR-0008: a step closed by accept-step ran no playbook; every view of the run says so
        "accepted_steps": accept.accepted(s, str(run_id)),
        "available_actions": available_actions(
            run,
            step,
            resolved,
            _snapshot_id(s, str(run_id)),
            retire_sent=_retire_sent(s, str(run_id)),
            now=now,
        ),
        "last_worker_heartbeat": _iso(hb),
        "links": {"steps": f"/api/v1/runs/{run_id}/steps"},
    }
    return body


def downtime_body(s: Session, run: Mapping[Any, Any]) -> dict[str, Any]:
    """Every downtime interval of the run and their sum (api-design.md, renewal-workflow.md 3). A run row whose first
    interval exists only in ``downtime_started_at``/``downtime_ended_at`` is read through those columns."""
    items = downtime.intervals(s, str(run["id"]))
    if not items:
        now = s.execute(text("SELECT now()")).scalar_one()
        items = downtime.from_run_columns(run, now)
    out = downtime.summary(items, terminal=run["state"] in TERMINAL)
    out["intervals"] = [_row(i) for i in out["intervals"]]
    return out


def steps(s: Session, run_id: UUID) -> list[dict[str, Any]]:
    rows = s.execute(
        text("SELECT id, seq, step_key, state, resolution, attempt, destructive, evidence, error, error_class, "
             "deadline_at, lease_owner, lease_expires_at, heartbeat_at, created_at, finished_at FROM workflow_step "
             "WHERE run_id = :r ORDER BY seq"), {"r": run_id}).mappings().all()  # fmt: skip
    return [_row(r) for r in rows]


def cutover_request(
    s: Session,
    who: Principal,
    cfg: RenewalConfig,
    run_id: UUID,
    *,
    typed: str | None,
    stepup_id: UUID | None,
) -> dict[str, Any]:
    run, resolved = run_row(s, run_id, who)
    if not authorize(who, "operator", resolved["scope"]):
        raise not_found("run")
    step = s.execute(text("SELECT step_key FROM workflow_step WHERE run_id = :r AND state = 'waiting'"),
                     {"r": run_id}).scalar()  # fmt: skip
    if step != "await_cutover":
        raise DomainError(
            409, "not-awaiting-cutover", "Not at the cutover gate", "The run is not waiting at G2."
        )
    facts = load_facts(s.connection(), str(run["renewal_plan_id"]))
    if ((facts.policy or {}).get("approvals") or {}).get("cutover"):
        return request_approval(s, who, gate=Gate.CUTOVER, plan_id=facts.plan_id, run_id=str(run_id),
                                scope=resolved["scope"])  # fmt: skip
    # No cutover approval required: the operator's own request, human session + step-up + TC (security-model 7.1).
    if not who.is_human or stepup_id is None:
        raise DomainError(403, "human-session-required", "Human session required",
                          "Entering the downtime window needs a human session, TOTP step-up and typed confirmation.")  # fmt: skip
    expected = tc_of(resolved["blue"]["name"], resolved["blue"]["server_id"])
    if not hmac.compare_digest(" ".join((typed or "").split()), expected):
        raise DomainError(422, "confirmation-mismatch", "Typed confirmation does not match",
                          "Type the server name and the last 6 characters of its id.")  # fmt: skip
    consume_stepup(s, who, stepup_id, action=CUTOVER_STEPUP_ACTION, target_id=str(run_id))
    aid = new_id()
    s.execute(
        text("INSERT INTO approval (id, subject_type, subject_id, plan_id, run_id, scope, bound_hash, requester_set, "
             "requested_by, decided_by, decision, typed_confirmation, auth_method, stepup_id, operator_confirmed, "
             "decided_at, expires_at) VALUES (:i, 'cutover', :r, :p, :r, :scope, :h, '{}', :u, :u, 'approved', :tc, "
             ":am, :su, true, now(), now() + make_interval(secs => :v))"),
        {"i": aid, "r": run_id, "p": facts.plan_id, "scope": resolved["scope"], "h": facts.recomputed_hash,
         "u": who.user_id, "tc": typed, "am": who.auth_method, "su": stepup_id,
         "v": float(cfg.validity_cutover)},
    )  # fmt: skip
    send_signal(s.connection(), str(run_id), "approve", actor_id=str(who.user_id), approval_id=aid)
    _audit(s, who, "approval.decide", "approval", aid, resolved["scope"], subject_type="cutover",
           decision="approved", operator_confirmed=True)  # fmt: skip
    return approval_body(s, aid)


def retirement_request(s: Session, who: Principal, run_id: UUID) -> dict[str, Any]:
    run, resolved = run_row(s, run_id, who)
    if not authorize(who, "operator", resolved["scope"]):
        raise not_found("run")
    step = s.execute(text("SELECT step_key FROM workflow_step WHERE run_id = :r AND state = 'waiting'"),
                     {"r": run_id}).scalar()  # fmt: skip
    if step != "await_retirement":
        raise DomainError(409, "retention-not-elapsed", "Not at the retirement gate",
                          "Retirement can be requested once the retention period has elapsed.")  # fmt: skip
    return request_approval(s, who, gate=Gate.RETIREMENT, plan_id=str(run["renewal_plan_id"]), run_id=str(run_id),
                            scope=resolved["scope"])  # fmt: skip


def action(
    s: Session, who: Principal, run_id: UUID, name: str, *, typed: str | None, stepup_id: UUID | None,
    attestation: str | None, step_id: UUID | str | None = None, probe_id: str | None = None,
) -> dict[str, Any]:  # fmt: skip
    if name not in ACTIONS:
        raise not_found("action")
    kind, confirmed = ACTIONS[name]
    run, resolved = run_row(s, run_id, who)
    scope = resolved["scope"]
    accept_payload: dict[str, Any] = {}
    if kind == "reprepare_automation":
        _check_reprepare(s, who, run, scope)
    elif kind == "accept_step":
        try:
            accept_payload = _check_accept(s, who, run, resolved, step_id=step_id, probe_id=probe_id,
                                           attestation=attestation)  # fmt: skip
        except DomainError as exc:
            _accept_refused(s, who, str(run_id), scope, exc)
            raise
    else:
        # probe is read-only: an approver may refresh the probe an accept-step rests on (ADR-0008)
        role_ok = authorize(who, "operator", scope) or (
            kind in ("mark_resolved", "probe") and authorize(who, "approver", scope)
        )
        if not role_ok:
            raise DomainError(403, "forbidden", "Forbidden", who.needs_role_message("operator"),
                              "Sign out and sign in as an account that holds it.")  # fmt: skip
        if kind == "probe" and accept.pending(s, str(run_id), kind="probe"):
            # PMR-1: a probe may reach green over SSH in the worker's main loop; repeated clicks are not queued
            raise DomainError(409, "probe-pending", "A probe is pending",
                              "The worker has not applied the earlier probe yet: one pending probe per run.",
                              "Reload the run page in a few seconds.")  # fmt: skip
    if not who.is_human and "operate" not in who.token_scopes:
        raise DomainError(
            403, "token-scope", "Forbidden", "The API token's scope does not allow this action."
        )
    payload: dict[str, Any] = {}
    sig_id = (
        new_id()
    )  # named by the step-up spent below, in this transaction (review PMR-8, REN-10)
    if confirmed:
        try:
            if not who.is_human or stepup_id is None:
                raise DomainError(403, "human-session-required", "Human session required",
                                  "This action needs a human session, TOTP step-up and typed confirmation.")  # fmt: skip
            expected = tc_target(
                s.connection(), str(run_id), kind, run["phase"] or "build", resolved
            )
            if not expected or not hmac.compare_digest(" ".join((typed or "").split()), expected):
                raise DomainError(422, "confirmation-mismatch", "Typed confirmation does not match",
                                  "Type the affected server's name and the last 6 characters of its id.")  # fmt: skip
        except DomainError as exc:
            if kind == "accept_step":
                _accept_refused(s, who, str(run_id), scope, exc)
            raise
        consume_stepup(
            s, who, stepup_id, action=f"run.{kind}", target_id=str(run_id), signal_id=sig_id
        )
        payload = {"typed_confirmation": typed, "stepup_id": str(stepup_id)}
    if attestation:
        payload["attestation"] = attestation[:2000]
    payload |= accept_payload
    sig = send_signal(s.connection(), str(run_id), kind, actor_id=str(who.user_id), payload=payload,
                      signal_id=sig_id)  # fmt: skip
    if kind == "accept_step":
        audit.record(
            s, action="run.accept_step.requested", target_type=accept.ENTITY, target_id=sig, actor_id=who.user_id,
            principal_type=who.principal_type, auth_method=who.auth_method, source_ip=who.source_ip,
            project_scope=scope, run_id=UUID(str(run_id)),
            after={"run_id": str(run_id), "step_key": accept_payload["step_key"], "attempt": accept_payload["attempt"],
                   "approver": str(who.user_id), "signal_id": sig, "probe_id": accept_payload["probe_id"]},
        )  # fmt: skip
    else:
        _audit(
            s,
            who,
            f"run.{kind}.request",
            "renewal_run",
            str(run_id),
            scope,
            kind=kind,
            signal_id=sig,
        )
    return run_body(s, run_id)


def _check_accept(
    s: Session, who: Principal, run: Mapping[Any, Any], resolved: Mapping[str, Any], *, step_id: UUID | str | None,
    probe_id: str | None, attestation: str | None,
) -> dict[str, Any]:  # fmt: skip
    """``accept-step`` (:mod:`ovlm.renewal.accept`, ADR-0008): an approver who is not the run's requester (run starter,
    plan creator; whatever ``auth.allow_operator_approver`` says), on a restore step of the allowlist parked because
    its playbook ran and refused, with an attestation and the latest OVLM probe, fresh and meeting the postcondition.
    Returns the signal payload fields. The worker re-checks all of it, with a probe of its own."""
    scope = resolved["scope"]
    if not authorize(who, "approver", scope):
        raise DomainError(403, "forbidden", "Forbidden", who.needs_role_message("approver"),
                          "Sign out and sign in as an account that holds it.")  # fmt: skip
    creator = s.execute(
        text("SELECT created_by FROM renewal_plan WHERE id = :p"), {"p": run["renewal_plan_id"]}
    ).scalar()
    if who.user_id in {run["started_by"], creator}:
        raise DomainError(403, "sod-violation", "Separation of duties",
                          "The run's requester (who started it or created its plan) cannot accept a step.")  # fmt: skip
    step = s.execute(
        text("SELECT id, step_key, state, attempt, error FROM workflow_step WHERE run_id = :r AND state = 'needs_human'"),
        {"r": run["id"]},
    ).mappings().first()  # fmt: skip
    phase = effective_phase(
        run["phase"], run.get("downtime_started_at"), run.get("downtime_ended_at")
    )
    why = accept.not_applicable(
        run_state=run["state"], step_key=step["step_key"] if step else None, step_state=step["state"] if step else None,
        phase=phase, error=step["error"] if step else None,
    )  # fmt: skip
    if why is not None or step is None:
        raise DomainError(
            409, accept.NOT_APPLICABLE, "accept-step does not apply", why or "no parked step"
        )
    if step_id is not None and str(step_id) != str(step["id"]):
        raise DomainError(409, accept.NOT_APPLICABLE, "Another step is parked",
                          "The parked step changed since the page was loaded. Reload the run.")  # fmt: skip
    if accept.pending(s, str(run["id"])):
        raise DomainError(409, accept.PENDING, "An accept-step request is pending",
                          "The worker has not applied the earlier request yet: one pending accept per run.")  # fmt: skip
    if accept.already_accepted(s, str(run["id"]), step["step_key"]):
        raise DomainError(409, accept.ALREADY, "Already accepted",
                          "This step was already accepted once in this run.")  # fmt: skip
    if (problem := accept.attestation_problem(attestation)) is not None:
        raise DomainError(422, accept.ATTESTATION, "Attestation required", problem)
    shown = accept.shown_probe(run.get("current_truth"))
    if shown is None or not probe_id or str(shown.get("id")) != probe_id:
        raise DomainError(409, accept.PROBE_MISMATCH, "Not the latest probe",
                          "The probe you saw is not the run's latest probe. Probe again and re-read it.")  # fmt: skip
    if str(shown.get("step_id")) != str(step["id"]) or shown.get("attempt") != step["attempt"]:
        raise DomainError(409, accept.PROBE_MISMATCH, "Probe of another attempt",
                          "The probe was taken for another step or attempt. Probe again.")  # fmt: skip
    age = accept.probe_age(shown, s.execute(text("SELECT now()")).scalar_one())
    if age is None or age > accept.FRESH_SECONDS:
        raise DomainError(409, accept.PROBE_STALE, "Probe too old",
                          f"OVLM's probe must be at most {int(accept.FRESH_SECONDS)} s old. Probe again.")  # fmt: skip
    if not shown.get("ok"):
        raise DomainError(
            409, accept.POSTCONDITION, "Postcondition not met", "; ".join(accept.failing(shown))
        )
    return {"step_id": str(step["id"]), "step_key": step["step_key"], "attempt": step["attempt"],
            "probe_id": probe_id}  # fmt: skip


def _accept_refused(s: Session, who: Principal, run_id: str, scope: str, exc: DomainError) -> None:
    """``run.accept_step.refused`` for a request the api refuses: its own transaction, so it survives the rollback."""
    record_independent(
        s, action="run.accept_step.refused", target_type=accept.ENTITY, target_id=run_id, result="denied",
        actor_id=who.user_id, principal_type=who.principal_type, auth_method=who.auth_method,
        source_ip=who.source_ip, project_scope=scope, run_id=UUID(run_id),
        after={"run_id": run_id, "approver": str(who.user_id), "outcome": "refused", "refusal_code": exc.code,
               "refusal": str(exc.detail)[:200]},
    )  # fmt: skip


def _check_reprepare(s: Session, who: Principal, run: Mapping[Any, Any], scope: str) -> None:
    """``reprepare-automation`` (:mod:`ovlm.renewal.reprepare`): an approver, never the run's requester (run starter,
    plan creator), on a run parked on a lost or unverifiable automation checkout. The worker re-checks all of it."""
    if not authorize(who, "approver", scope):
        raise DomainError(403, "forbidden", "Forbidden", who.needs_role_message("approver"),
                          "Sign out and sign in as an account that holds it.")  # fmt: skip
    creator = s.execute(
        text("SELECT created_by FROM renewal_plan WHERE id = :p"), {"p": run["renewal_plan_id"]}
    ).scalar()
    if who.user_id in {run["started_by"], creator}:
        raise DomainError(403, "sod-violation", "Separation of duties",
                          "The run's requester (who started it or created its plan) cannot authorize a re-clone.")  # fmt: skip
    error = s.execute(
        text("SELECT error FROM workflow_step WHERE run_id = :r AND state = 'needs_human'"),
        {"r": run["id"]},
    ).scalar()
    if run["state"] != "needs_human" or not reprepare.applies_to(error):
        raise DomainError(409, "not-applicable", "Not stopped on a lost checkout",
                          "reprepare-automation applies only to a step parked because the run's verified automation "
                          "checkout is gone or does not match B6's tree digest.")  # fmt: skip


def list_runs(
    s: Session, who: Principal, *, state: str | None, service: UUID | None
) -> list[dict[str, Any]]:
    rows = s.execute(
        text("SELECT r.id, p.resolved ->> 'scope' AS scope FROM workflow_run r JOIN renewal_plan p ON p.id = "
             "r.renewal_plan_id WHERE r.kind = :k AND (CAST(:st AS text) IS NULL OR r.state = :st) AND "
             "(CAST(:sv AS uuid) IS NULL OR r.service_id = :sv) ORDER BY r.created_at DESC LIMIT 200"),
        {"k": KIND, "st": state, "sv": service}).all()  # fmt: skip
    return [run_body(s, r.id) for r in rows if authorize(who, "viewer", r.scope)]


def list_approvals(s: Session, who: Principal, *, open_only: bool) -> list[dict[str, Any]]:
    rows = s.execute(
        text("SELECT id, scope FROM approval WHERE (NOT :o OR (decision IS NULL AND void_reason IS NULL)) "
             "ORDER BY created_at DESC LIMIT 200"), {"o": open_only}).all()  # fmt: skip
    return [approval_body(s, r.id) for r in rows if authorize(who, "viewer", r.scope)]


def list_plans(s: Session, who: Principal) -> list[dict[str, Any]]:
    rows = (
        s.execute(text("SELECT * FROM renewal_plan ORDER BY created_at DESC LIMIT 200"))
        .mappings()
        .all()
    )
    return [plan_body(s, r) for r in rows if authorize(who, "viewer", r["resolved"]["scope"])]


def approval_exists(s: Session, aid: UUID) -> bool:
    return s.execute(text("SELECT 1 FROM approval WHERE id = :i"), {"i": aid}).first() is not None


def visible(who: Principal, scope: str) -> bool:
    return authorize(who, "viewer", scope)


#: Plan states in which a changed policy version still matters: the plan hash is recomputed from the live policy row.
_PLAN_DONE = (*TERMINAL, "expired")


def open_plans_for_policy(s: Session, policy_id: UUID) -> dict[str, int]:
    """What a new version of a policy voids: plans under it that are not finished, and their live approvals.

    The plan hash binds the policy version, so every approval given on these plans stops matching (UI-2).
    """
    done = list(_PLAN_DONE)
    plans = s.execute(
        text("SELECT count(*) FROM renewal_plan WHERE policy_id = :p AND NOT (state = ANY(:d))"),
        {"p": policy_id, "d": done},
    ).scalar_one()
    approvals = s.execute(
        text("SELECT count(*) FROM approval a JOIN renewal_plan p ON p.id = a.plan_id "
             "WHERE p.policy_id = :p AND NOT (p.state = ANY(:d)) AND a.void_reason IS NULL "
             "AND (a.decision IS NULL OR a.decision = 'approved')"),
        {"p": policy_id, "d": done}).scalar_one()  # fmt: skip
    return {"plans": int(plans), "approvals": int(approvals)}
