"""Renewal pages (E6-3, E6-4): planning, plans, approvals (G1/G2/G3), run timeline and run actions.

Every page calls the service functions the REST API calls (``ovlm.renewal.service``, ``ovlm.readiness.service``,
``ovlm.policies.service``) behind the same role dependencies; nothing here is a private API. The UI adds only
convenience, never authority:

* Approvals and typed confirmations need a human session. API tokens may open the pages (read-only) and see why
  they cannot decide; the POST handlers refuse them with the same wording as the API (SEC-7.2).
* One form carries everything a decision needs (password, authenticator code, typed confirmation). The handler
  checks the typed confirmation first (so a typo does not spend a one-time code), then issues the single-use
  step-up for exactly this action and target (``login.reauth``, the call behind ``POST /session/reauth``), then
  calls the same service function as the API, which re-checks everything server-side and consumes the step-up.
* Every unsafe request carries the CSRF token (hidden field); the auth dependency checks it and the Origin.
"""

from __future__ import annotations

import hmac
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm.auth import login as login_svc
from ovlm.auth.authz import Action, authorize, authorize_action
from ovlm.auth.deps import get_db, get_hasher, get_settings, get_vault, require_role
from ovlm.auth.errors import ProblemError
from ovlm.auth.principal import Principal
from ovlm.auth.sod import Eligibility, Gate, account_provenance, check_approval_eligibility
from ovlm.auth.totp import TotpUnavailableError, TotpVault
from ovlm.config import Settings
from ovlm.inventory import service as inventory
from ovlm.policies.service import vm_deadline
from ovlm.readiness import service as readiness
from ovlm.registry import service as registry
from ovlm.registry.errors import DomainError
from ovlm.renewal import service as svc
from ovlm.renewal.config import RenewalConfig
from ovlm.renewal.evidence import APPROVAL_STEPUP_ACTION, CUTOVER_STEPUP_ACTION
from ovlm.renewal.plans import blast_radius, load_facts, tc_of, tc_target
from ovlm.ui import renewal_view as rv
from ovlm.ui.readiness_view import blockers, evidence_lines, quota_check
from ovlm.ui.support import UiRoute, error_page, parse_ts, render

router = APIRouter(route_class=UiRoute, include_in_schema=False)
Db = Annotated[Session, Depends(get_db)]
Cfg = Annotated[Settings, Depends(get_settings)]
Hasher = Annotated[PasswordHasher, Depends(get_hasher)]
Vault = Annotated[TotpVault | None, Depends(get_vault)]
VIEWER = Depends(require_role("viewer"))
OPERATOR = Depends(require_role("operator"))

NOTICES = {
    "plan-created": "Plan created. Review it, then request the plan approval (G1).",
    "approval-requested": "Approval requested. An approver who is not in the requester set must decide it.",
    "decided": "Your decision is recorded.",
    "run-started": "The run is requested. The worker admits it, or rejects it with a reason shown below.",
    "request-sent": "Request sent. The worker validates it again before acting; it shows as a pending signal until it does.",
    "cutover-confirmed": "Cutover confirmed. The worker re-checks the confirmation and the window before the downtime starts.",
}
#: The actions that ask for a human session, a step-up and a typed confirmation (``svc.ACTIONS``, second element).
CONFIRMED = frozenset(name for name, (_, confirmed) in svc.ACTIONS.items() if confirmed)
API_CLIENT_REFUSAL = (
    "API tokens cannot approve or confirm destructive actions. Sign in to the web interface with your own "
    "account (password and authenticator code) and do it here."
)


# --- small helpers ------------------------------------------------------------------------------------------------


def _cfg(settings: Settings) -> RenewalConfig:
    return RenewalConfig.from_settings(settings)


def _uuid(value: str) -> UUID | None:
    try:
        return UUID(value)
    except (ValueError, AttributeError):
        return None


def _usernames(db: Session, ids: list[str]) -> dict[str, str]:
    valid = [i for i in {str(x) for x in ids if x} if _uuid(i)]
    if not valid:
        return {}
    rows = db.execute(
        text("SELECT id, username FROM app_user WHERE id = ANY(CAST(:ids AS uuid[]))"),
        {"ids": "{" + ",".join(valid) + "}"},
    ).all()
    return {str(r.id): r.username for r in rows}


def _can(who: Principal, role: str, scope: str | None) -> bool:
    return authorize(who, role, scope)


def _fail_page(
    request: Request,
    status: int,
    title: str,
    detail: str,
    next_action: str | None = None,
    code: str = "",
) -> HTMLResponse:
    return error_page(request, status, title, detail, next_action, code)


def _all_open(db: Session, who: Principal) -> dict[str, list[dict[str, Any]]]:
    return {
        "plans": svc.list_plans(db, who),
        "runs": svc.list_runs(db, who, state=None, service=None),
        "approvals": svc.list_approvals(db, who, open_only=False),
    }


# --- planning page ----------------------------------------------------------------------------------------------


def _current_vms(db: Session, who: Principal) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cursor = None
    while True:
        page = registry.list_managed_vms(db, limit=inventory.MAX_PAGE, cursor=cursor)
        for vm in page.items:
            if vm["role"] != "current":
                continue
            service = registry.get_service(db, UUID(vm["service_id"]))
            scope = f"project:{service['project_connection_id']}" if service else None
            if service is None or not _can(who, "viewer", scope):
                continue
            out.append({"vm": vm, "service": service, "scope": scope})
        if not page.next_cursor or len(out) >= inventory.MAX_PAGE * 10:
            return out
        cursor = page.next_cursor


def _upcoming(
    db: Session, who: Principal, plans: list[dict[str, Any]], runs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    live_plan = {
        p["managed_vm_id"]: p
        for p in plans
        if p["state"] in ("draft", "awaiting_approval", "approved")
    }
    live_run = {r["service_id"]: r for r in runs if r["state"] not in svc.TERMINAL}
    rows = []
    for item in _current_vms(db, who):
        vm, service = item["vm"], item["service"]
        deadline = vm_deadline(db, UUID(vm["id"])) or {}
        assessment = readiness.latest_assessment(db, UUID(vm["id"]))
        server = inventory.server_detail(db, UUID(vm["observed_server_id"])) or {}
        rows.append({
            "vm": vm, "service": service, "name": server.get("name") or vm["openstack_server_id"],
            "deadline": deadline, "level": assessment["level"] if assessment else None,
            "assessed_at": assessment["created_at"] if assessment else None,
            "blockers": blockers(assessment), "quota": quota_check(assessment),
            "plan": live_plan.get(vm["id"]), "run": live_run.get(vm["service_id"]),
            "can_plan": _can(who, "operator", item["scope"]),
        })  # fmt: skip
    far = datetime.max.replace(tzinfo=UTC)
    rows.sort(key=lambda r: (parse_ts(r["deadline"].get("deadline")) or far, r["name"]))
    return rows


@router.get("/renewals", response_class=HTMLResponse)
def renewals(request: Request, db: Db, notice: str = "", who: Principal = VIEWER) -> HTMLResponse:
    data = _all_open(db, who)
    runs = sorted(data["runs"], key=lambda r: r["state"] in svc.TERMINAL)  # active runs first
    return render(
        request, "renewals/index.html", active="renewals", notice=NOTICES.get(notice),
        upcoming=_upcoming(db, who, data["plans"], data["runs"]), plans=data["plans"], runs=runs,
        open_approvals=[a for a in data["approvals"] if a["decision"] is None and a["void_reason"] is None],
        level_text={"ready": "Ready", "partially-ready": "Partially ready", "not-ready": "Not ready"},
    )  # fmt: skip


@router.post("/renewals/plans")
def create_plan(
    request: Request, db: Db, settings: Cfg, managed_vm_id: Annotated[str, Form()] = "",
    planned_window_start: Annotated[str, Form()] = "", who: Principal = OPERATOR,
) -> Response:  # fmt: skip
    vm = _uuid(managed_vm_id)
    if vm is None:
        raise DomainError(422, "invalid-vm", "Choose a VM", "The managed VM id is not valid.")
    window = None
    if planned_window_start.strip():
        window = parse_ts(planned_window_start.strip())
        if window is None:
            raise DomainError(
                422,
                "invalid-window",
                "Check the window",
                "Use a date and time such as 2026-11-20T02:00.",
            )
    out = svc.create_plan(db, who, _cfg(settings), vm, window)
    db.commit()
    return RedirectResponse(f"/renewals/plans/{out['id']}?notice=plan-created", status_code=303)


# --- plan page --------------------------------------------------------------------------------------------------


def _plan_context(db: Session, who: Principal, plan_id: UUID) -> dict[str, Any]:
    row = svc.plan_scope(db, plan_id, who)
    plan = svc.plan_body(db, row)
    scope = plan["resolved"]["scope"]
    facts = load_facts(db.connection(), str(plan_id))
    policy = facts.policy or {}
    approvals = [
        a for a in svc.list_approvals(db, who, open_only=False) if a["plan_id"] == str(plan_id)
    ]
    runs = [
        r
        for r in svc.list_runs(db, who, state=None, service=None)
        if r["renewal_plan_id"] == str(plan_id)
    ]
    assessment = readiness.latest_assessment(db, UUID(plan["managed_vm_id"]))
    g1 = [a for a in approvals if a["subject_type"] == "plan"]
    return {
        "plan": plan, "scope": scope, "policy": policy, "approvals": approvals,
        "g1_required": bool((policy.get("approvals") or {}).get("plan")),
        "g1_open": next((a for a in g1 if a["decision"] is None and a["void_reason"] is None), None),
        "stale": facts.recomputed_hash is None or facts.recomputed_hash != plan["plan_hash"],
        "runs": runs, "assessment": assessment, "blockers": blockers(assessment),
        "quota": quota_check(assessment), "is_operator": _can(who, "operator", scope),
        "names": _usernames(db, [plan.get("created_by") or ""]), "key": uuid4().hex,
        "restore": rv.restore_table(plan["resolved"]), "policy_rows": rv.policy_rows(policy),
    }  # fmt: skip


@router.get("/renewals/plans/{plan_id}", response_class=HTMLResponse)
def plan_page(
    request: Request, plan_id: str, db: Db, notice: str = "", who: Principal = VIEWER
) -> HTMLResponse:
    pid = _uuid(plan_id)
    if pid is None:
        return _fail_page(request, 404, "Plan not found", "No such plan.")
    ctx = _plan_context(db, who, pid)
    return render(
        request,
        "renewals/plan.html",
        active="renewals",
        notice=NOTICES.get(notice),
        error=None,
        **ctx,
    )


@router.post("/renewals/plans/{plan_id}/approval-requests")
def request_plan_approval(
    request: Request, plan_id: str, db: Db, who: Principal = OPERATOR
) -> Response:
    pid = _uuid(plan_id)
    if pid is None:
        return _fail_page(request, 404, "Plan not found", "No such plan.")
    plan = svc.plan_scope(db, pid, who)
    scope = plan["resolved"]["scope"]
    if not _can(who, "operator", scope):
        raise svc.not_found("plan")
    out = svc.request_approval(db, who, gate=Gate.PLAN, plan_id=str(pid), run_id=None, scope=scope)
    db.commit()
    return RedirectResponse(f"/approvals/{out['id']}?notice=approval-requested", status_code=303)


@router.post("/renewals/plans/{plan_id}/start")
def start_plan(
    request: Request, plan_id: str, db: Db, idempotency_key: Annotated[str, Form()] = "",
    who: Principal = OPERATOR,
) -> Response:  # fmt: skip
    pid = _uuid(plan_id)
    if pid is None:
        return _fail_page(request, 404, "Plan not found", "No such plan.")
    path, bh = request.url.path, svc.body_hash({})
    done = svc.replay(db, who, idempotency_key, "POST", path, bh)
    if done is None:
        done = svc.start(db, who, pid)
        svc.remember(db, who, idempotency_key, "POST", path, bh, done)
        db.commit()
    return RedirectResponse(f"/renewals/runs/{done['id']}?notice=run-started", status_code=303)


# --- approval page ----------------------------------------------------------------------------------------------


def _approval_state(a: dict[str, Any]) -> str:
    if a["void_reason"]:
        return "voided"
    if a["decision"] is None:
        return "open"
    expires = parse_ts(a.get("expires_at"))
    if a["decision"] == "approved" and expires and expires < datetime.now(UTC):
        return "expired"
    return str(a["decision"])


def _eligibility(
    db: Session, who: Principal, approval: dict[str, Any], gate: str, scope: str
) -> Eligibility:
    """The separation-of-duties verdict for *this viewer on this approval*, from the function the API decides with
    (it reads the requester set, the earlier gates' deciders and the installation setting; it changes nothing)."""
    facts = load_facts(db.connection(), approval["plan_id"])
    starter = None
    if approval["run_id"]:
        starter = db.execute(
            text("SELECT started_by FROM workflow_run WHERE id = :r"), {"r": approval["run_id"]}
        ).scalar()
    prior: set[UUID] = set()
    if gate != "plan":
        for earlier in (Gate.PLAN, Gate.CUTOVER):
            if earlier.value == gate:
                break
            subject = approval["plan_id"] if earlier is Gate.PLAN else approval["run_id"]
            decided = db.execute(
                text(
                    "SELECT decided_by FROM approval WHERE subject_type = :t AND subject_id = :s "
                    "AND decision = 'approved' AND NOT operator_confirmed ORDER BY decided_at DESC LIMIT 1"
                ),
                {"t": earlier.value, "s": subject},
            ).scalar()
            if decided:
                prior.add(decided)
    return check_approval_eligibility(
        db, who, gate=Gate(gate), scope=scope,
        requester_set=facts.requester_set(
            run_starter=starter, approval_requester=UUID(approval["requested_by"])
        ),
        prior_gate_deciders=prior,
        require_distinct_approvers=bool((facts.policy or {}).get("require_distinct_approvers")),
    )  # fmt: skip


def _approval_context(db: Session, who: Principal, approval_id: UUID) -> dict[str, Any]:
    if not svc.approval_exists(db, approval_id):
        raise svc.not_found("approval")
    approval = svc.approval_body(db, approval_id)
    if not svc.visible(who, approval["scope"]):
        raise svc.not_found("approval")
    plan = svc.plan_body(db, svc.plan_scope(db, UUID(approval["plan_id"]), who))
    resolved = plan["resolved"]
    gate = approval["subject_type"]
    scope = approval["scope"]
    run = svc.run_body(db, approval["run_id"]) if approval["run_id"] else None
    names = _usernames(
        db, [approval["requested_by"], approval["decided_by"] or "", *approval["requester_set"]]
    )
    state = _approval_state(approval)
    elig = _eligibility(db, who, approval, gate, scope)
    blocked: str | None = None
    if not who.is_human:
        blocked = API_CLIENT_REFUSAL
    elif not elig.allowed:
        detail = " ".join(v.detail for v in elig.violations)
        if any(v.code.startswith("sod-") for v in elig.violations):
            detail = "Separation of duties: " + detail
        if "approver role" not in detail:
            detail += " Ask another person holding the approver role in this project to decide."
        blocked = detail
    reasons = [r.replace("_", " ") for r in elig.self_approval_reasons]
    self_approval = elig.allowed and elig.self_approved
    expected_tc = (
        tc_of(resolved["blue"]["name"], resolved["blue"]["server_id"]) if gate != "plan" else None
    )
    return {
        "approval": approval, "plan": plan, "resolved": resolved, "gate": gate, "gate_text": rv.GATE_TEXT[gate],
        "state": state, "run": run, "names": names, "inputs": rv.hash_inputs(approval),
        "restore": rv.restore_table(resolved) if gate == "cutover" else None,
        "blocked": blocked if state == "open" else None, "self_approval": self_approval and state == "open",
        "reasons": reasons,
        "can_decide": state == "open" and blocked is None, "is_token": not who.is_human,
        "needs_tc": gate != "plan", "tc_target": rv.typed_target(expected_tc) if expected_tc else None,
        "my_provenance": account_provenance(db, who.user_id) if gate == "retirement" and state == "open" else None,
        "truth": rv.truth_sections(run["current_truth"]) if run and run.get("current_truth") else [],
        "truth_age": rv.truth_age_seconds(run) if run else None,
        "policy_rows": rv.policy_rows(rv.hash_inputs(approval)["policy"]),
    }  # fmt: skip


def _approval_page(
    request: Request, db: Session, who: Principal, approval_id: UUID, status: int = 200,
    notice: str | None = None, error: dict[str, str | None] | None = None, **form: Any,
) -> HTMLResponse:  # fmt: skip
    ctx = _approval_context(db, who, approval_id)
    return render(
        request,
        "renewals/approval.html",
        status,
        active="renewals",
        notice=notice,
        error=error,
        form=form,
        **ctx,
    )


@router.get("/approvals/{approval_id}", response_class=HTMLResponse)
def approval_page(
    request: Request, approval_id: str, db: Db, notice: str = "", who: Principal = VIEWER
) -> HTMLResponse:
    aid = _uuid(approval_id)
    if aid is None:
        return _fail_page(request, 404, "Approval not found", "No such approval.")
    return _approval_page(request, db, who, aid, notice=NOTICES.get(notice))


def _stepup(
    db: Session, settings: Settings, hasher: PasswordHasher, vault: TotpVault | None, who: Principal,
    password: str, totp_code: str, action: str, target_id: str,
) -> UUID:  # fmt: skip
    """Issue the single-use step-up for exactly this action and target; failures become ``ProblemError``."""
    try:
        step = login_svc.reauth(
            db, settings, hasher, vault, who, password=password, totp_code=totp_code.strip() or None,
            action=action, target_id=target_id,
        )  # fmt: skip
    except login_svc.TotpFlowError as exc:
        raise ProblemError(403, exc.code, "Confirmation refused", str(exc)) from None
    except login_svc.RateLimitedError as exc:
        raise ProblemError(
            429, "rate-limited", "Too many failed attempts", f"Retry in {exc.retry_after} seconds."
        ) from None
    except (login_svc.AuthFailedError, TotpUnavailableError):
        raise ProblemError(
            401, "stepup-failed", "Password or code not accepted",
            "Check your password and the current authenticator code. A code that was just used cannot be used again: "
            "wait for the next one.",
        ) from None  # fmt: skip
    return UUID(str(step.id))


def _problem(exc: ProblemError | DomainError) -> tuple[int, dict[str, str | None]]:
    if isinstance(exc, ProblemError):
        return exc.status_code, {
            "title": exc.title,
            "detail": str(exc.detail),
            "next_action": exc.next_action,
            "code": exc.code,
        }
    return exc.status, {
        "title": exc.title,
        "detail": exc.detail,
        "next_action": exc.next_action,
        "code": exc.code,
    }


@router.post("/approvals/{approval_id}/decision")
def decide(
    request: Request, approval_id: str, db: Db, settings: Cfg, hasher: Hasher, vault: Vault,
    decision: Annotated[str, Form()] = "", typed_confirmation: Annotated[str, Form()] = "",
    comment: Annotated[str, Form()] = "", password: Annotated[str, Form()] = "",
    totp_code: Annotated[str, Form()] = "", who: Principal = VIEWER,
) -> Response:  # fmt: skip
    aid = _uuid(approval_id)
    if aid is None:
        return _fail_page(request, 404, "Approval not found", "No such approval.")
    form = {"decision": decision, "comment": comment}
    try:
        ctx = _approval_context(db, who, aid)  # 404 for out-of-scope, like the API
        if not who.is_human:
            raise ProblemError(
                403, "human-session-required", "Human session required", API_CLIENT_REFUSAL
            )
        if ctx["state"] != "open":  # before a one-time code is spent on it
            raise DomainError(409, "approval-closed", "Approval closed", f"This approval is already {ctx['state']}.")  # fmt: skip
        if (
            decision not in ("approved", "rejected")
            or len(comment) > 2000
            or len(typed_confirmation) > 300
        ):
            raise DomainError(422, "invalid-decision", "Check the form", "Choose approve or reject; the comment is limited to 2000 characters.")  # fmt: skip
        if ctx["needs_tc"] and decision == "approved":
            expected = tc_of(ctx["resolved"]["blue"]["name"], ctx["resolved"]["blue"]["server_id"])
            if not hmac.compare_digest(" ".join(typed_confirmation.split()), expected):
                raise DomainError(422, "confirmation-mismatch", "Typed confirmation does not match",
                                  "Type the server name and the last 6 characters of its id.")  # fmt: skip
        stepup = _stepup(
            db, settings, hasher, vault, who, password, totp_code, APPROVAL_STEPUP_ACTION, str(aid)
        )
        svc.decide(db, who, _cfg(settings), aid, decision=decision, typed=typed_confirmation or None,
                   comment=comment or None, stepup_id=stepup)  # fmt: skip
        db.commit()
    except (ProblemError, DomainError) as exc:
        db.rollback()
        status, error = _problem(exc)
        if status == 404:
            raise
        return _approval_page(request, db, who, aid, status, error=error, **form)
    return RedirectResponse(f"/approvals/{aid}?notice=decided", status_code=303)


# --- run page ----------------------------------------------------------------------------------------------------

_TERMINAL = svc.TERMINAL
#: pending/executed action -> label shown in the timeline
_ACTION_LABEL = {
    "probe": "Probe", "retry-step": "Retry step", "abort": "Abort", "rollback": "Roll back",
    "revert": "Revert to the old VM", "discard": "Discard the new VM", "mark-resolved": "Mark resolved",
}  # fmt: skip


def _attempts(
    db: Session, who: Principal, step_ids: list[str], scope: str
) -> dict[str, list[dict[str, Any]]]:
    if not step_ids:
        return {}
    rows = db.execute(
        text(
            "SELECT id, step_id, attempt, phase, target_role, classification, exit_code, reason, duration_seconds, "
            "task_summary, result_error, artifact_expires_at, artifacts_purged_at FROM automation_run "
            "WHERE step_id = ANY(CAST(:ids AS uuid[])) ORDER BY step_id, attempt"
        ),
        {"ids": "{" + ",".join(step_ids) + "}"},
    ).mappings().all()  # fmt: skip
    can_read = authorize_action(who, Action.AUTOMATION_ARTEFACT_VIEW, scope)
    out: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(str(r["step_id"]), []).append({
            **{k: (str(v) if k in ("id", "step_id") else v) for k, v in r.items()},
            "can_read_artefacts": can_read and r["artifacts_purged_at"] is None,
            "purged": r["artifacts_purged_at"] is not None,
        })  # fmt: skip
    return out


def _step_view(step: dict[str, Any], attempts: list[dict[str, Any]]) -> dict[str, Any]:
    code, label = rv.step_title(step["step_key"])
    return {
        **step, "code": code, "label": label, "guest": step["step_key"] in rv.GUEST_STEPS,
        "evidence_rows": evidence_lines(step.get("evidence")), "error_rows": evidence_lines(step.get("error")),
        "attempts": attempts,
    }  # fmt: skip


def _gate_forms(
    db: Session,
    run: dict[str, Any],
    current: dict[str, Any] | None,
    approvals: list[dict[str, Any]],
) -> dict[str, Any]:
    key = current["step_key"] if current and current["state"] == "waiting" else None
    facts = load_facts(db.connection(), run["renewal_plan_id"])
    cutover_approval_needed = bool(((facts.policy or {}).get("approvals") or {}).get("cutover"))
    open_g = {
        a["subject_type"]: a
        for a in approvals
        if a["decision"] is None and a["void_reason"] is None and a["run_id"] == run["id"]
    }
    return {
        "cutover": key == "await_cutover", "retirement": key == "await_retirement",
        "cutover_needs_approval": cutover_approval_needed, "open": open_g,
    }  # fmt: skip


def _run_context(db: Session, who: Principal, run_id: UUID) -> dict[str, Any]:
    _, resolved = svc.run_row(db, run_id, who)
    scope = resolved["scope"]
    body = svc.run_body(db, run_id)
    raw_steps = svc.steps(db, run_id)
    attempts = _attempts(db, who, [s["id"] for s in raw_steps], scope)
    steps = [_step_view(s, attempts.get(s["id"], [])) for s in raw_steps]
    approvals = [
        a
        for a in svc.list_approvals(db, who, open_only=False)
        if a["plan_id"] == body["renewal_plan_id"]
    ]
    current = body["current_step"]
    parked = next((s for s in reversed(steps) if s["state"] == "needs_human"), None)
    is_op = _can(who, "operator", scope)
    is_appr = _can(who, "approver", scope)
    actions = []
    for a in body["available_actions"]:
        name = a["action"]
        confirmed = name in CONFIRMED
        usable = is_op or (name == "mark-resolved" and is_appr)
        why = None
        if not usable:
            why = (
                "You need the operator role in this project."
                if name != "mark-resolved"
                else "You need the operator or approver role."
            )
        elif confirmed and not who.is_human:
            why = "API tokens cannot confirm this; use a human session in the web interface."
        actions.append(
            {
                **a,
                "confirmed": confirmed,
                "usable": why is None,
                "why": why,
                "label": _ACTION_LABEL.get(name, name),
            }
        )
    names = _usernames(
        db,
        [s["actor_id"] for s in body["pending_signals"]]
        + [a["decided_by"] or "" for a in approvals],
    )
    return {
        "run": body, "steps": steps, "scope": scope, "plan_id": body["renewal_plan_id"], "phase_text": rv.PHASE_TEXT.get(body["phase"] or "build", ""),
        "state_text": rv.RUN_STATE_TEXT.get(body["state"], body["state"]), "downtime": rv.downtime(body),
        "nh": rv.needs_human_text(body["needs_human_reason"]) if body["state"] == "needs_human" else None, "parked": parked,
        "truth": rv.truth_sections(body.get("current_truth")), "truth_age": rv.truth_age_seconds(body),
        "actions": actions, "approvals": approvals, "names": names, "terminal": body["state"] in _TERMINAL,
        "self_approved": any(a["self_approved"] and a["decision"] == "approved" for a in approvals),
        "gates": _gate_forms(db, body, current, approvals), "is_operator": is_op, "is_human": who.is_human,
        "lease_expired": bool(
            current and current.get("state") == "running" and (parse_ts(current.get("lease_expires_at")) or datetime.max.replace(tzinfo=UTC)) < datetime.now(UTC)
        ),
        "key": uuid4().hex,
        "restore": rv.restore_table(resolved), "blast": blast_radius(resolved, "cutover"),
    }  # fmt: skip


def _cutover_tc_target(ctx: dict[str, Any], db: Session) -> dict[str, str] | None:
    row = db.execute(
        text("SELECT resolved FROM renewal_plan WHERE id = :p"), {"p": ctx["plan_id"]}
    ).scalar_one()
    return rv.typed_target(tc_of(row["blue"]["name"], row["blue"]["server_id"]))


@router.get("/renewals/runs/{run_id}", response_class=HTMLResponse)
def run_page(
    request: Request, run_id: str, db: Db, notice: str = "", who: Principal = VIEWER
) -> HTMLResponse:
    rid = _uuid(run_id)
    if rid is None:
        return _fail_page(request, 404, "Run not found", "No such run.")
    ctx = _run_context(db, who, rid)
    ctx["tc_target"] = (
        _cutover_tc_target(ctx, db)
        if ctx["gates"]["cutover"] and not ctx["gates"]["cutover_needs_approval"]
        else None
    )
    return render(
        request,
        "renewals/run.html",
        active="renewals",
        notice=NOTICES.get(notice),
        error=None,
        form={},
        **ctx,
    )


@router.get("/renewals/runs/{run_id}/panel", response_class=HTMLResponse)
def run_panel(request: Request, run_id: str, db: Db, who: Principal = VIEWER) -> HTMLResponse:
    """The polled part of the run page (HTMX): state, downtime timer, current truth, steps. No forms inside."""
    rid = _uuid(run_id)
    if rid is None:
        return _fail_page(request, 404, "Run not found", "No such run.")
    return render(request, "renewals/_run_panel.html", **_run_context(db, who, rid))


def _run_page_with_error(
    request: Request,
    db: Session,
    who: Principal,
    rid: UUID,
    status: int,
    error: dict[str, str | None],
    **form: Any,
) -> HTMLResponse:
    ctx = _run_context(db, who, rid)
    ctx["tc_target"] = (
        _cutover_tc_target(ctx, db)
        if ctx["gates"]["cutover"] and not ctx["gates"]["cutover_needs_approval"]
        else None
    )
    return render(
        request,
        "renewals/run.html",
        status,
        active="renewals",
        notice=None,
        error=error,
        form=form,
        **ctx,
    )


@router.post("/renewals/runs/{run_id}/cutover-request")
def cutover_request(
    request: Request, run_id: str, db: Db, settings: Cfg, hasher: Hasher, vault: Vault,
    typed_confirmation: Annotated[str, Form()] = "", password: Annotated[str, Form()] = "",
    totp_code: Annotated[str, Form()] = "", who: Principal = OPERATOR,
) -> Response:  # fmt: skip
    rid = _uuid(run_id)
    if rid is None:
        return _fail_page(request, 404, "Run not found", "No such run.")
    try:
        run, resolved = svc.run_row(db, rid, who)
        facts = load_facts(db.connection(), str(run["renewal_plan_id"]))
        if ((facts.policy or {}).get("approvals") or {}).get("cutover"):
            out = svc.cutover_request(db, who, _cfg(settings), rid, typed=None, stepup_id=None)
            db.commit()
            return RedirectResponse(
                f"/approvals/{out['id']}?notice=approval-requested", status_code=303
            )
        # Policy needs no cutover approval: the operator's own confirmation (human session, step-up, typed).
        if not who.is_human:
            raise ProblemError(
                403, "human-session-required", "Human session required", API_CLIENT_REFUSAL
            )
        expected = tc_of(resolved["blue"]["name"], resolved["blue"]["server_id"])
        if not hmac.compare_digest(" ".join(typed_confirmation.split()), expected):
            raise DomainError(422, "confirmation-mismatch", "Typed confirmation does not match",
                              "Type the server name and the last 6 characters of its id.")  # fmt: skip
        stepup = _stepup(
            db, settings, hasher, vault, who, password, totp_code, CUTOVER_STEPUP_ACTION, str(rid)
        )
        svc.cutover_request(
            db, who, _cfg(settings), rid, typed=typed_confirmation, stepup_id=stepup
        )
        db.commit()
    except (ProblemError, DomainError) as exc:
        db.rollback()
        status, error = _problem(exc)
        if status == 404:
            raise
        return _run_page_with_error(request, db, who, rid, status, error)
    return RedirectResponse(f"/renewals/runs/{rid}?notice=cutover-confirmed", status_code=303)


@router.post("/renewals/runs/{run_id}/retirement-request")
def retirement_request(
    request: Request, run_id: str, db: Db, who: Principal = OPERATOR
) -> Response:
    rid = _uuid(run_id)
    if rid is None:
        return _fail_page(request, 404, "Run not found", "No such run.")
    out = svc.retirement_request(db, who, rid)
    db.commit()
    return RedirectResponse(f"/approvals/{out['id']}?notice=approval-requested", status_code=303)


# --- run actions -------------------------------------------------------------------------------------------------


def _action_context(
    db: Session, who: Principal, rid: UUID, name: str
) -> tuple[dict[str, Any], str]:
    """The page context and, apart from it, the expected typed confirmation (never rendered)."""
    if name not in svc.ACTIONS:
        raise svc.not_found("action")
    kind, confirmed = svc.ACTIONS[name]
    run, resolved = svc.run_row(db, rid, who)
    body = svc.run_body(db, rid)
    offered = next((a for a in body["available_actions"] if a["action"] == name), None)
    target = (
        tc_target(db.connection(), str(rid), kind, run["phase"] or "build", resolved)
        if confirmed
        else ""
    )
    return {
        "run": body, "action_name": name, "kind": kind, "label": _ACTION_LABEL.get(name, name), "confirmed": confirmed,
        "offered": offered, "resolved": resolved, "scope": resolved["scope"], "blast": blast_radius(resolved, "cutover"),
        "tc_target": rv.typed_target(target) if target else None, "parked": body.get("needs_human_reason"),
        "key": uuid4().hex, "is_token": not who.is_human, "step_text": rv.step_title((body["current_step"] or {}).get("step_key", ""))[1],
        "phase_text": rv.PHASE_TEXT.get(body["phase"] or "build", ""),
    }, target  # fmt: skip


@router.get("/renewals/runs/{run_id}/actions/{name}", response_class=HTMLResponse)
def action_page(
    request: Request, run_id: str, name: str, db: Db, who: Principal = VIEWER
) -> Response:
    rid = _uuid(run_id)
    if rid is None:
        return _fail_page(request, 404, "Run not found", "No such run.")
    ctx, _ = _action_context(db, who, rid, name)
    if not ctx["confirmed"]:
        return RedirectResponse(f"/renewals/runs/{rid}", status_code=303)
    return render(request, "renewals/action.html", active="renewals", error=None, form={}, **ctx)


@router.post("/renewals/runs/{run_id}/actions/{name}")
def run_action(
    request: Request, run_id: str, name: str, db: Db, settings: Cfg, hasher: Hasher, vault: Vault,
    typed_confirmation: Annotated[str, Form()] = "", password: Annotated[str, Form()] = "",
    totp_code: Annotated[str, Form()] = "", attestation: Annotated[str, Form()] = "",
    idempotency_key: Annotated[str, Form()] = "", who: Principal = VIEWER,
) -> Response:  # fmt: skip
    rid = _uuid(run_id)
    if rid is None:
        return _fail_page(request, 404, "Run not found", "No such run.")
    ctx, expected = _action_context(db, who, rid, name)
    form = {"attestation": attestation}
    try:
        path = request.url.path
        bh = svc.body_hash({"typed_confirmation": typed_confirmation, "attestation": attestation})
        if svc.replay(db, who, idempotency_key, "POST", path, bh) is not None:
            # The same form submitted twice: the first request is on record. Do not ask for a second code.
            return RedirectResponse(f"/renewals/runs/{rid}?notice=request-sent", status_code=303)
        stepup: UUID | None = None
        if ctx["confirmed"]:
            if not who.is_human:
                raise ProblemError(
                    403, "human-session-required", "Human session required", API_CLIENT_REFUSAL
                )
            if name == "mark-resolved" and not attestation.strip():
                raise DomainError(422, "attestation-required", "Say what you did", "Describe the manual fix: the engine re-probes before it continues, and the audit row keeps your words.")  # fmt: skip
            if not expected or not hmac.compare_digest(
                " ".join(typed_confirmation.split()), expected
            ):
                raise DomainError(422, "confirmation-mismatch", "Typed confirmation does not match",
                                  "Type the affected server's name and the last 6 characters of its id.")  # fmt: skip
            stepup = _stepup(
                db,
                settings,
                hasher,
                vault,
                who,
                password,
                totp_code,
                f"run.{ctx['kind']}",
                str(rid),
            )
        out = svc.action(
            db, who, rid, name, typed=typed_confirmation or None, stepup_id=stepup,
            attestation=attestation or None,
        )  # fmt: skip
        svc.remember(db, who, idempotency_key, "POST", path, bh, out)
        db.commit()
    except (ProblemError, DomainError) as exc:
        db.rollback()
        status, error = _problem(exc)
        if status == 404:
            raise
        if ctx["confirmed"]:
            return render(
                request,
                "renewals/action.html",
                status,
                active="renewals",
                error=error,
                form=form,
                **ctx,
            )
        return _run_page_with_error(request, db, who, rid, status, error)
    return RedirectResponse(f"/renewals/runs/{rid}?notice=request-sent", status_code=303)
