"""Renewal plans, approvals, runs and run actions (api-design.md 3.6, 3.7, 4).

Work-starting POSTs answer **202** with the run body and need ``Idempotency-Key``. Approvals and every action with
a typed confirmation are human-only (API tokens get 403) and consume a single-use TOTP step-up bound to the action
and target. Reads are scoped: out-of-scope resources answer 404. The api inserts rows only; the worker re-validates
approvals, step-ups and confirmations before acting (SEC-R-1).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from ovlm.api.routes_common import ProblemRoute
from ovlm.auth.deps import get_db, get_settings, require_role
from ovlm.auth.principal import Principal
from ovlm.auth.sod import Gate
from ovlm.config import Settings
from ovlm.renewal import service as svc
from ovlm.renewal.config import RenewalConfig

VIEWER = Depends(require_role("viewer"))
OPERATOR = Depends(require_role("operator", token_scope="operate"))  # noqa: S106 - scope name
APPROVER_HUMAN = Depends(require_role("approver", human_only=True))
DB = Depends(get_db)

router = APIRouter(prefix="/api/v1", route_class=ProblemRoute)


def _cfg(request: Request) -> RenewalConfig:
    settings: Settings = get_settings(request)
    return RenewalConfig.from_settings(settings)


class PlanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    managed_vm_id: UUID
    planned_window_start: datetime | None = None


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approved", "rejected"]
    stepup_id: UUID
    typed_confirmation: str | None = Field(default=None, max_length=300)
    comment: str | None = Field(default=None, max_length=2000)


class ConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    typed_confirmation: str | None = Field(default=None, max_length=300)
    stepup_id: UUID | None = None
    attestation: str | None = Field(default=None, max_length=2000)
    step_id: UUID | None = None
    #: accept-step: the id of the OVLM probe the approver read (``current_truth.accept_probe.id``, ADR-0008)
    probe_id: str | None = Field(default=None, max_length=64)


@router.post("/plans", status_code=201)
def create_plan(
    body: PlanIn, request: Request, s: Session = DB, who: Principal = OPERATOR
) -> dict[str, Any]:
    out = svc.create_plan(s, who, _cfg(request), body.managed_vm_id, body.planned_window_start)
    s.commit()
    return out


@router.get("/plans")
def list_plans(s: Session = DB, who: Principal = VIEWER) -> dict[str, Any]:
    return {"items": svc.list_plans(s, who), "next_cursor": None}


@router.get("/plans/{plan_id}")
def get_plan(plan_id: UUID, s: Session = DB, who: Principal = VIEWER) -> dict[str, Any]:
    return svc.plan_body(s, svc.plan_scope(s, plan_id, who))


@router.post("/plans/{plan_id}/approval-requests", status_code=201)
def plan_approval_request(
    plan_id: UUID, s: Session = DB, who: Principal = OPERATOR
) -> dict[str, Any]:
    plan = svc.plan_scope(s, plan_id, who)
    out = svc.request_approval(s, who, gate=Gate.PLAN, plan_id=str(plan_id), run_id=None,
                               scope=plan["resolved"]["scope"])  # fmt: skip
    s.commit()
    return out


@router.post("/plans/{plan_id}/start", status_code=202)
def start(
    plan_id: UUID, request: Request, response: Response, s: Session = DB, who: Principal = OPERATOR,
    idempotency_key: str | None = Header(default=None),
) -> dict[str, Any]:  # fmt: skip
    path, bh = request.url.path, svc.body_hash({})
    if (done := svc.replay(s, who, idempotency_key, "POST", path, bh)) is not None:
        return done
    out = svc.start(s, who, plan_id)
    svc.remember(s, who, idempotency_key or "", "POST", path, bh, out)
    s.commit()
    response.headers["Location"] = f"/api/v1/runs/{out['id']}"
    return out


@router.get("/approvals")
def list_approvals(
    state: Literal["open", "all"] = "open", s: Session = DB, who: Principal = VIEWER
) -> dict[str, Any]:
    return {"items": svc.list_approvals(s, who, open_only=state == "open"), "next_cursor": None}


@router.get("/approvals/{approval_id}")
def get_approval(approval_id: UUID, s: Session = DB, who: Principal = VIEWER) -> dict[str, Any]:
    body = svc.approval_body(s, approval_id) if svc.approval_exists(s, approval_id) else None
    if body is None or not svc.visible(who, body["scope"]):
        raise svc.not_found("approval")
    return body


@router.post("/approvals/{approval_id}/decision")
def decide(
    approval_id: UUID,
    body: DecisionIn,
    request: Request,
    s: Session = DB,
    who: Principal = APPROVER_HUMAN,
) -> dict[str, Any]:
    out = svc.decide(s, who, _cfg(request), approval_id, decision=body.decision, typed=body.typed_confirmation,
                     comment=body.comment, stepup_id=body.stepup_id)  # fmt: skip
    s.commit()
    return out


@router.get("/runs")
def list_runs(
    state: str | None = None, service: UUID | None = None, s: Session = DB, who: Principal = VIEWER
) -> dict[str, Any]:
    return {"items": svc.list_runs(s, who, state=state, service=service), "next_cursor": None}


@router.get("/runs/{run_id}")
def get_run(run_id: UUID, s: Session = DB, who: Principal = VIEWER) -> dict[str, Any]:
    svc.run_row(s, run_id, who)
    return svc.run_body(s, run_id)


@router.get("/runs/{run_id}/steps")
def get_steps(run_id: UUID, s: Session = DB, who: Principal = VIEWER) -> dict[str, Any]:
    svc.run_row(s, run_id, who)
    return {"items": svc.steps(s, run_id), "next_cursor": None}


@router.post("/runs/{run_id}/cutover-request", status_code=202)
def cutover_request(
    run_id: UUID,
    request: Request,
    body: ConfirmIn | None = None,
    s: Session = DB,
    who: Principal = OPERATOR,
) -> dict[str, Any]:
    body = body or ConfirmIn()
    out = svc.cutover_request(
        s, who, _cfg(request), run_id, typed=body.typed_confirmation, stepup_id=body.stepup_id
    )
    s.commit()
    return out


@router.post("/runs/{run_id}/retirement-request", status_code=202)
def retirement_request(run_id: UUID, s: Session = DB, who: Principal = OPERATOR) -> dict[str, Any]:
    out = svc.retirement_request(s, who, run_id)
    s.commit()
    return out


@router.post("/runs/{run_id}/actions/{name}", status_code=202)
def run_action(
    run_id: UUID, name: str, request: Request, body: ConfirmIn | None = None, s: Session = DB,
    who: Principal = VIEWER, idempotency_key: str | None = Header(default=None),
) -> dict[str, Any]:  # fmt: skip
    body = body or ConfirmIn()
    path, bh = request.url.path, svc.body_hash(body.model_dump(mode="json"))
    if (done := svc.replay(s, who, idempotency_key, "POST", path, bh)) is not None:
        return done
    out = svc.action(s, who, run_id, name, typed=body.typed_confirmation, stepup_id=body.stepup_id,
                     attestation=body.attestation, step_id=body.step_id, probe_id=body.probe_id)  # fmt: skip
    svc.remember(s, who, idempotency_key or "", "POST", path, bh, out)
    s.commit()
    return out
