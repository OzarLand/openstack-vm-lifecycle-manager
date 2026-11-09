"""Renewal REST endpoints (api-design.md 3.6, 3.7, 4) through the real app, real sessions, TOTP step-ups and RBAC."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from ovlm.config.renewal_defaults import DEFAULTS_ID
from ovlm.config.settings import (
    RenewalApprovalValidity,
    RenewalExternalVerify,
    RenewalGreenReady,
    RenewalHealthcheck,
    RenewalRetire,
    RenewalSettings,
)
from ovlm.registry.errors import DomainError
from ovlm.renewal.config import RenewalConfig
from ovlm.renewal.plans import resolve_plan
from ovlm.workflow.ids import new_id
from tests.integration.auth_support import PASSWORD, Env, env  # noqa: F401 - fixture
from tests.integration.renewal.conftest import CFG, _seed
from tests.integration.renewal.doubles import RenewalFake

RENEWAL = RenewalSettings(
    timeouts=dict(CFG.timeouts),
    automation_timeouts=dict(CFG.automation),
    green_ready=RenewalGreenReady(max_age=3600),
    healthcheck=RenewalHealthcheck(max_attempts=3, interval=0),
    external_verify=RenewalExternalVerify(required_successes=2, interval=0),
    retire=RenewalRetire(health_max_age=3600),
    approval_validity=RenewalApprovalValidity(retirement=3600),
)


class Api:
    def __init__(self, e: Env) -> None:
        self.env = e
        env_ = e
        cloud = RenewalFake(now=datetime.now(UTC), strict_gate=False)
        self.ids, _ = _seed(env_.owner, cloud, snapshot=False, policy={})
        scope = self.ids["scope"]
        self.op, _ = env_.user_client("op1", [("operator", scope)])
        self.ap, self.ap_secret = env_.user_client("ap1", [("approver", scope)])
        self.other, _ = env_.user_client("viewer-other", [("viewer", "project:" + new_id())])

    def h(self, c: TestClient, **extra: str) -> dict[str, str]:
        return self.env.headers(c, **extra)

    def stepup(self, c: TestClient, secret: str | None, action: str, target: str) -> str:
        self.env.clock.advance()
        body: dict[str, Any] = {"password": PASSWORD, "action": action, "target_id": target}
        if secret:
            body["totp_code"] = self.env.code(secret)
        r = c.post("/api/v1/session/reauth", json=body, headers=self.h(c))
        assert r.status_code == 200, r.text
        return str(r.json()["stepup_id"])


def configure(e: Env) -> None:
    e.app.state.settings = e.settings.model_copy(update={"renewal": RENEWAL})


def test_plan_on_a_fresh_config_records_the_defaults(env: Env) -> None:  # noqa: F811
    """P1-8: no renewal key set, the plan is created; it records every effective value and which came from the
    built-in defaults, bound into the plan hash (``resolved``), and the worst case is computed from them."""
    assert env.app.state.settings.renewal == RenewalSettings()  # nothing configured
    a = Api(env)
    r = a.op.post("/api/v1/plans", json={"managed_vm_id": a.ids["vm"]}, headers=a.h(a.op))
    assert r.status_code == 201, r.text
    plan = r.json()
    rec = plan["resolved"]["renewal_settings"]
    expected = RenewalConfig.from_settings(env.app.state.settings)
    assert rec["defaults"] == DEFAULTS_ID
    assert rec["values"] == expected.values() and len(rec["values"]) == 30
    assert rec["defaulted"] == sorted(rec["values"])  # every key from the defaults
    assert rec["values"]["renewal.timeouts.green_build"] == 900.0
    assert plan["resolved"]["worst_case_window_seconds"] == expected.worst_case_window(
        snapshot=False, stateless=False
    )
    assert plan["blast_radius"]["timeouts"]["keys_from_defaults"] == 30
    stored = env.sql(
        "SELECT resolved -> 'renewal_settings' FROM renewal_plan WHERE id = :i", i=plan["id"]
    )
    assert stored[0][0] == rec


def test_plan_records_an_override(env: Env) -> None:  # noqa: F811
    renewal = RenewalSettings(timeouts={"fip_status": 45, "volume_detach": 100},
                              healthcheck=RenewalHealthcheck(max_attempts=3))  # fmt: skip
    env.app.state.settings = env.settings.model_copy(update={"renewal": renewal})
    a = Api(env)
    r = a.op.post("/api/v1/plans", json={"managed_vm_id": a.ids["vm"]}, headers=a.h(a.op))
    assert r.status_code == 201, r.text
    rec = r.json()["resolved"]["renewal_settings"]
    assert rec["values"]["renewal.timeouts.fip_status"] == 45.0
    assert rec["values"]["renewal.timeouts.volume_detach"] == 100.0
    assert rec["values"]["renewal.healthcheck.max_attempts"] == 3
    overridden = {"renewal.timeouts.fip_status", "renewal.timeouts.volume_detach",
                  "renewal.healthcheck.max_attempts"}  # fmt: skip
    assert overridden.isdisjoint(rec["defaulted"]) and len(rec["defaulted"]) == 27
    default_worst = RenewalConfig.from_settings(env.settings).worst_case_window(
        snapshot=False, stateless=False
    )
    # W9 + S8 (+15 s each), W3 + S4 (+40 s each), one more attempt in W8 (+130 s) and S7 (start + check, +300 s)
    assert (
        r.json()["resolved"]["worst_case_window_seconds"]
        == default_worst + 2 * 15 + 2 * 40 + 130 + 300
    )


def test_plan_refused_when_the_profile_asks_more_than_the_step_bound(env: Env) -> None:  # noqa: F811
    a = Api(env)
    # a new profile version (versions are immutable) whose automation asks the runner for 600 s of quiesce
    env.sql(
        "INSERT INTO profile_version (id, profile_id, number, spec, spec_hash, automation_sha, created_by) "
        "SELECT :i, profile_id, 2, jsonb_set(spec, '{automation,timeouts}', '{\"quiesce\": 600}'), spec_hash, "
        "automation_sha, created_by FROM profile_version WHERE number = 1",
        i=new_id(),
    )
    env.sql("UPDATE profile SET latest_version = 2")
    r = a.op.post("/api/v1/plans", json={"managed_vm_id": a.ids["vm"]}, headers=a.h(a.op))
    assert r.status_code == 409 and r.json()["code"] == "renewal-timeouts-inconsistent", r.text
    assert "quiesce (600 s > 120 s)" in r.json()["detail"]


def test_plan_needs_every_key_of_a_hand_built_config(env: Env) -> None:  # noqa: F811
    """A config built without the defaults (tools, tests) is still refused with the list of missing keys."""
    a = Api(env)
    partial = RenewalConfig(timeouts={"green_build": 900.0})
    with env.owner.connect() as c:
        prow = c.execute(text("SELECT * FROM policy")).mappings().one()
        with pytest.raises(DomainError) as exc:
            resolve_plan(c, UUID(a.ids["vm"]), partial, policy_row=prow)
    assert exc.value.code == "renewal-config-incomplete"
    assert "timeouts.fip_status" in exc.value.detail


def test_plan_approval_start_and_run_actions(env: Env) -> None:  # noqa: F811
    configure(env)
    a = Api(env)
    r = a.op.post("/api/v1/plans", json={"managed_vm_id": a.ids["vm"]}, headers=a.h(a.op))
    assert r.status_code == 201, r.text
    plan = r.json()
    assert plan["state"] == "draft" and plan["resolved"]["first_use"] is False
    assert plan["blast_radius"]["floating_ip"] == "192.0.2.10"
    assert (
        a.other.get(f"/api/v1/plans/{plan['id']}").status_code == 404
    )  # out of scope reads as not found

    r = a.op.post(f"/api/v1/plans/{plan['id']}/approval-requests", headers=a.h(a.op))
    assert r.status_code == 201, r.text
    appr = r.json()
    assert str(a.op.get("/api/v1/session").json()["user_id"]) in appr["requester_set"]

    # the operator cannot decide (approver role, human session); the approver needs a step-up for this approval
    r = a.op.post(f"/api/v1/approvals/{appr['id']}/decision",
                  json={"decision": "approved", "stepup_id": new_id()}, headers=a.h(a.op))  # fmt: skip
    assert r.status_code == 403
    r = a.ap.post(f"/api/v1/approvals/{appr['id']}/decision",
                  json={"decision": "approved", "stepup_id": new_id()}, headers=a.h(a.ap))  # fmt: skip
    assert r.status_code == 403 and r.json()["code"] == "stepup-invalid"
    su = a.stepup(a.ap, a.ap_secret, "approval.decide", appr["id"])
    r = a.ap.post(f"/api/v1/approvals/{appr['id']}/decision",
                  json={"decision": "approved", "stepup_id": su}, headers=a.h(a.ap))  # fmt: skip
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "approved" and r.json()["self_approved"] is False

    # start: readiness must be ready; Idempotency-Key required; replay returns the same run
    start = f"/api/v1/plans/{plan['id']}/start"
    r = a.op.post(start, headers=a.h(a.op, **{"Idempotency-Key": "k-start-0001"}))
    assert r.status_code == 409 and r.json()["code"] == "readiness-not-ready"
    env.sql(
        "INSERT INTO readiness_assessment (id, managed_vm_id, input_snapshot, level, summary, workflow_run_id) "
        "VALUES (:i, :v, '{}', 'ready', '{}', :w)", i=new_id(), v=a.ids["vm"], w=new_id(),
    )  # fmt: skip
    assert a.op.post(start, headers=a.h(a.op)).status_code == 400  # no Idempotency-Key
    r = a.op.post(start, headers=a.h(a.op, **{"Idempotency-Key": "k-start-0002"}))
    assert r.status_code == 202, r.text
    run = r.json()
    assert run["state"] == "requested" and r.headers["Location"] == f"/api/v1/runs/{run['id']}"
    again = a.op.post(start, headers=a.h(a.op, **{"Idempotency-Key": "k-start-0002"}))
    assert again.status_code == 202 and again.json()["id"] == run["id"]
    assert (
        a.op.post(start, headers=a.h(a.op, **{"Idempotency-Key": "k-start-0003"})).status_code
        == 409
    )

    body = a.op.get(f"/api/v1/runs/{run['id']}").json()
    assert body["available_actions"][0]["action"] == "abort"
    assert a.other.get(f"/api/v1/runs/{run['id']}").status_code == 404

    # destructive action: TC checked server-side against current values, step-up bound to (run.abort, run)
    act = f"/api/v1/runs/{run['id']}/actions/abort"
    blue_tc = f"app01-prod {a.ids['blue'][-6:]}"
    r = a.op.post(act, json={"typed_confirmation": "nope 123456", "stepup_id": new_id()},
                  headers=a.h(a.op, **{"Idempotency-Key": "k-abort-0001"}))  # fmt: skip
    assert r.status_code == 422 and r.json()["code"] == "confirmation-mismatch"
    su = a.stepup(a.op, None, "run.abort", run["id"])
    r = a.op.post(act, json={"typed_confirmation": blue_tc, "stepup_id": su},
                  headers=a.h(a.op, **{"Idempotency-Key": "k-abort-0002"}))  # fmt: skip
    assert r.status_code == 202, r.text
    assert r.json()["pending_signals"][0]["kind"] == "abort"
    sig = env.sql("SELECT kind, payload FROM run_signal WHERE run_id = :r", r=run["id"])
    assert sig[0][0] == "abort" and sig[0][1]["typed_confirmation"] == blue_tc
    acts = [
        x[0] for x in env.sql("SELECT action FROM audit_event WHERE target_id = :r", r=run["id"])
    ]
    assert "run.start" in acts and "run.abort.request" in acts

    # cutover request outside the G2 gate is refused
    r = a.op.post(f"/api/v1/runs/{run['id']}/cutover-request", headers=a.h(a.op))
    assert r.status_code == 409 and r.json()["code"] == "not-awaiting-cutover"
