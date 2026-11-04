# ruff: noqa: F811
"""HTTP-level tests of the renewal pages (E6-3, E6-4): real app, real PostgreSQL, real login sessions and TOTP.

They render each page for each role, check the CSRF token on every form and that a missing or wrong one is refused,
check what is visible to whom (viewer, operator, approver, a user of another project, an API token), and check that
the typed confirmation, the step-up, the separation of duties and the human-session rule are enforced by the server
when the browser form is bypassed. Run states the engine would produce are seeded as rows; the engine itself is
covered by ``tests/integration/renewal``.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient

from ovlm.workflow.ids import new_id
from tests.integration.auth_support import ORIGIN, PASSWORD, Env
from tests.integration.auth_support import env as env  # noqa: F401 - fixture
from tests.integration.renewal.test_api import Api, configure

POST_FORM = re.compile(r"<form([^>]*method=\"post\"[^>]*)>(.*?)</form>", re.S)


class World(Api):
    """The renewal API world plus helpers to drive the UI like a browser."""

    def __init__(self, e: Env) -> None:
        configure(e)
        super().__init__(e)
        self.e = e
        e.sql(
            "DELETE FROM renewal_plan"
        )  # the seed's ready-made plan: these tests make their own through the UI

    # -- browser-ish helpers -------------------------------------------------------------------------------

    def csrf(self, c: TestClient) -> str:
        return str(c.get("/api/v1/session").json()["csrf_token"])

    def post(
        self,
        c: TestClient,
        url: str,
        data: dict[str, str] | None = None,
        *,
        token: str | None = None,
    ) -> Any:
        body = dict(data or {})
        body["csrf_token"] = token if token is not None else self.csrf(c)
        return c.post(url, data=body, headers={"Origin": ORIGIN}, follow_redirects=False)

    def totp(self, secret: str | None) -> dict[str, str]:
        self.e.clock.advance()
        return {"password": PASSWORD, **({"totp_code": self.e.code(secret)} if secret else {})}

    # -- data ------------------------------------------------------------------------------------------------

    def ready(self) -> None:
        self.e.sql(
            "INSERT INTO readiness_assessment (id, managed_vm_id, input_snapshot, level, summary, workflow_run_id) "
            "VALUES (:i, :v, '{}', 'ready', '{}', :w)", i=new_id(), v=self.ids["vm"], w=new_id(),
        )  # fmt: skip

    def make_plan(self) -> str:
        r = self.post(self.op, "/renewals/plans", {"managed_vm_id": self.ids["vm"]})
        assert r.status_code == 303, r.text
        return str(r.headers["location"].split("?")[0].rsplit("/", 1)[1])

    def request_g1(self, plan_id: str) -> str:
        r = self.post(self.op, f"/renewals/plans/{plan_id}/approval-requests")
        assert r.status_code == 303 and r.headers["location"].startswith("/approvals/"), r.text
        return str(r.headers["location"].split("?")[0].rsplit("/", 1)[1])

    def approve(self, approval_id: str, *, typed: str | None = None) -> Any:
        data = {"decision": "approved", **self.totp(self.ap_secret)}
        if typed is not None:
            data["typed_confirmation"] = typed
        return self.post(self.ap, f"/approvals/{approval_id}/decision", data)

    def approved_plan(self) -> str:
        plan = self.make_plan()
        assert self.approve(self.request_g1(plan)).status_code == 303
        return plan

    def seed_run(
        self,
        plan_id: str,
        *,
        state: str = "running",
        phase: str = "build",
        steps: list[dict[str, Any]] | None = None,
        **cols: Any,
    ) -> str:
        run = new_id()
        base: dict[str, Any] = {
            "id": run, "state": state, "plan": plan_id, "svc": self.ids["service"], "phase": phase,
            "nh": cols.pop("needs_human_reason", None), "dt": cols.pop("downtime_started_at", None),
            "dte": cols.pop("downtime_ended_at", None),
            "truth": json.dumps(cols.pop("current_truth")) if "current_truth" in cols else None,
            "truth_at": cols.pop("current_truth_at", None), "u": None,
        }  # fmt: skip
        user = self.e.sql("SELECT id FROM app_user WHERE username = 'op1'")
        base["u"] = user[0][0] if user else None
        self.e.sql(
            "INSERT INTO workflow_run (id, kind, strategy, strategy_version, state, renewal_plan_id, service_id, phase, "
            "needs_human_reason, downtime_started_at, downtime_ended_at, current_truth, current_truth_at, started_by, "
            "finished_at) VALUES (:id, 'renewal', 'bluegreen_fip_v1', '1', :state, :plan, :svc, :phase, :nh, :dt, :dte, "
            "CAST(:truth AS jsonb), :truth_at, :u, CASE WHEN :state IN ('completed', 'rolled_back', 'failed', "
            "'rejected', 'cancelled') THEN now() END)", **base,
        )  # fmt: skip
        for seq, step in enumerate(steps or [], start=1):
            self.e.sql(
                "INSERT INTO workflow_step (id, run_id, seq, step_key, state, attempt, evidence, error_class, error, "
                "destructive, lease_owner, lease_expires_at, fencing_token, heartbeat_at, finished_at) VALUES (:id, :r, "
                ":seq, :key, :state, :attempt, CAST(:ev AS jsonb), :ec, CAST(:err AS jsonb), :d, :lo, :le, :ft, :hb, :fin)",
                id=step.get("id", new_id()), r=run, seq=seq, key=step["key"], state=step["state"],
                attempt=step.get("attempt", 1), ev=json.dumps(step["evidence"]) if "evidence" in step else None,
                ec=step.get("error_class"), err=json.dumps(step["error"]) if "error" in step else None,
                d=step.get("destructive", False), lo=step.get("lease_owner"), le=step.get("lease_expires_at"),
                ft=1 if step["state"] == "running" else None, hb=step.get("heartbeat_at"),
                fin=datetime.now(UTC) if step["state"] in ("succeeded", "failed") else None,
            )  # fmt: skip
        return run


def forms_carry_csrf(html: str, token: str) -> int:
    """Every ``<form method="post">`` has the hidden CSRF field with this session's token. Returns the count."""
    forms = [(tag, body) for tag, body in POST_FORM.findall(html) if "/logout" not in tag]
    for _, body in forms:
        assert f'name="csrf_token" value="{token}"' in body, body[:200]
    return len(forms)


def api_token(w: World, c: TestClient, scopes: list[str]) -> dict[str, str]:
    body = {"name": "t" + uuid4().hex[:6], "scopes": scopes, "project_scope": w.ids["scope"]}
    r = c.post("/api/v1/tokens", json=body, headers=w.h(c))
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


# --- planning page ----------------------------------------------------------------------------------------------


def test_planning_page_lists_upcoming_renewals_with_readiness_and_creates_a_plan(env: Env) -> None:
    w = World(env)
    r = w.op.get("/renewals")
    assert r.status_code == 200
    assert "app01-prod" in r.text and "Upcoming renewals" in r.text
    assert (
        "not assessed" in r.text and "Advisory" not in r.text.split("Quota")[0]
    )  # the quota column exists
    assert "Quota (advisory)" in r.text
    assert forms_carry_csrf(r.text, w.csrf(w.op)) >= 1 and "Create plan" in r.text
    assert "style=" not in r.text
    # a viewer sees the same table without the create form; a user of another project sees nothing of it
    viewer, _ = env.user_client("viewer1", [("viewer", w.ids["scope"])])
    v = viewer.get("/renewals")
    assert (
        v.status_code == 200
        and "app01-prod" in v.text
        and "Create plan" not in v.text
        and "needs the operator role" in v.text
    )
    assert "app01-prod" not in w.other.get("/renewals").text
    w.ready()
    assert "Ready" in w.op.get("/renewals").text


def test_create_plan_needs_csrf_operator_and_a_valid_vm(env: Env) -> None:
    w = World(env)
    data = {"managed_vm_id": w.ids["vm"]}
    assert (
        w.op.post("/renewals/plans", data=data, headers={"Origin": ORIGIN}).status_code == 403
    )  # no token
    assert w.post(w.op, "/renewals/plans", data, token="forged").status_code == 403
    assert (
        w.op.post(
            "/renewals/plans",
            data={**data, "csrf_token": w.csrf(w.op)},
            headers={"Origin": "https://evil.example"},
        ).status_code
        == 403
    )
    viewer, _ = env.user_client("viewer1", [("viewer", w.ids["scope"])])
    assert w.post(viewer, "/renewals/plans", data).status_code == 403
    assert w.post(w.other, "/renewals/plans", data).status_code == 403
    bad = w.post(w.op, "/renewals/plans", {"managed_vm_id": "nope"})
    assert bad.status_code == 422 and "Choose a VM" in bad.text
    assert (
        w.post(
            w.op, "/renewals/plans", {**data, "planned_window_start": "tomorrow-ish"}
        ).status_code
        == 422
    )
    r = w.post(w.op, "/renewals/plans", {**data, "planned_window_start": "2026-12-01T02:00"})
    assert r.status_code == 303 and r.headers["location"].startswith("/renewals/plans/")
    assert env.sql("SELECT count(*) FROM audit_event WHERE action = 'plan.create'")[0][0] == 1


def test_plan_page_shows_what_is_touched_and_enforces_scope(env: Env) -> None:
    w = World(env)
    plan = w.make_plan()
    r = w.op.get(f"/renewals/plans/{plan}")
    assert r.status_code == 200
    for needle in (
        "app01-prod",
        "192.0.2.10",
        "Worst-case downtime",
        "Plan hash",
        "Request plan approval (G1)",
        "Starting a run is refused",
    ):
        assert needle in r.text, needle
    assert forms_carry_csrf(r.text, w.csrf(w.op)) == 1
    assert "Start run" not in r.text  # not approved yet
    assert w.other.get(f"/renewals/plans/{plan}").status_code == 404
    assert w.ap.get(f"/renewals/plans/{plan}").status_code == 200
    assert (
        "Request plan approval" not in w.ap.get(f"/renewals/plans/{plan}").text
    )  # approvers do not request
    assert w.op.get(f"/renewals/plans/{uuid4()}").status_code == 404
    assert w.op.get("/renewals/plans/not-a-uuid").status_code == 404


# --- approval page (G1) -----------------------------------------------------------------------------------------


def test_g1_page_shows_every_hash_input_and_the_requester_set(env: Env) -> None:
    w = World(env)
    plan = w.make_plan()
    aid = w.request_g1(plan)
    page = w.ap.get(f"/approvals/{aid}")
    assert page.status_code == 200
    t = page.text
    for needle in (
        "G1", "Profile version", "spec hash", "https://git.example.invalid/app.git", "a" * 40,
        "first approval of this repository", "app01-prod", w.ids["blue"], "192.0.2.10", w.ids["volume"],
        "/srv/data", "ubuntu-24.04", "m1.small", "Policy: policy version", "automatic restore in the window",
        "maximum window duration", "Plan hash bound", "Requester set", "op1", "Record my decision",
    ):  # fmt: skip
        assert needle in t, needle
    assert forms_carry_csrf(t, w.csrf(w.ap)) == 1
    assert (
        'name="password"' in t and 'name="totp_code"' in t and 'name="typed_confirmation"' not in t
    )  # G1: no TC
    assert w.other.get(f"/approvals/{aid}").status_code == 404
    assert w.ap.get(f"/approvals/{uuid4()}").status_code == 404
    # the plan's creator may read it but cannot decide it
    op = w.op.get(f"/approvals/{aid}")
    assert (
        op.status_code == 200
        and "You cannot decide this" in op.text
        and "approver role" in op.text
        and 'name="decision"' not in op.text
    )


def test_g1_decision_checks_csrf_password_and_totp_and_unlocks_start(env: Env) -> None:
    w = World(env)
    plan = w.make_plan()
    aid = w.request_g1(plan)
    url = f"/approvals/{aid}/decision"
    data = {"decision": "approved", "password": PASSWORD}
    assert w.ap.post(url, data=data, headers={"Origin": ORIGIN}).status_code == 403  # no CSRF token
    assert w.post(w.ap, url, data, token="forged").status_code == 403

    def state() -> Any:
        return env.sql("SELECT decision FROM approval WHERE id = :i", i=aid)[0][0]

    wrong = w.post(
        w.ap, url, {**w.totp(w.ap_secret), "decision": "approved", "password": "not-my-password"}
    )
    assert (
        wrong.status_code == 401
        and "Password or code not accepted" in wrong.text
        and state() is None
    )
    no_code = w.post(w.ap, url, {"decision": "approved", "password": PASSWORD})
    assert no_code.status_code in (401, 403) and state() is None
    r = w.approve(aid)
    assert r.status_code == 303 and r.headers["location"] == f"/approvals/{aid}?notice=decided"
    assert state() == "approved"
    done = w.ap.get(r.headers["location"])
    assert (
        "Your decision is recorded" in done.text
        and "approved" in done.text
        and "Record my decision" not in done.text
    )
    assert "approval.decide" in [
        x[0] for x in env.sql("SELECT action FROM audit_event WHERE target_id = :i", i=aid)
    ]
    # a second decision on a closed approval is refused by the service
    again = w.approve(aid)
    assert again.status_code == 409 and "already approved" in again.text
    # the plan page now offers the run, and starting is refused until readiness is ready
    page = w.op.get(f"/renewals/plans/{plan}")
    assert "Start run" in page.text and forms_carry_csrf(page.text, w.csrf(w.op)) == 1
    key = re.search(r'name="idempotency_key" value="([0-9a-f]+)"', page.text)
    assert key
    refused = w.post(w.op, f"/renewals/plans/{plan}/start", {"idempotency_key": key.group(1)})
    assert refused.status_code == 409 and "VM not ready" in refused.text
    w.ready()
    started = w.post(w.op, f"/renewals/plans/{plan}/start", {"idempotency_key": key.group(1)})
    assert started.status_code == 303 and started.headers["location"].startswith("/renewals/runs/")
    replay = w.post(w.op, f"/renewals/plans/{plan}/start", {"idempotency_key": key.group(1)})
    assert replay.headers["location"] == started.headers["location"]  # same key, same run
    assert env.sql("SELECT count(*) FROM workflow_run")[0][0] == 1
    no_key = w.post(w.op, f"/renewals/plans/{plan}/start", {})
    assert no_key.status_code == 400 and "Idempotency-Key" in no_key.text


def test_decision_is_refused_for_api_tokens_and_the_page_says_why(env: Env) -> None:
    w = World(env)
    aid = w.request_g1(w.make_plan())
    bearer = api_token(w, w.ap, ["read"])
    bare = env.client()
    page = bare.get(f"/approvals/{aid}", headers=bearer)
    assert page.status_code == 200
    assert (
        "API tokens cannot approve" in page.text
        and 'name="decision"' not in page.text
        and 'name="password"' not in page.text
    )
    r = bare.post(
        f"/approvals/{aid}/decision",
        data={"decision": "approved", "password": PASSWORD},
        headers=bearer,
    )
    assert r.status_code == 403 and "API tokens cannot approve" in r.text
    assert env.sql("SELECT decision FROM approval WHERE id = :i", i=aid)[0][0] is None
    # the same through the API: the UI offers nothing the API lacks, and refuses what the API refuses
    api = bare.post(
        f"/api/v1/approvals/{aid}/decision",
        json={"decision": "approved", "stepup_id": new_id()},
        headers=bearer,
    )
    assert api.status_code == 403 and api.json()["code"] == "human-session-required"


def test_separation_of_duties_is_shown_and_enforced_and_self_approval_is_flagged(env: Env) -> None:
    w = World(env)
    plan = w.make_plan()  # created by op1
    aid = w.request_g1(plan)
    # an operator who also holds approver (granted behind the API's back, as an old binding could be)
    both, secret = env.user_client("both", [("operator", w.ids["scope"])], totp=True)
    env.sql("INSERT INTO role_binding (id, user_id, role, scope) SELECT :i, id, 'approver', :s FROM app_user WHERE username = 'both'",
            i=new_id(), s=w.ids["scope"])  # fmt: skip
    both.get("/api/v1/session")  # grants are read per request
    page = both.get(f"/approvals/{aid}")
    assert (
        "You cannot decide this" in page.text
        and "Separation of duties" in page.text
        and 'name="decision"' not in page.text
    )
    data = {"decision": "approved", **w.totp(secret)}
    forced = w.post(both, f"/approvals/{aid}/decision", data)  # the browser form bypassed
    assert (
        forced.status_code == 403
        and env.sql("SELECT decision FROM approval WHERE id = :i", i=aid)[0][0] is None
    )
    # the installation allows it: the page warns before, and flags after
    env.sql("INSERT INTO installation_setting (key, value, changed_by, reason) VALUES ('allow_operator_approver', 'true', "
            "(SELECT id FROM app_user WHERE username = 'both'), 'test')")  # fmt: skip
    warn = both.get(f"/approvals/{aid}")
    assert "recorded as self-approved" in warn.text and 'name="decision"' in warn.text
    ok = w.post(both, f"/approvals/{aid}/decision", {"decision": "approved", **w.totp(secret)})
    assert ok.status_code == 303, ok.text
    assert env.sql("SELECT self_approved FROM approval WHERE id = :i", i=aid)[0][0] is True
    after = w.op.get(f"/approvals/{aid}")
    assert "self-approved" in after.text and "Self-approved." in after.text
    assert "self-approved" in w.op.get(f"/renewals/plans/{plan}").text


# --- run page: timeline, truth, actions --------------------------------------------------------------------------


def test_run_timeline_for_a_parked_run_explains_what_to_do(env: Env) -> None:
    w = World(env)
    plan = w.approved_plan()
    now = datetime.now(UTC)
    detach = new_id()
    run = w.seed_run(
        plan, state="needs_human", phase="window", needs_human_reason="post_start_failure",
        downtime_started_at=now - timedelta(minutes=5), current_truth_at=now - timedelta(minutes=2),
        current_truth={"volume": {"status": "in-use", "attached_to": "green"}, "fip": {"port_id": "p-green", "status": "ACTIVE"}, "probe": "ok"},
        steps=[
            {"key": "preflight", "state": "succeeded", "evidence": {"checks": ["plan hash equal"], "image": {"id": "x"}}},
            {"key": "detach_volume", "state": "succeeded", "id": detach, "destructive": True, "evidence": {"volume": "available"}},
            {"key": "healthcheck_green", "state": "needs_human", "attempt": 3, "error_class": "needs_human",
             "error": {"reason": "healthcheck_exhausted", "truth": {"x": 1}}, "evidence": {"guest_says": "<script>alert(1)</script>"}},
        ],
    )  # fmt: skip
    r = w.op.get(f"/renewals/runs/{run}")
    assert r.status_code == 200
    t = r.text
    for needle in (
        "This run is stopped and needs a person", "What happened", "service had already started on the new VM",
        "What to do next", "post_start_failure", "Current truth", "attached to", "in-use", "p-green",
        "Downtime", "in progress", "of the 1h 00m budget", "What you can do now", "Probe", "Roll back",
        "blue will start on data the new VM may have changed; no snapshot exists", "Retry step", "Mark resolved",
        "B1", "Re-check the plan against the live cloud", "W3", "W8", "attempt 3",
        "includes text reported by the guest", "healthcheck_exhausted",
    ):  # fmt: skip
        assert needle in t, needle
    assert "<script>alert(1)</script>" not in t and "&lt;script&gt;" in t  # guest text is escaped
    assert "style=" not in t and forms_carry_csrf(t, w.csrf(w.op)) >= 2
    assert re.search(
        r'hx-get="/renewals/runs/[0-9a-f-]+/panel" hx-trigger="every 5s"', t
    )  # live while open
    # a viewer reads the same truth but is told why nothing is clickable
    viewer, _ = env.user_client("viewer1", [("viewer", w.ids["scope"])])
    v = viewer.get(f"/renewals/runs/{run}")
    assert (
        v.status_code == 200
        and "Current truth" in v.text
        and "You need the operator role in this project." in v.text
    )
    assert "/actions/rollback" not in v.text and "Roll back…" not in v.text
    assert w.other.get(f"/renewals/runs/{run}").status_code == 404
    assert w.other.get(f"/renewals/runs/{run}/panel").status_code == 404
    # the polled fragment has the live parts and no password field
    p = w.op.get(f"/renewals/runs/{run}/panel")
    assert (
        p.status_code == 200
        and "<html" not in p.text
        and "Current truth" in p.text
        and 'type="password"' not in p.text
    )


def test_finished_run_stops_polling_and_a_requested_run_says_it_is_waiting(env: Env) -> None:
    w = World(env)
    plan = w.approved_plan()
    done = w.seed_run(
        plan, state="completed", phase="retire", steps=[{"key": "retire_old", "state": "succeeded"}]
    )
    r = w.op.get(f"/renewals/runs/{done}")
    assert "hx-trigger" not in r.text and "The run is finished" in r.text and "Completed" in r.text
    env.sql("UPDATE workflow_run SET state = 'completed', finished_at = now()")  # free the service
    waiting = w.seed_run(plan, state="requested")
    r = w.op.get(f"/renewals/runs/{waiting}")
    assert "Waiting for the worker to admit the run" in r.text and "Abort" in r.text
    assert "no worker has reported yet" in r.text


def test_restricted_automation_links_are_for_operators_only(env: Env) -> None:
    w = World(env)
    plan = w.approved_plan()
    step = new_id()
    run = w.seed_run(plan, steps=[{"key": "configure_green", "state": "succeeded", "id": step}])
    art = new_id()
    env.sql(
        "INSERT INTO automation_run (id, step_id, attempt, phase, target_role, project_scope, repo, sha, requirements_hash, "
        "ansible_core_version, extravars_sha256, extravars_keys, classification, host_key_mode, log, events, "
        "artifact_expires_at, duration_seconds, exit_code) VALUES (:i, :s, 1, 'configure', 'new', :sc, 'r', :sha, 'h', '2', 'e', "
        "'{}', 'ok', 'pinned', 'SECRET LOG', '[]', now() + interval '1 day', 12, 0)",
        i=art, s=step, sc=w.ids["scope"], sha="a" * 40,
    )  # fmt: skip
    op = w.op.get(f"/renewals/runs/{run}")
    assert (
        f'href="/api/v1/automation-runs/{art}/artefacts"' in op.text and "SECRET LOG" not in op.text
    )
    viewer, _ = env.user_client("viewer1", [("viewer", w.ids["scope"])])
    v = viewer.get(f"/renewals/runs/{run}")
    assert (
        "Automation attempts (1)" in v.text
        and "/artefacts" not in v.text
        and "operators and admins only" in v.text
    )
    assert w.op.get(f"/api/v1/automation-runs/{art}/artefacts").status_code == 200
    assert viewer.get(f"/api/v1/automation-runs/{art}/artefacts").status_code == 403


# --- destructive actions: blast radius, typed confirmation, step-up -----------------------------------------------


def test_abort_shows_blast_radius_and_enforces_typed_confirmation_and_stepup(env: Env) -> None:
    w = World(env)
    plan = w.approved_plan()
    run = w.seed_run(plan, steps=[{"key": "configure_green", "state": "running", "lease_owner": "w1",
                                    "lease_expires_at": datetime.now(UTC) + timedelta(minutes=5), "heartbeat_at": datetime.now(UTC)}])  # fmt: skip
    page = w.op.get(f"/renewals/runs/{run}/actions/abort")
    assert page.status_code == 200
    for needle in (
        "What this will do",
        "delete green; blue" if False else "stop at the step boundary",
        "app01-prod",
        w.ids["blue"],
        w.ids["volume"],
        "192.0.2.10",
        "Typed confirmation",
        'name="password"',
    ):
        assert needle in page.text, needle
    assert (
        w.ids["blue"][-6:] in page.text and "app01-prod " + w.ids["blue"][-6:] not in page.text
    )  # the answer is not handed over
    assert forms_carry_csrf(page.text, w.csrf(w.op)) == 1
    key = re.search(r'name="idempotency_key" value="([0-9a-f]+)"', page.text)
    assert key
    url = f"/renewals/runs/{run}/actions/abort"
    tc = f"app01-prod {w.ids['blue'][-6:]}"

    def signals() -> Any:
        return env.sql("SELECT kind FROM run_signal WHERE run_id = :r", r=run)

    def stepups() -> Any:
        return env.sql("SELECT count(*) FROM stepup WHERE consumed_at IS NULL")[0][0]

    base = {"idempotency_key": key.group(1)}
    # no CSRF token, forged token
    assert (
        w.op.post(
            url,
            data={**base, "typed_confirmation": tc, "password": PASSWORD},
            headers={"Origin": ORIGIN},
        ).status_code
        == 403
    )
    assert (
        w.post(
            w.op, url, {**base, "typed_confirmation": tc, "password": PASSWORD}, token="forged"
        ).status_code
        == 403
    )
    # wrong typed confirmation: refused before a one-time code is spent
    before = stepups()
    bad = w.post(
        w.op, url, {**base, "typed_confirmation": "app01-prod 000000", "password": PASSWORD}
    )
    assert bad.status_code == 422 and "Typed confirmation does not match" in bad.text
    assert signals() == [] and stepups() == before
    # missing / wrong password
    nopw = w.post(w.op, url, {**base, "typed_confirmation": tc, "password": "wrong"})
    assert nopw.status_code == 401 and signals() == []
    # a viewer, and a user of another project, cannot do it at all
    viewer, _ = env.user_client("viewer1", [("viewer", w.ids["scope"])])
    assert (
        w.post(viewer, url, {**base, "typed_confirmation": tc, "password": PASSWORD}).status_code
        == 403
    )
    assert w.post(
        w.other, url, {**base, "typed_confirmation": tc, "password": PASSWORD}
    ).status_code in (403, 404)
    # the right thing records one signal; the same form submitted twice does not record two
    ok = w.post(w.op, url, {**base, "typed_confirmation": f"  {tc} ", "password": PASSWORD})
    assert (
        ok.status_code == 303
        and ok.headers["location"] == f"/renewals/runs/{run}?notice=request-sent"
    )
    twice = w.post(w.op, url, {**base, "typed_confirmation": f"  {tc} ", "password": PASSWORD})
    assert twice.status_code == 303 and signals() == [("abort",)]
    assert "run.abort.request" in [
        x[0] for x in env.sql("SELECT action FROM audit_event WHERE target_id = :r", r=run)
    ]
    after = w.op.get(ok.headers["location"])
    assert (
        "Request sent" in after.text
        and "Pending:" in after.text
        and "abort requested by op1" in after.text
    )


def test_actions_refuse_api_tokens_and_unknown_actions_and_probe_needs_no_confirmation(
    env: Env,
) -> None:
    w = World(env)
    plan = w.approved_plan()
    run = w.seed_run(plan, state="needs_human", needs_human_reason="api_unreachable", phase="window",
                     steps=[{"key": "stop_old", "state": "needs_human", "error_class": "needs_human"}])  # fmt: skip
    bearer = api_token(w, w.op, ["read", "operate"])
    bare = env.client()
    tc = f"app01-prod {w.ids['blue'][-6:]}"
    r = bare.post(
        f"/renewals/runs/{run}/actions/rollback",
        data={"typed_confirmation": tc, "password": PASSWORD, "idempotency_key": "k" * 12},
        headers=bearer,
    )
    assert r.status_code == 403 and "API tokens cannot approve or confirm" in r.text
    assert env.sql("SELECT count(*) FROM run_signal")[0][0] == 0
    page = bare.get(f"/renewals/runs/{run}/actions/rollback", headers=bearer)
    assert (
        page.status_code == 200
        and "API tokens cannot confirm this" in page.text
        and 'name="password"' not in page.text
    )
    assert w.op.get(f"/renewals/runs/{run}/actions/nuke").status_code == 404
    assert (
        w.post(
            w.op, f"/renewals/runs/{run}/actions/nuke", {"idempotency_key": "k" * 12}
        ).status_code
        == 404
    )
    # probe and retry-step are plain forms: no password, but still CSRF and an idempotency key
    p = w.op.get(f"/renewals/runs/{run}")
    assert (
        "Probe" in p.text and "/actions/probe" in p.text and "OpenStack stopped answering" in p.text
    )
    assert (
        w.op.get(f"/renewals/runs/{run}/actions/probe", follow_redirects=False).status_code == 303
    )
    nocsrf = w.op.post(
        f"/renewals/runs/{run}/actions/probe",
        data={"idempotency_key": "k" * 12},
        headers={"Origin": ORIGIN},
    )
    assert nocsrf.status_code == 403
    ok = w.post(w.op, f"/renewals/runs/{run}/actions/probe", {"idempotency_key": "probe-key-0001"})
    assert ok.status_code == 303
    assert env.sql("SELECT kind FROM run_signal WHERE run_id = :r", r=run) == [("probe",)]


def test_mark_resolved_needs_an_attestation_and_a_typed_confirmation(env: Env) -> None:
    w = World(env)
    plan = w.approved_plan()
    run = w.seed_run(plan, state="needs_human", needs_human_reason="volume_stuck_attaching", phase="window",
                     steps=[{"key": "attach_volume_green", "state": "needs_human", "error_class": "needs_human"}])  # fmt: skip
    page = w.op.get(f"/renewals/runs/{run}/actions/mark-resolved")
    assert "What did you do?" in page.text
    url = f"/renewals/runs/{run}/actions/mark-resolved"
    tc = f"app01-prod {w.ids['blue'][-6:]}"
    base = {"idempotency_key": "mr-key-000001", "typed_confirmation": tc, "password": PASSWORD}
    assert w.post(w.op, url, base).status_code == 422  # no attestation
    ok = w.post(w.op, url, {**base, "attestation": "admin force-detached the volume"})
    assert ok.status_code == 303
    sig = env.sql("SELECT kind, payload FROM run_signal WHERE run_id = :r", r=run)
    assert (
        sig[0][0] == "mark_resolved"
        and sig[0][1]["attestation"] == "admin force-detached the volume"
    )


# --- G2 and G3 ---------------------------------------------------------------------------------------------------


def test_g2_page_shows_the_downtime_window_the_restore_table_and_demands_the_typed_confirmation(
    env: Env,
) -> None:
    w = World(env)
    plan = w.approved_plan()
    run = w.seed_run(plan, state="running", phase="build",
                     steps=[{"key": "preflight", "state": "succeeded"}, {"key": "await_cutover", "state": "waiting"}])  # fmt: skip
    ap2, secret2 = env.user_client("ap2", [("approver", w.ids["scope"])])
    page = w.op.get(f"/renewals/runs/{run}")
    assert (
        "Request cutover approval (G2)" in page.text
        and forms_carry_csrf(page.text, w.csrf(w.op)) >= 1
    )
    assert (
        w.post(w.ap, f"/renewals/runs/{run}/cutover-request").status_code == 403
    )  # approvers do not request
    r = w.post(w.op, f"/renewals/runs/{run}/cutover-request")
    assert r.status_code == 303
    aid = r.headers["location"].split("?")[0].rsplit("/", 1)[1]
    first = w.ap.get(f"/approvals/{aid}")  # ap1 decided G1: the two-person rule bars them from G2
    assert (
        "You cannot decide this" in first.text
        and "two-person rule" in first.text
        and 'name="decision"' not in first.text
    )
    forced = w.approve(aid, typed=f"app01-prod {w.ids['blue'][-6:]}")
    assert (
        forced.status_code == 403
        and env.sql("SELECT decision FROM approval WHERE id = :i", i=aid)[0][0] is None
    )
    g2 = ap2.get(f"/approvals/{aid}")
    t = g2.text
    for needle in (
        "G2", "Cutover approval", "Worst-case downtime", "Budget you accept", "1h 00m", "revert carries green&#39;s writes forward",
        "Automatic restore: when it can happen", "W7 service start fails on the new VM", "no: stops and pages an operator",
        "W1 quiesce the old VM fails", "OpenStack API unreachable", "at most once per run", "Typed confirmation (to approve)",
        "app01-prod", w.ids["blue"][-6:],
    ):  # fmt: skip
        assert needle in t, needle
    assert forms_carry_csrf(t, w.csrf(ap2)) == 1
    url = f"/approvals/{aid}/decision"

    def unspent() -> Any:
        return env.sql("SELECT count(*) FROM stepup WHERE consumed_at IS NULL")[0][0]

    before = unspent()
    miss = w.post(ap2, url, {"decision": "approved", **w.totp(secret2)})
    assert miss.status_code == 422 and "Typed confirmation does not match" in miss.text
    wrong = w.post(
        ap2,
        url,
        {"decision": "approved", "typed_confirmation": "app01-prod 000000", **w.totp(secret2)},
    )
    assert (
        wrong.status_code == 422
        and env.sql("SELECT decision FROM approval WHERE id = :i", i=aid)[0][0] is None
    )
    assert unspent() == before  # a typo does not burn a one-time code
    ok = w.post(
        ap2,
        url,
        {
            "decision": "approved",
            "typed_confirmation": f"app01-prod {w.ids['blue'][-6:]}",
            **w.totp(secret2),
        },
    )
    assert ok.status_code == 303, ok.text
    assert env.sql("SELECT kind FROM run_signal WHERE run_id = :r", r=run) == [("approve",)]
    # rejecting needs no typed confirmation
    assert "approved" in w.op.get(f"/approvals/{aid}").text


def test_g2_without_a_cutover_approval_needs_the_operators_own_typed_confirmation(env: Env) -> None:
    w = World(env)
    env.sql(
        "UPDATE policy SET approvals = CAST(:a AS jsonb)",
        a=json.dumps({"plan": False, "cutover": False}),
    )
    plan = w.make_plan()  # made on the policy as it is now: no plan approval, no cutover approval
    run = w.seed_run(plan, steps=[{"key": "await_cutover", "state": "waiting"}])
    page = w.op.get(f"/renewals/runs/{run}")
    assert (
        "You confirm the downtime yourself" in page.text
        and "Start the downtime window" in page.text
    )
    assert (
        "Request cutover approval" not in page.text
        and forms_carry_csrf(page.text, w.csrf(w.op)) >= 1
    )
    url = f"/renewals/runs/{run}/cutover-request"
    assert w.op.post(url, data={}, headers={"Origin": ORIGIN}).status_code == 403  # no CSRF token
    bad = w.post(w.op, url, {"typed_confirmation": "nope", "password": PASSWORD})
    assert bad.status_code == 422 and "Typed confirmation does not match" in bad.text
    bearer = api_token(w, w.op, ["operate"])
    tok = env.client().post(
        url, data={"typed_confirmation": f"app01-prod {w.ids['blue'][-6:]}"}, headers=bearer
    )
    assert tok.status_code == 403 and "API tokens cannot" in tok.text
    assert env.sql("SELECT count(*) FROM approval")[0][0] == 0
    ok = w.post(
        w.op, url, {"typed_confirmation": f"app01-prod {w.ids['blue'][-6:]}", "password": PASSWORD}
    )
    assert ok.status_code == 303 and ok.headers["location"].endswith("notice=cutover-confirmed"), (
        ok.text
    )
    row = env.sql(
        "SELECT operator_confirmed, decision, auth_method FROM approval WHERE run_id = :r", r=run
    )
    assert row == [(True, "approved", row[0][2])]
    assert env.sql("SELECT kind FROM run_signal WHERE run_id = :r", r=run) == [("approve",)]


def test_g3_page_never_allows_self_approval_and_shows_the_provenance_of_the_decider(
    env: Env,
) -> None:
    w = World(env)
    plan = w.approved_plan()
    run = w.seed_run(plan, state="running", phase="retained",
                     current_truth={"green": {"status": "ACTIVE"}, "volume": {"attached_to": "green"}}, current_truth_at=datetime.now(UTC),
                     steps=[{"key": "retain_old", "state": "succeeded"}, {"key": "await_retirement", "state": "waiting"}])  # fmt: skip
    page = w.op.get(f"/renewals/runs/{run}")
    assert (
        "Request retirement approval (G3)" in page.text
        and "Deleting the old VM is irreversible" in page.text
    )
    r = w.post(w.op, f"/renewals/runs/{run}/retirement-request")
    assert r.status_code == 303
    aid = r.headers["location"].split("?")[0].rsplit("/", 1)[1]
    ap2, secret2 = env.user_client("ap2", [("approver", w.ids["scope"])])
    mine = w.ap.get(f"/approvals/{aid}")  # ap1 decided G1: not a second person
    assert "You cannot decide this" in mine.text and 'name="decision"' not in mine.text
    g3 = ap2.get(f"/approvals/{aid}")
    t = g3.text
    for needle in ("G3", "Retirement approval", "Deletes the old VM. This cannot be undone.", "What the worker will re-check before it deletes",
                   "ACTIVE", "Your account (recorded with your decision)", "created by", "Typed confirmation (to approve)"):  # fmt: skip
        assert needle in t, needle
    # the G1 approver (ap1 decided nothing here; the plan's approver is ap1 via approved_plan) is not a second person
    refused = w.post(
        w.ap,
        f"/approvals/{aid}/decision",
        {
            "decision": "approved",
            "typed_confirmation": f"app01-prod {w.ids['blue'][-6:]}",
            **w.totp(w.ap_secret),
        },
    )
    assert (
        refused.status_code == 403
        and "second" in refused.text.lower()
        or "two-person" in refused.text.lower()
    )
    assert env.sql("SELECT decision FROM approval WHERE id = :i", i=aid)[0][0] is None
    # a different approver can
    ok = w.post(
        ap2,
        f"/approvals/{aid}/decision",
        {
            "decision": "approved",
            "typed_confirmation": f"app01-prod {w.ids['blue'][-6:]}",
            **w.totp(secret2),
        },
    )
    assert ok.status_code == 303, ok.text
    done = w.op.get(f"/approvals/{aid}")
    assert "created by" in done.text and "Decider's account" in done.text


def test_pages_need_a_session_and_every_page_is_free_of_inline_styles_and_cdn(env: Env) -> None:
    w = World(env)
    plan = w.approved_plan()
    run = w.seed_run(plan, steps=[{"key": "preflight", "state": "succeeded"}])
    anon = env.client()
    for path in (
        "/renewals",
        f"/renewals/plans/{plan}",
        f"/renewals/runs/{run}",
        f"/renewals/runs/{run}/panel",
        f"/approvals/{uuid4()}",
    ):
        r = anon.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login", path
    for path in ("/renewals", f"/renewals/plans/{plan}", f"/renewals/runs/{run}"):
        t = w.ap.get(path).text
        assert "style=" not in t and not re.search(
            r'(src|href)="https?://(?!github\.com/OzarLand)', t
        ), path
