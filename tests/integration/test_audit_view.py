# ruff: noqa: F811
"""``GET /api/v1/audit`` and the ``/audit`` page (E6-4): real app, real PostgreSQL, real sessions and tokens.

Rows are written as the owner (test set-up); the reading side runs as the ``ovlm_api`` role through the app. The
renewal world of ``test_renewal_ui`` gives a project (``w.ids["scope"]``), an operator and an approver of it, a viewer
of another project, and seeded runs with steps.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from ovlm.workflow.ids import new_id
from tests.integration.auth_support import Env
from tests.integration.auth_support import env as env  # noqa: F401 - fixture
from tests.integration.test_renewal_ui import World, api_token

ADMIN_ONLY = (
    "auth.login.success",
    "authz.denied",
    "token.revoke",
    "user.create",
    "role_binding.create",
)


def put(
    e: Env, action: str, *, scope: str | None, target_type: str = "service", target_id: str | None = None,
    run: str | None = None, step: str | None = None, actor: UUID | None = None, ts: datetime | None = None,
    after: dict[str, Any] | None = None, result: str = "success",
) -> int:  # fmt: skip
    rows = e.sql(
        "INSERT INTO audit_event (ts, actor_id, principal_type, auth_method, project_scope, action, target_type, "
        "target_id, after, result, run_id, step_id) VALUES (COALESCE(:ts, now()), :actor, 'human', 'session', :scope, "
        ":action, :tt, :tid, CAST(:after AS jsonb), :result, :run, :step) RETURNING id",
        ts=ts, actor=actor, scope=scope, action=action, tt=target_type, tid=target_id,
        after=json.dumps(after) if after is not None else None, result=result, run=run, step=step,
    )  # fmt: skip
    return int(rows[0][0])


def ids(r: Any) -> list[int]:
    assert r.status_code == 200, r.text
    return [i["id"] for i in r.json()["items"]]


def as_admin(w: World, name: str = "adm1", scope: str = "global") -> TestClient:
    c, _ = w.e.user_client(name, [("admin", scope)])
    return c


# --- scoping --------------------------------------------------------------------------------------------------------


def test_project_scoped_callers_never_see_another_projects_events(env: Env) -> None:
    w = World(env)
    mine, theirs = w.ids["scope"], f"project:{uuid4()}"
    a = put(env, "service.create", scope=mine)
    b = put(env, "service.create", scope=theirs)
    g = put(
        env, "settings.update", scope=None, target_type="settings"
    )  # no project: global readers only
    glob, _ = env.user_client("glob-viewer", [("viewer", "global")])

    assert ids(w.op.get("/api/v1/audit")) == [a]  # an operator scoped to one project
    assert ids(glob.get("/api/v1/audit")) == [g, b, a]
    other = w.other.get("/api/v1/audit")  # a viewer of a third project sees nothing, not even a 403
    assert other.status_code == 200 and other.json() == {"items": [], "next_cursor": None}
    # filters cannot reach across projects either
    assert ids(w.op.get("/api/v1/audit", params={"target": "x"})) == []
    assert w.op.get("/api/v1/audit").json()["items"][0]["project_scope"] == mine
    assert env.client().get("/api/v1/audit").status_code == 401


def test_events_of_a_run_without_a_scope_follow_the_runs_project(env: Env) -> None:
    w = World(env)
    run = w.seed_run(w.approved_plan())
    row = put(
        env, "step.outcome", scope=None, run=run, target_type="workflow_step", target_id=new_id()
    )
    assert row in ids(
        w.op.get("/api/v1/audit")
    )  # the worker wrote it without a scope; the plan's project is mine
    assert row not in ids(w.other.get("/api/v1/audit"))
    glob, _ = env.user_client("glob-viewer", [("viewer", "global")])
    assert row in ids(glob.get("/api/v1/audit"))


# --- admin-only actions (SEC-R-31) ----------------------------------------------------------------------------------------


def test_authentication_token_and_user_events_are_for_global_admins_only(env: Env) -> None:
    w = World(env)
    mine = w.ids["scope"]
    visible = put(env, "service.create", scope=mine)
    hidden = [put(env, action, scope=mine) for action in ADMIN_ONLY]
    hidden += [put(env, action, scope=None) for action in ADMIN_ONLY]
    viewer, _ = env.user_client("viewer-mine", [("viewer", mine)])
    glob_op, _ = env.user_client("glob-op", [("operator", "global")])
    project_admin = as_admin(w, "padm", mine)
    for who in (viewer, w.op, glob_op, project_admin):
        got = ids(who.get("/api/v1/audit"))
        assert not set(got) & set(hidden), who
        assert visible in got or who is glob_op
    # filters cannot be used to dig them out
    actions = {i["action"] for i in glob_op.get("/api/v1/audit").json()["items"]}
    assert actions.isdisjoint(ADMIN_ONLY)
    for target in (None, "x"):
        r = viewer.get(
            "/api/v1/audit",
            params={"actor": str(uuid4())} if target is None else {"target": target},
        )
        assert ids(r) == []
    admin = as_admin(w)
    assert set(hidden) | {visible} <= set(ids(admin.get("/api/v1/audit", params={"limit": 200})))


# --- run= filter ----------------------------------------------------------------------------------------------------------


def test_run_filter_returns_the_whole_trail_of_one_run(env: Env) -> None:
    w = World(env)
    mine = w.ids["scope"]
    plan = w.approved_plan()
    step = new_id()
    run = w.seed_run(plan, steps=[{"key": "preflight", "state": "succeeded", "id": step}])
    other_step = new_id()
    other_run = w.seed_run(
        plan,
        state="completed",
        steps=[{"key": "preflight", "state": "succeeded", "id": other_step}],
    )
    approval = new_id()
    env.sql(
        "INSERT INTO approval (id, subject_type, subject_id, plan_id, run_id, scope, bound_hash, requested_by) "
        "SELECT :a, 'cutover', :r, :p, :r, :s, 'h', requested_by FROM approval LIMIT 1",
        a=approval, r=run, p=plan, s=mine,
    )  # fmt: skip
    expected = [
        put(
            env, "run.start", scope=mine, target_type="renewal_run", target_id=run
        ),  # the run as the target
        put(env, "renewal.cutover", scope=None, run=run, target_type="renewal_run", target_id=run),
        put(
            env,
            "step.claim",
            scope=None,
            run=run,
            step=step,
            target_type="workflow_step",
            target_id=step,
        ),
        put(
            env, "lease.release", scope=mine, target_type="workflow_step", target_id=step
        ),  # step target, no run id
        put(env, "approval.decide", scope=mine, target_type="approval", target_id=approval),
    ]
    put(env, "run.start", scope=mine, target_type="renewal_run", target_id=other_run)
    put(
        env,
        "step.claim",
        scope=None,
        run=other_run,
        step=other_step,
        target_type="workflow_step",
        target_id=other_step,
    )
    put(env, "service.create", scope=mine)

    got = w.op.get("/api/v1/audit", params={"run": run}).json()["items"]
    assert set(expected) <= {i["id"] for i in got}
    # AU-1: the plan's own events come with the run: plan.create, and the approvals of the plan (G1 is the plan's)
    extra = [i for i in got if i["id"] not in expected]
    assert extra and {i["action"] for i in extra} <= {
        "plan.create",
        "approval.request",
        "approval.decide",
    }
    assert all(i["target_type"] in ("renewal_plan", "approval") for i in extra)
    assert any(
        i["action"] == "approval.decide" and i["target_type"] == "approval" for i in extra
    )  # G1
    assert (
        w.other.get("/api/v1/audit", params={"run": run}).json()["items"] == []
    )  # invisible project: nothing
    assert w.op.get("/api/v1/audit", params={"run": "not-a-uuid"}).status_code == 422


# --- other filters, shape, pagination -------------------------------------------------------------------------------------------


def test_actor_target_and_time_filters_and_the_recorded_shape(env: Env) -> None:
    w = World(env)
    mine = w.ids["scope"]
    who = w.op.get("/api/v1/session").json()["user_id"]
    now = datetime.now(UTC)
    old = put(
        env,
        "service.update",
        scope=mine,
        target_id="svc-1",
        ts=now - timedelta(days=3),
        actor=UUID(who),
    )
    new = put(
        env,
        "service.update",
        scope=mine,
        target_id="svc-2",
        after={"name": "App", "changed_fields": ["owner_contact"]},
    )
    q = "/api/v1/audit"
    assert ids(w.op.get(q, params={"actor": who})) == [old]
    assert ids(w.op.get(q, params={"target": "svc-2"})) == [new]
    assert ids(w.op.get(q, params={"from": (now - timedelta(days=1)).isoformat()})) == [new]
    assert ids(w.op.get(q, params={"to": (now - timedelta(days=1)).isoformat()})) == [old]
    assert ids(w.op.get(q, params={"from": (now - timedelta(days=1)).strftime("%Y-%m-%d")})) == [
        new
    ]
    assert w.op.get(q, params={"from": "yesterday"}).status_code == 422
    item = w.op.get(q, params={"target": "svc-2"}).json()["items"][0]
    assert (
        item["after"] == {"name": "App", "changed_fields": ["owner_contact"]}
        and item["before"] is None
    )
    assert set(item) == {
        "id", "ts", "actor_id", "principal_type", "auth_method", "source_ip", "project_scope", "action",
        "target_type", "target_id", "before", "after", "result", "run_id", "step_id", "request_id", "authority_ref",
    }  # fmt: skip


def test_pagination_newest_first_with_a_maximum(env: Env) -> None:
    w = World(env)
    mine = w.ids["scope"]
    rows = [put(env, "service.update", scope=mine, target_id=f"s{i}") for i in range(5)]
    seen: list[int] = []
    cursor = None
    pages = 0
    while True:
        r = w.op.get("/api/v1/audit", params={"limit": 2, **({"cursor": cursor} if cursor else {})})
        assert r.status_code == 200
        seen += [i["id"] for i in r.json()["items"]]
        cursor, pages = r.json()["next_cursor"], pages + 1
        if cursor is None:
            break
    assert pages == 3 and seen == sorted(rows, reverse=True)
    assert w.op.get("/api/v1/audit", params={"limit": 201}).status_code == 422
    assert w.op.get("/api/v1/audit", params={"limit": 0}).status_code == 422
    bad = w.op.get("/api/v1/audit", params={"cursor": "garbage"})
    assert bad.status_code == 400 and bad.json()["code"] == "invalid-cursor"
    assert w.op.get("/api/v1/audit", params={"limit": 200}).json()["next_cursor"] is None


# --- API tokens -------------------------------------------------------------------------------------------------------------


def test_a_read_token_may_read_the_audit_but_only_its_project_and_no_admin_events(env: Env) -> None:
    w = World(env)
    mine = w.ids["scope"]
    a = put(env, "service.create", scope=mine)
    put(env, "service.create", scope=f"project:{uuid4()}")
    put(env, "token.revoke", scope=mine)
    anon = env.client()
    read = api_token(w, w.op, ["read"])
    assert ids(anon.get("/api/v1/audit", headers=read)) == [a]
    # a token of a global admin is still not an admin: no admin-only events
    admin = as_admin(w)
    r = admin.post(
        "/api/v1/tokens",
        json={"name": "adm-read", "scopes": ["read"], "project_scope": "global"},
        headers=w.h(admin),
    )
    assert r.status_code == 201, r.text
    got = anon.get(
        "/api/v1/audit",
        params={"limit": 200},
        headers={"Authorization": f"Bearer {r.json()['token']}"},
    )
    assert (
        "token.revoke" not in {i["action"] for i in got.json()["items"]} and got.status_code == 200
    )
    assert (
        anon.get("/api/v1/audit", headers={"Authorization": "Bearer ovlm_bad_token"}).status_code
        == 401
    )


# --- the page ---------------------------------------------------------------------------------------------------------------


def test_audit_page_renders_filters_scopes_and_links_from_the_run(env: Env) -> None:
    w = World(env)
    mine = w.ids["scope"]
    run = w.seed_run(w.approved_plan())
    put(
        env,
        "service.create",
        scope=mine,
        target_id="svc-visible",
        after={"name": "<script>alert(1)</script>"},
    )
    put(env, "service.create", scope=f"project:{uuid4()}", target_id="svc-foreign")
    put(env, "token.revoke", scope=mine, target_id="tok-hidden")
    put(env, "renewal.cutover", scope=None, run=run, target_type="renewal_run", target_id=run)

    r = w.op.get("/audit")
    assert r.status_code == 200
    t = r.text
    assert (
        "<h1>Audit</h1>" in t
        and "service.create" in t
        and "svc-visible" in t
        and "renewal.cutover" in t
    )
    assert "svc-foreign" not in t and "tok-hidden" not in t and "token.revoke" not in t
    assert (
        "<script>alert(1)</script>" not in t and r"\u003cscript\u003e" in t
    )  # recorded values are escaped
    assert "style=" not in t and "arrives with backlog" not in t
    assert re.search(
        r'<form[^>]*hx-get="/audit"[^>]*hx-target="#results"', t
    )  # HTMX, with a plain GET fallback
    assert 'name="run"' in t and 'name="from"' in t and 'name="to"' in t
    # the run filter shows the run's trail
    rr = w.op.get("/audit", params={"run": run})
    assert "renewal.cutover" in rr.text and "service.create" not in rr.text
    # HTMX request: same content (the page swaps #results)
    assert (
        "renewal.cutover"
        in w.op.get("/audit", params={"run": run}, headers={"HX-Request": "true"}).text
    )
    # other project's viewer and the admin
    o = w.other.get("/audit")
    assert (
        o.status_code == 200
        and "service.create" not in o.text
        and "No audit events match" in o.text
    )
    admin = as_admin(w)
    assert "token.revoke" in admin.get("/audit").text
    # bad input is explained, not a 500
    bad = w.op.get("/audit", params={"run": "nope", "from": "yesterday"})
    assert bad.status_code == 422 and "run id" in bad.text and "from filter" in bad.text
    assert w.op.get("/audit", params={"cursor": "garbage"}).status_code == 200
    # the run page links to the trail; anonymous goes to login
    page = w.op.get(f"/renewals/runs/{run}")
    assert f'href="/audit?run={run}"' in page.text
    anon = env.client().get("/audit", follow_redirects=False)
    assert anon.status_code == 303 and anon.headers["location"] == "/login"


def test_audit_page_paginates_with_a_next_link(env: Env) -> None:
    w = World(env)
    for i in range(53):
        put(env, "service.update", scope=w.ids["scope"], target_id=f"s{i:03d}")
    first = w.op.get("/audit", params={"target": ""})
    m = re.search(r'rel="next" href="(/audit\?[^"]+)"', first.text)
    assert m and "s052" in first.text and "s002" not in first.text
    second = w.op.get(m.group(1).replace("&amp;", "&"))
    assert second.status_code == 200 and "s002" in second.text and "s052" not in second.text
    assert 'rel="next"' not in second.text
