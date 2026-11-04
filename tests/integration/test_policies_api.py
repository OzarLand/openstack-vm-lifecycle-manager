# ruff: noqa: F811
"""Policies, bindings, exceptions, effective policy and deadlines against a real PostgreSQL (E3-3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.lifecycle_support import add_user, audit_rows, stepup
from tests.integration.test_registry_api import Env, env  # noqa: F401

POLICY: dict[str, Any] = {
    "name": "weekly",
    "max_age": "P90D",
    "renewal_interval": "P60D",
    "windows": [{"weekdays": ["sat"], "start": "01:00", "end": "05:00", "timezone": "UTC"}],
    "max_window_duration": "PT2H",
}


def as_admin(env: Env) -> None:
    env.as_("admin")


def make_policy(env: Env, **patch: Any) -> dict[str, Any]:
    as_admin(env)
    r = env.client.post("/api/v1/policies", json={**POLICY, **patch})
    assert r.status_code == 201, r.text
    env.as_("operator")
    return r.json()  # type: ignore[no-any-return]


def bind(env: Env, policy_id: str, scope_type: str, scope_id: str) -> dict[str, Any]:
    as_admin(env)
    r = env.client.post(
        "/api/v1/policy-bindings",
        json={"policy_id": policy_id, "scope_type": scope_type, "scope_id": scope_id},
    )
    assert r.status_code == 201, r.text
    env.as_("operator")
    return r.json()  # type: ignore[no-any-return]


def make_group(env: Env, name: str = "prod") -> str:
    return str(
        env.auth.sql(
            "INSERT INTO service_group (id, name) VALUES (gen_random_uuid(), :n) RETURNING id",
            n=name,
        )[0][0]
    )


def register_vm(env: Env, slug: str = "app01", launched_days_ago: float = 0) -> tuple[str, str]:
    svc = env.make_service(slug)
    vm = env.client.post(
        f"/api/v1/services/{svc['id']}/managed-vms",
        json={"observed_server_id": env.observed_id(env.ids["blue"])},
    )
    assert vm.status_code == 201, vm.text
    launched = datetime.now(UTC) - timedelta(days=launched_days_ago)
    with env.worker.begin() as c:  # the worker owns launched_at_effective
        c.execute(
            text("UPDATE managed_vm SET launched_at_effective = :t WHERE id = :i"),
            {"t": launched, "i": vm.json()["id"]},
        )
    return svc["id"], vm.json()["id"]


# --- policy CRUD, roles, ETag -----------------------------------------------------------------------------------------


def test_admin_creates_reads_and_every_other_role_is_refused(env: Env) -> None:
    created = make_policy(env)
    assert (
        created["max_age"] == "P90D"
        and created["max_window_duration"] == "PT2H"
        and created["version"] == 1
    )
    assert (
        created["approvals"] == {"plan": True, "cutover": True}
        and created["auto_restore_in_window"] is True
    )
    assert (
        created["snapshot_retain_after_restore"] == "until_next_renewal"
        and created["last_edited_by"]
    )

    for who in ("operator", "viewer"):
        env.as_(who)
        assert env.client.post("/api/v1/policies", json={**POLICY, "name": "x"}).status_code == 403
        assert env.client.get(f"/api/v1/policies/{created['id']}").status_code == 200
    one = env.client.get(f"/api/v1/policies/{created['id']}")
    assert one.headers["ETag"] == '"1"'
    assert [p["id"] for p in env.client.get("/api/v1/policies").json()["items"]] == [created["id"]]
    assert env.auth.client().post("/api/v1/policies", json=POLICY).status_code == 401
    assert env.client.get(f"/api/v1/policies/{uuid4()}").json()["code"] == "policy-not-found"


def test_duplicate_names_and_invalid_bodies(env: Env) -> None:
    make_policy(env)
    as_admin(env)
    dup = env.client.post("/api/v1/policies", json=POLICY)
    assert dup.status_code == 409 and dup.json()["code"] == "policy-name-taken"
    bad = {**POLICY, "name": "bad", "max_window_duration": "PT9H"}
    r = env.client.post("/api/v1/policies", json=bad)
    assert r.status_code == 422 and r.headers["content-type"].startswith("application/problem+json")
    assert r.json()["errors"][0]["message"].startswith("max_window_duration does not fit")
    no_budget = {k: v for k, v in POLICY.items() if k != "max_window_duration"} | {
        "name": "nobudget"
    }
    r = env.client.post("/api/v1/policies", json=no_budget)
    assert r.status_code == 422 and r.json()["errors"][0]["field"] == "max_window_duration"
    assert env.client.get("/api/v1/policies").json()["items"][0]["name"] == "weekly"


def test_put_and_delete_use_if_match(env: Env) -> None:
    created = make_policy(env)
    url = f"/api/v1/policies/{created['id']}"
    as_admin(env)
    body = {**POLICY, "max_age": "P30D", "renewal_interval": "P20D"}
    assert env.client.request("PUT", url, json=body).status_code == 428
    assert env.client.request("PUT", url, json=body, headers={"If-Match": '"5"'}).status_code == 412
    ok = env.client.request("PUT", url, json=body, headers={"If-Match": '"1"'})
    assert (
        ok.status_code == 200
        and ok.json()["version"] == 2
        and ok.json()["max_age"] == "P30D"
        and ok.headers["ETag"] == '"2"'
    )
    assert (
        env.client.request("PUT", url, json=body, headers={"If-Match": '"1"'}).status_code == 412
    )  # stale now
    assert env.client.delete(url).status_code == 428
    assert env.client.delete(url, headers={"If-Match": '"1"'}).status_code == 412
    before, after = (
        audit_rows(env, "policy.update")[0].before,
        audit_rows(env, "policy.update")[0].after,
    )
    assert before["max_age"] == "P90D" and after["max_age"] == "P30D" and after["version"] == 2
    assert env.client.delete(url, headers={"If-Match": '"2"'}).status_code == 204
    assert env.client.get(url).status_code == 404
    assert [r.after for r in audit_rows(env, "policy.create")][0]["name"] == "weekly"
    assert audit_rows(env, "policy.delete")[0].before["name"] == "weekly"


def test_a_policy_with_bindings_cannot_be_deleted(env: Env) -> None:
    pol = make_policy(env)
    svc = env.make_service()
    binding = bind(env, pol["id"], "service", svc["id"])
    as_admin(env)
    r = env.client.delete(f"/api/v1/policies/{pol['id']}", headers={"If-Match": '"1"'})
    assert r.status_code == 409 and r.json()["code"] == "policy-in-use"
    assert env.client.delete(f"/api/v1/policy-bindings/{binding['id']}").status_code == 204
    assert (
        env.client.delete(f"/api/v1/policies/{pol['id']}", headers={"If-Match": '"1"'}).status_code
        == 204
    )


# --- bindings and effective policy ------------------------------------------------------------------------------------------


def test_binding_rules(env: Env) -> None:
    pol = make_policy(env)
    svc = env.make_service()
    first = bind(env, pol["id"], "service", svc["id"])
    as_admin(env)
    body = {"policy_id": pol["id"], "scope_type": "service", "scope_id": svc["id"]}
    assert (
        env.client.post("/api/v1/policy-bindings", json=body).json()["code"] == "binding-exists"
    )  # one policy per scope
    assert (
        env.client.post("/api/v1/policy-bindings", json={**body, "scope_id": str(uuid4())}).json()[
            "code"
        ]
        == "unknown-scope"
    )
    assert (
        env.client.post("/api/v1/policy-bindings", json={**body, "policy_id": str(uuid4())}).json()[
            "code"
        ]
        == "unknown-policy"
    )
    assert (
        env.client.post(
            "/api/v1/policy-bindings", json={**body, "scope_type": "project"}
        ).status_code
        == 422
    )
    env.as_("operator")
    assert env.client.post("/api/v1/policy-bindings", json=body).status_code == 403
    assert env.client.delete(f"/api/v1/policy-bindings/{first['id']}").status_code == 403
    env.as_("viewer")
    listed = env.client.get(
        "/api/v1/policy-bindings", params={"scope_type": "service", "scope_id": svc["id"]}
    ).json()["items"]
    assert [b["id"] for b in listed] == [first["id"]]
    assert (
        env.client.get("/api/v1/policy-bindings", params={"policy_id": str(uuid4())}).json()[
            "items"
        ]
        == []
    )
    assert audit_rows(env, "policy_binding.create")[0].after["scope_type"] == "service"


def test_effective_policy_most_specific_wins_and_no_policy_means_none(env: Env) -> None:
    group = make_group(env)
    svc = env.make_service()
    assert (
        env.client.patch(
            f"/api/v1/services/{svc['id']}",
            json={"service_group_id": group},
            headers={"If-Match": '"1"'},
        ).status_code
        == 200
    )
    url = f"/api/v1/services/{svc['id']}/effective-policy"

    none = env.client.get(url).json()  # no binding anywhere: no global default (FR-POL-4)
    assert (
        none["policy"] is None
        and none["binding"] is None
        and none["source"] is None
        and none["due_possible"] is False
    )
    assert "never due" in none["reason"]

    group_pol, svc_pol = make_policy(env, name="group-wide"), make_policy(env, name="just-this")
    bind(env, group_pol["id"], "service_group", group)
    via_group = env.client.get(url).json()
    assert via_group["source"] == "service_group" and via_group["policy"]["id"] == group_pol["id"]

    svc_binding = bind(env, svc_pol["id"], "service", svc["id"])
    both = env.client.get(url).json()
    assert (
        both["source"] == "service"
        and both["policy"]["id"] == svc_pol["id"]
        and both["binding"]["id"] == svc_binding["id"]
    )
    assert [b["policy_id"] for b in both["shadowed_bindings"]] == [
        group_pol["id"]
    ] and "most specific" in both["reason"]

    as_admin(env)
    env.client.delete(f"/api/v1/policy-bindings/{svc_binding['id']}")
    assert (
        env.client.get(url).json()["policy"]["id"] == group_pol["id"]
    )  # the group policy applies again
    assert env.client.get(f"/api/v1/services/{uuid4()}/effective-policy").status_code == 404


# --- deadlines (FR-POL-5) ---------------------------------------------------------------------------------------------------------


def test_deadline_is_none_without_a_policy_even_for_an_ancient_vm(env: Env) -> None:
    _, vm = register_vm(env, launched_days_ago=4000)
    d = env.client.get(f"/api/v1/managed-vms/{vm}/deadline").json()
    assert (
        d["status"] == "no_policy"
        and d["due"] is False
        and d["deadline"] is None
        and d["policy_id"] is None
    )


def test_deadline_is_launch_plus_max_age_in_the_next_window(env: Env) -> None:
    pol = make_policy(env)
    svc, vm = register_vm(env, launched_days_ago=10)
    bind(env, pol["id"], "service", svc)
    d = env.client.get(f"/api/v1/managed-vms/{vm}/deadline").json()
    launched = datetime.fromisoformat(d["launched_at"])
    deadline = datetime.fromisoformat(d["deadline"])
    assert (
        deadline == launched + timedelta(days=90)
        and d["status"] == "scheduled"
        and d["due"] is False
    )
    start, end = (
        datetime.fromisoformat(d["next_window_start"]),
        datetime.fromisoformat(d["next_window_end"]),
    )
    assert (
        start >= deadline
        and start.weekday() == 5
        and (end - start) <= timedelta(hours=4)
        and start.hour in (1, deadline.hour)
    )
    assert d["policy_id"] == pol["id"] and d["policy_version"] == 1 and d["max_age"] == "P90D"


def test_an_old_vm_is_due_and_retained_vms_never_are(env: Env) -> None:
    pol = make_policy(env, max_age="P30D", renewal_interval="P20D")
    svc, vm = register_vm(env, launched_days_ago=45)
    bind(env, pol["id"], "service", svc)
    d = env.client.get(f"/api/v1/managed-vms/{vm}/deadline").json()
    assert d["status"] == "due" and d["due"] is True
    with env.worker.begin() as c:
        c.execute(text("UPDATE managed_vm SET role = 'retained' WHERE id = :i"), {"i": vm})
    d = env.client.get(f"/api/v1/managed-vms/{vm}/deadline").json()
    assert d["status"] == "not_applicable" and d["due"] is False
    assert env.client.get(f"/api/v1/managed-vms/{uuid4()}/deadline").status_code == 404


# --- exceptions (FR-POL-3) ------------------------------------------------------------------------------------------------------


def exception_body(sid: str, **patch: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "service_id": sid, "reason": "vendor freeze until the audit ends", "owner": "owner@example.invalid",
        "starts_at": (now - timedelta(hours=1)).isoformat(), "expires_at": (now + timedelta(days=14)).isoformat(), **patch,
    }  # fmt: skip


def test_exception_waives_only_after_a_distinct_approver_approves_and_expires_by_itself(
    env: Env,
) -> None:
    pol = make_policy(env, max_age="P30D", renewal_interval="P20D")
    svc, vm = register_vm(env, launched_days_ago=45)
    bind(env, pol["id"], "service", svc)
    deadline_url = f"/api/v1/managed-vms/{vm}/deadline"
    assert env.client.get(deadline_url).json()["due"] is True

    req = env.client.post("/api/v1/policy-exceptions", json=exception_body(svc))
    assert (
        req.status_code == 201
        and req.json()["state"] == "pending"
        and req.json()["requested_by"] == str(env.operator_id)
    )
    xid = req.json()["id"]
    assert env.client.get(deadline_url).json()["due"] is True  # a request waives nothing

    approver, secret = add_user(env, "approver1", "approver")
    # no step-up, a step-up for another target, and an operator all fail
    r = approver.post(f"/api/v1/policy-exceptions/{xid}/approve", json={"stepup_id": str(uuid4())})
    assert r.status_code == 403 and r.json()["code"] == "stepup-invalid"
    wrong = stepup(env, approver, secret, "policy_exception.approve", str(uuid4()))
    assert (
        approver.post(
            f"/api/v1/policy-exceptions/{xid}/approve", json={"stepup_id": wrong}
        ).status_code
        == 403
    )
    assert (
        env.client.post(
            f"/api/v1/policy-exceptions/{xid}/approve", json={"stepup_id": wrong}
        ).status_code
        == 403
    )  # operator
    assert env.client.get(deadline_url).json()["due"] is True

    good = stepup(env, approver, secret, "policy_exception.approve", xid)
    ok = approver.post(f"/api/v1/policy-exceptions/{xid}/approve", json={"stepup_id": good})
    assert (
        ok.status_code == 200
        and ok.json()["state"] == "active"
        and ok.json()["approved_by"] == str(approver.user_id)
    )
    waived = env.client.get(deadline_url).json()
    assert waived["status"] == "waived" and waived["due"] is False and waived["exception_id"] == xid
    assert waived["waived_until"] == ok.json()["expires_at"] and waived["deadline"]
    again = approver.post(
        f"/api/v1/policy-exceptions/{xid}/approve",
        json={"stepup_id": stepup(env, approver, secret, "policy_exception.approve", xid)},
    )
    assert again.status_code == 409 and again.json()["code"] == "exception-already-approved"
    assert (
        env.client.get(f"/api/v1/services/{svc}/effective-policy").json()["active_exception"]["id"]
        == xid
    )

    # expiry needs no action: the exception just stops applying
    env.auth.sql(
        "UPDATE policy_exception SET starts_at = now() - interval '3 days', expires_at = now() - interval '1 second' WHERE id = :i",
        i=xid,
    )
    back = env.client.get(deadline_url).json()
    assert back["status"] == "due" and back["due"] is True
    assert env.client.get(f"/api/v1/policy-exceptions/{xid}").json()["state"] == "expired"
    assert (
        env.client.get(f"/api/v1/services/{svc}/effective-policy").json()["active_exception"]
        is None
    )

    trail = audit_rows(env, "policy_exception.approve")
    assert len(trail) == 1 and trail[0].after["approved_by"] == str(approver.user_id)
    for row in audit_rows(env, "policy_exception.request"):
        assert "owner@example" not in str(row.after) and row.after["reason"].startswith(
            "vendor freeze"
        )


def test_the_requester_cannot_approve_their_own_exception(env: Env) -> None:
    pol = make_policy(env)
    svc, _ = register_vm(env)
    bind(env, pol["id"], "service", svc)
    both, secret = add_user(env, "both", "operator", "approver")
    xid = both.post("/api/v1/policy-exceptions", json=exception_body(svc)).json()["id"]
    step = stepup(env, both, secret, "policy_exception.approve", xid)
    r = both.post(f"/api/v1/policy-exceptions/{xid}/approve", json={"stepup_id": step})
    assert r.status_code == 403 and r.json()["code"] == "sod-violation"
    assert env.client.get(f"/api/v1/policy-exceptions/{xid}").json()["state"] == "pending"
    # refused before the step-up was spent
    assert env.auth.sql("SELECT consumed_at FROM stepup WHERE id = :i", i=step)[0][0] is None
    with pytest.raises(DBAPIError, match="approved_by"):  # and the database refuses it too
        env.auth.sql(
            "UPDATE policy_exception SET approved_by = requested_by, approved_at = now() WHERE id = :i",
            i=xid,
        )


def test_exception_request_validation(env: Env) -> None:
    svc = env.make_service()
    now = datetime.now(UTC)
    for patch, code in (
        (
            {
                "expires_at": (now - timedelta(days=1)).isoformat(),
                "starts_at": (now - timedelta(days=2)).isoformat(),
            },
            "exception-already-expired",
        ),
        ({"service_id": str(uuid4())}, "service-not-found"),
    ):
        r = env.client.post("/api/v1/policy-exceptions", json=exception_body(svc["id"], **patch))
        assert r.json()["code"] == code, r.text
    r = env.client.post(
        "/api/v1/policy-exceptions",
        json=exception_body(svc["id"], expires_at=(now - timedelta(hours=2)).isoformat()),
    )
    assert (
        r.status_code == 422 and r.json()["code"] == "validation-error"
    )  # expires before it starts
    naive = env.client.post(
        "/api/v1/policy-exceptions",
        json=exception_body(svc["id"], expires_at="2999-01-01T00:00:00"),
    )
    assert naive.status_code == 422 and "time zone" in naive.text
    env.as_("viewer")
    assert (
        env.client.post("/api/v1/policy-exceptions", json=exception_body(svc["id"])).status_code
        == 403
    )
    assert (
        env.client.get("/api/v1/policy-exceptions", params={"service_id": svc["id"]}).status_code
        == 200
    )


# --- database grants and constraints ----------------------------------------------------------------------------------------------


def test_api_role_cannot_rewrite_or_delete_exceptions(env: Env) -> None:
    svc = env.make_service()
    xid = env.client.post("/api/v1/policy-exceptions", json=exception_body(svc["id"])).json()["id"]
    for stmt in (
        "UPDATE policy_exception SET reason = 'edited'",
        "UPDATE policy_exception SET expires_at = now() + interval '1 year'",
        "DELETE FROM policy_exception",
    ):
        with env.api.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
            c.execute(text(stmt))
    with env.worker.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
        c.execute(text("UPDATE policy SET max_age_seconds = 1"))
    assert env.client.get(f"/api/v1/policy-exceptions/{xid}").json()["reason"].startswith("vendor")
    with pytest.raises(DBAPIError, match="check"):
        env.auth.sql(
            "INSERT INTO policy_exception (id, service_id, reason, owner, starts_at, expires_at, requested_by) "
            "VALUES (gen_random_uuid(), :s, 'r', 'o', now(), now(), gen_random_uuid())", s=svc["id"],
        )  # fmt: skip
