# ruff: noqa: F811
"""Tokens, TOTP, step-up and ``require_role`` (security-model.md section 10, items 3, 4, 6 partially)."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.integration.auth_support import ORIGIN, PASSWORD, Env, env  # noqa: F401


def post(env: Env, c: TestClient, path: str, **kw: Any) -> Any:
    return c.post(path, headers=env.headers(c), **kw)


def mint_token(
    env: Env, c: TestClient, *scopes: str, project: str = "global", days: int = 30
) -> str:
    r = post(
        env,
        c,
        "/api/v1/tokens",
        json={
            "name": "t",
            "scopes": list(scopes),
            "project_scope": project,
            "expires_in_days": days,
        },
    )
    assert r.status_code == 201, r.text
    return str(r.json()["token"])


def bearer(raw: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {raw}"}


# --- API tokens (10.3) ------------------------------------------------------------------------------------


def test_token_secret_is_stored_only_as_a_hash_and_shown_once(env: Env) -> None:
    c, _ = env.user_client("olga", [("operator", "global")])
    raw = mint_token(env, c, "operate")
    tid, secret = raw.split("_")[1], raw.split("_")[2]
    [row] = env.sql(
        "SELECT id::text, secret_hash, scopes, expires_at, project_scope FROM api_token"
    )
    assert row.secret_hash == hashlib.sha256(secret.encode()).hexdigest()
    assert secret not in str(row) and tid.replace("-", "") == raw.split("_")[1]
    listing = c.get("/api/v1/tokens").json()["items"]
    assert len(listing) == 1 and "token" not in listing[0] and secret not in str(listing)


def test_token_authenticates_and_expired_or_revoked_tokens_get_401(env: Env) -> None:
    c, _ = env.user_client("pia", [("operator", "global")])
    raw = mint_token(env, c, "read")
    anon = env.client()
    assert anon.get("/_t/viewer", headers=bearer(raw)).json() == {"user": "pia"}
    assert anon.get("/_t/viewer", headers={"Authorization": "Bearer ovlm_nope"}).status_code == 401
    assert anon.get("/_t/viewer", headers={"Authorization": "Basic abc"}).status_code == 401
    forged = raw[:-4] + ("AAAA" if not raw.endswith("AAAA") else "BBBB")
    assert anon.get("/_t/viewer", headers=bearer(forged)).status_code == 401
    # expiry
    env.sql(
        "UPDATE api_token SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day'"
    )
    r = anon.get("/_t/viewer", headers=bearer(raw))
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    # revocation
    raw2 = mint_token(env, c, "read")
    assert anon.get("/_t/viewer", headers=bearer(raw2)).status_code == 200
    tid = [
        t for t in c.get("/api/v1/tokens").json()["items"] if not t["revoked"] and t["last_used_at"]
    ][0]["id"]
    assert c.delete(f"/api/v1/tokens/{tid}", headers=env.headers(c)).status_code == 204
    assert anon.get("/_t/viewer", headers=bearer(raw2)).status_code == 401
    # a disabled user's tokens die with the user
    raw3 = mint_token(env, c, "read")
    assert anon.get("/_t/viewer", headers=bearer(raw3)).status_code == 200
    env.sql("UPDATE app_user SET state='disabled' WHERE username='pia'")
    assert anon.get("/_t/viewer", headers=bearer(raw3)).status_code == 401


def test_token_cannot_exceed_owner_scope_or_90_days(env: Env) -> None:
    c, _ = env.user_client("quinn", [("viewer", "global")])
    h = env.headers(c)
    assert (
        c.post("/api/v1/tokens", json={"name": "t", "scopes": ["operate"]}, headers=h).status_code
        == 422
    )
    assert (
        c.post("/api/v1/tokens", json={"name": "t", "scopes": ["admin"]}, headers=h).status_code
        == 422
    )
    assert (
        c.post(
            "/api/v1/tokens",
            json={"name": "t", "scopes": ["read"], "expires_in_days": 91},
            headers=h,
        ).status_code
        == 422
    )
    assert (
        c.post(
            "/api/v1/tokens",
            json={"name": "t", "scopes": ["read"], "project_scope": "project:x"},
            headers=h,
        ).status_code
        == 201
    )
    # the DB refuses what the API refuses (max 90 days, mandatory expiry)
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        env.sql("UPDATE api_token SET expires_at = created_at + interval '91 days'")
    with pytest.raises(IntegrityError):
        env.sql("UPDATE api_token SET expires_at = NULL")


def test_token_never_reaches_admin_approver_or_human_only_endpoints(env: Env) -> None:
    admin, _ = env.user_client("root", [("admin", "global"), ("operator", "global")])
    raw = mint_token(env, admin, "read", "operate")
    anon = env.client()
    h = bearer(raw)
    assert anon.get("/api/v1/users", headers=h).status_code == 403  # admin endpoint
    assert anon.post("/api/v1/users", headers=h, json={"username": "mallory"}).status_code == 403
    assert anon.post("/_t/admin", headers=h).status_code == 403
    assert anon.post("/_t/approver", headers=h).json()["code"] == "human-session-required"
    assert (
        anon.post("/api/v1/tokens", headers=h, json={"name": "x", "scopes": ["read"]}).json()[
            "code"
        ]
        == "human-session-required"
    )
    assert (
        anon.post(
            "/api/v1/session/reauth",
            headers=h,
            json={"password": PASSWORD, "action": "a", "target_id": "t"},
        ).status_code
        == 403
    )
    assert (
        anon.post("/_t/operator", headers=h).status_code == 200
    )  # but plain operator work is allowed
    # an approver's token reaches viewer only
    ap, _ = env.user_client("appy", [("approver", "global")])
    raw_ap = mint_token(env, ap, "read")
    assert anon.get("/_t/viewer", headers=bearer(raw_ap)).status_code == 200
    assert anon.post("/_t/approver", headers=bearer(raw_ap)).status_code == 403


def test_token_scopes_gate_operator_endpoints(env: Env) -> None:
    c, _ = env.user_client("rita", [("operator", "global")])
    read, sync, operate = (mint_token(env, c, s) for s in ("read", "inventory:sync", "operate"))
    anon = env.client()
    assert anon.post("/_t/operator", headers=bearer(read)).json()["code"] == "token-scope"
    assert anon.post("/_t/sync", headers=bearer(read)).status_code == 403
    assert anon.post("/_t/sync", headers=bearer(sync)).status_code == 200
    assert (
        anon.post("/_t/operator", headers=bearer(sync)).status_code == 403
    )  # sync token: sync only
    assert anon.post("/_t/operator", headers=bearer(operate)).status_code == 200
    assert anon.post("/_t/sync", headers=bearer(operate)).status_code == 200


def test_project_scoped_token_stays_in_its_project(env: Env) -> None:
    c, _ = env.user_client("sven", [("operator", "global")])
    raw = mint_token(env, c, "operate", project="project:a")
    anon = env.client()
    assert anon.post("/_t/project/a", headers=bearer(raw)).status_code == 200
    assert anon.post("/_t/project/b", headers=bearer(raw)).status_code == 403
    assert anon.post("/_t/operator", headers=bearer(raw)).status_code == 200  # "any scope I hold"


# --- require_role + role bindings ----------------------------------------------------------------------------


def test_require_role_lattice_and_project_scope(env: Env) -> None:
    viewer, _ = env.user_client("vic", [("viewer", "global")])
    op_a, _ = env.user_client("opa", [("operator", "project:a")])
    op_g, _ = env.user_client("opg", [("operator", "global")])
    assert viewer.get("/_t/viewer").status_code == 200
    r = post(env, viewer, "/_t/operator")
    assert r.status_code == 403 and r.json()["code"] == "forbidden"
    assert r.headers["content-type"].startswith("application/problem+json")
    assert post(env, op_a, "/_t/project/a").status_code == 200
    assert post(env, op_a, "/_t/project/b").status_code == 403
    assert post(env, op_g, "/_t/project/anything").status_code == 200
    assert op_a.get("/_t/viewer").status_code == 200  # operator implies viewer
    assert env.client().get("/_t/viewer").status_code == 401
    # admin does not inherit operator or approver; approver is not operator
    admin, _ = env.user_client("adm", [("admin", "global")])
    assert post(env, admin, "/_t/operator").status_code == 403
    assert post(env, admin, "/_t/approver").status_code == 403
    assert post(env, admin, "/_t/admin").status_code == 200
    assert admin.get("/_t/viewer").status_code == 200


def test_denials_of_mutating_endpoints_are_audited_reads_are_not(env: Env) -> None:
    viewer, _ = env.user_client("wes", [("viewer", "global")])
    post(env, viewer, "/_t/operator")
    post(env, viewer, "/_t/project/zzz")
    rows = env.sql(
        "SELECT action, result, target_id, project_scope FROM audit_event WHERE action='authz.denied' ORDER BY id"
    )
    assert [(r.result, r.target_id, r.project_scope) for r in rows] == [
        ("denied", "POST /_t/operator", None),
        ("denied", "POST /_t/project/{project_id}", "project:zzz"),
    ]


def test_role_binding_changes_end_sessions_and_are_audited(env: Env) -> None:
    admin, _ = env.user_client("root", [("admin", "global")])
    user, _ = env.user_client("xena", [("viewer", "global")])
    [xena] = env.sql("SELECT id FROM app_user WHERE username='xena'")
    r = post(
        env,
        admin,
        "/api/v1/role-bindings",
        json={"user_id": str(xena.id), "role": "operator", "scope": "project:a"},
    )
    assert r.status_code == 201, r.text
    assert user.get("/api/v1/session").status_code == 401  # privilege change: new session needed
    assert (
        post(
            env, admin, "/api/v1/role-bindings", json={"user_id": str(xena.id), "role": "emperor"}
        ).status_code
        == 422
    )
    assert (
        post(
            env,
            admin,
            "/api/v1/role-bindings",
            json={"user_id": str(xena.id), "role": "viewer", "scope": "x/y"},
        ).status_code
        == 422
    )
    user = env.client()
    assert env.api_login(user, "xena").status_code == 200
    assert post(env, user, "/_t/project/a").status_code == 200
    bid = r.json()["id"]
    assert (
        admin.delete(f"/api/v1/role-bindings/{bid}", headers=env.headers(admin)).status_code == 204
    )
    assert (
        admin.delete(f"/api/v1/role-bindings/{bid}", headers=env.headers(admin)).status_code == 404
    )
    assert user.get("/api/v1/session").status_code == 401
    kept = env.sql(
        "SELECT revoked_at IS NOT NULL AS gone, revoked_by IS NOT NULL AS by FROM role_binding WHERE id = :i",
        i=bid,
    )
    assert [(k.gone, k.by) for k in kept] == [(True, True)]  # history kept
    actions = [
        r.action
        for r in env.sql(
            "SELECT action FROM audit_event WHERE action LIKE 'role_binding.%' ORDER BY id"
        )
    ]
    assert actions == ["role_binding.create", "role_binding.revoke"]
    # non-admins cannot manage bindings
    viewer, _ = env.user_client("yan", [("viewer", "global")])
    assert (
        post(
            env, viewer, "/api/v1/role-bindings", json={"user_id": str(xena.id), "role": "admin"}
        ).status_code
        == 403
    )


# --- TOTP (mandatory for approver and admin) -----------------------------------------------------------------


def test_approver_and_admin_roles_are_suspended_until_totp_is_confirmed(env: Env) -> None:
    link = env.create_user("zed", [("approver", "global"), ("operator", "global")])
    c = env.client()
    r = env.enrol(c, link)
    assert r.headers["location"] == "/account/totp"
    me = c.get("/api/v1/session").json()
    assert me["totp"] == {"confirmed": False, "enrolment_required": True}
    assert {x["role"] for x in me["roles"]} == {"operator"}  # approver withheld
    denied = post(env, c, "/_t/approver")
    assert denied.status_code == 403 and denied.json()["code"] == "totp-enrolment-required"
    assert post(env, c, "/_t/operator").status_code == 200  # other roles keep working
    # enrol: pending until a valid code confirms; a wrong code does not
    h = env.headers(c)
    secret = c.post("/api/v1/session/totp/enrol", headers=h).json()["secret"]
    bad = c.post("/api/v1/session/totp/confirm", json={"code": "000000"}, headers=h)
    assert bad.status_code in (401, 429)
    old_cookie = c.cookies.get("__Host-ovlm_session")
    good = c.post("/api/v1/session/totp/confirm", json={"code": env.code(secret)}, headers=h)
    assert good.status_code == 200
    assert (
        c.cookies.get("__Host-ovlm_session") != old_cookie
    )  # session id rotated on privilege change
    assert post(env, c, "/_t/approver").status_code == 200
    assert (
        c.post("/api/v1/session/totp/enrol", headers=env.headers(c)).json()["code"]
        == "totp-already-enrolled"
    )
    # the secret is encrypted at rest
    [u] = env.sql("SELECT totp_secret_enc FROM app_user WHERE username='zed'")
    assert secret.encode() not in bytes(u.totp_secret_enc)


def test_totp_login_requires_a_fresh_valid_code_each_time(env: Env) -> None:
    c, secret = env.user_client("amy", [("approver", "global")])
    assert secret
    cl = env.client()
    assert env.api_login(cl, "amy").status_code == 401  # missing code
    assert env.api_login(cl, "amy", PASSWORD, None).status_code == 401
    wrong = cl.post(
        "/api/v1/session",
        json={"username": "amy", "password": PASSWORD, "totp_code": "123456"},
        headers={"Origin": ORIGIN},
    )
    assert wrong.status_code == 401
    assert wrong.json()["detail"] == "Invalid username, password or code."
    ok = env.api_login(cl, "amy", PASSWORD, secret)
    assert ok.status_code == 200 and ok.json()["auth_method"] == "password+totp"
    # the same code (same time step) cannot be used again, even by the legitimate user
    replay = cl.post(
        "/api/v1/session",
        json={"username": "amy", "password": PASSWORD, "totp_code": env.code(secret)},
        headers={"Origin": ORIGIN},
    )
    assert replay.status_code == 401
    env.clock.advance()
    assert env.api_login(env.client(), "amy", PASSWORD, secret).status_code == 200
    reasons = [
        r.after["reason"]
        for r in env.sql(
            "SELECT after FROM audit_event WHERE action='auth.login.failure' ORDER BY id"
        )
    ]
    assert reasons == ["totp_missing", "totp_missing", "bad_totp", "bad_totp"]


def test_totp_fails_closed_without_a_key(env: Env) -> None:
    c, _ = env.user_client("ben", [("viewer", "global")])
    env.app.state.totp_vault = None
    h = env.headers(c)
    env.app.state.settings = env.app.state.settings.model_copy(
        update={"auth": env.app.state.settings.auth.model_copy(update={"totp_key_file": None})}
    )
    r = c.post("/api/v1/session/totp/enrol", headers=h)
    assert r.status_code == 503 and r.json()["code"] == "totp-unavailable"


# --- step-up (10.4) -------------------------------------------------------------------------------------------


def reauth(
    env: Env,
    c: TestClient,
    secret: str | None,
    action: str = "approval.decide",
    target: str = "ap-1",
    **kw: Any,
) -> Any:
    body: dict[str, Any] = {
        "password": kw.get("password", PASSWORD),
        "action": action,
        "target_id": target,
    }
    if secret:
        body["totp_code"] = env.code(secret)
    return c.post("/api/v1/session/reauth", json=body, headers=env.headers(c))


def decide(env: Env, c: TestClient, step: str, target: str = "ap-1", path: str = "decide") -> Any:
    return c.post(f"/_t/{path}/{target}", params={"stepup_id": step}, headers=env.headers(c))


def test_stepup_is_single_use_and_bound_to_action_target_and_session(env: Env) -> None:
    c, secret = env.user_client("cora", [("approver", "global")])
    env.clock.advance()
    r = reauth(env, c, secret)
    assert r.status_code == 200, r.text
    step = r.json()["stepup_id"]
    assert r.json()["action"] == "approval.decide" and r.json()["target_id"] == "ap-1"
    # another target: refused, and the step-up is NOT spent by the failed attempt
    wrong = decide(env, c, step, target="ap-2")
    assert wrong.status_code == 403 and wrong.json()["code"] == "stepup-invalid"
    ok = decide(env, c, step)
    assert ok.status_code == 200 and ok.json() == {"decided": "ap-1"}
    # single use: reuse refused
    again = decide(env, c, step)
    assert again.status_code == 403 and again.json()["code"] == "stepup-invalid"
    [sp] = env.sql("SELECT consumed_at, expires_at - created_at AS ttl FROM stepup")
    assert sp.consumed_at is not None and sp.ttl.total_seconds() == 300  # valid 5 minutes
    # unknown id: same answer as a spent one
    assert decide(env, c, str(uuid4())).json()["code"] == "stepup-invalid"
    refused = env.sql(
        "SELECT count(*) FROM audit_event WHERE action='auth.stepup.refused' AND result='denied'"
    )
    assert refused[0][0] == 3


def test_stepup_expires_and_needs_password_and_totp(env: Env) -> None:
    c, secret = env.user_client("dina", [("approver", "global")])
    env.clock.advance()
    assert reauth(env, c, secret, password="wrong password entirely").status_code == 401
    assert reauth(env, c, None).status_code == 401  # TOTP code missing
    r = reauth(env, c, secret)
    step = r.json()["stepup_id"]
    env.sql("UPDATE stepup SET expires_at = now() - interval '1 second'")
    assert decide(env, c, step).json()["code"] == "stepup-invalid"  # expired (5 min)
    # the DB refuses a longer validity than 5 minutes
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        env.sql("UPDATE stepup SET expires_at = created_at + interval '6 minutes'")


def test_stepup_is_bound_to_the_issuing_session_and_to_humans(env: Env) -> None:
    c1, secret = env.user_client("eli", [("approver", "global")])
    env.clock.advance()
    step = reauth(env, c1, secret).json()["stepup_id"]
    c2 = env.client()
    env.clock.advance()
    assert env.api_login(c2, "eli", PASSWORD, secret).status_code == 200
    assert decide(env, c2, step).json()["code"] == "stepup-invalid"  # same user, other session
    assert decide(env, c1, step).status_code == 200
    # another user cannot use it either
    other, osecret = env.user_client("fay", [("approver", "global")])
    env.clock.advance()
    step2 = reauth(env, c1, secret, target="ap-9").json()["stepup_id"]
    assert decide(env, other, step2, target="ap-9").json()["code"] == "stepup-invalid"
    # tokens cannot obtain or use a step-up
    raw = mint_token(env, other, "read")
    r = env.client().post(
        "/api/v1/session/reauth",
        headers=bearer(raw),
        json={"password": PASSWORD, "action": "a", "target_id": "t"},
    )
    assert r.status_code == 403
    r = env.client().post("/_t/decide/ap-9", params={"stepup_id": step2}, headers=bearer(raw))
    assert r.status_code == 403 and r.json()["code"] == "human-session-required"


def test_stepup_stays_unspent_when_the_authorised_change_rolls_back(env: Env) -> None:
    c, secret = env.user_client("gus", [("approver", "global")])
    env.clock.advance()
    step = reauth(env, c, secret, target="ap-5").json()["stepup_id"]
    # the endpoint consumes then crashes before committing: nothing is spent
    with pytest.raises(RuntimeError, match="step-up was consumed"):
        c.post("/_t/decide-then-fail/ap-5", params={"stepup_id": step}, headers=env.headers(c))
    assert env.sql("SELECT consumed_at FROM stepup") == [(None,)]
    assert decide(env, c, step, target="ap-5").status_code == 200
