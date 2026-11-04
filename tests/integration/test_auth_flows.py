# ruff: noqa: F811
"""Authentication integration tests (security-model.md section 10, items 1-4, 6): real PostgreSQL, real app."""

from __future__ import annotations

import hashlib
import re
from typing import Any
from uuid import uuid4

import pytest

from ovlm.auth.cli import admin_main
from tests.integration.auth_support import (  # noqa: F401
    ORIGIN,
    PASSWORD,
    Env,
    env,
    iter_api_routes,
)

# --- bootstrap CLI --------------------------------------------------------------------------------------------


def test_cli_bootstrap_prints_a_one_time_link_and_has_no_password_option(
    env: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    s = env.settings
    for k, v in {
        "OVLM_CONFIG_FILE": "/nonexistent.toml",
        "OVLM_DB__HOST": s.db.host,
        "OVLM_DB__PORT": str(s.db.port),
        "OVLM_DB__NAME": s.db.name,
        "OVLM_DB__SSLMODE": "disable",
        "OVLM_DB__PASSWORD_FILE": str(s.db.password_file),
        "OVLM_EXTERNAL_URL": ORIGIN,
    }.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(SystemExit):  # no --password anywhere; --enrol-link is mandatory
        admin_main(["create", "--username", "root", "--password", "x", "--enrol-link"])
    with pytest.raises(SystemExit):
        admin_main(["create", "--username", "root"])
    assert admin_main(["create", "--username", "root", "--enrol-link"]) == 0
    out, _err = capsys.readouterr()
    link = out.strip()
    assert link.startswith(f"{ORIGIN}/enrol/")
    assert admin_main(["create", "--username", "root", "--enrol-link"]) == 2  # duplicate

    [user] = env.sql("SELECT state, password_hash, created_via, created_by FROM app_user")
    assert (user.state, user.password_hash, user.created_via, user.created_by) == (
        "pending_enrolment",
        None,
        "cli",
        None,
    )
    assert env.sql("SELECT role, scope FROM role_binding") == [("admin", "global")]
    audit = env.sql(
        "SELECT action, principal_type, auth_method, actor_id FROM audit_event ORDER BY id"
    )
    assert [(a.action, a.principal_type, a.auth_method, a.actor_id) for a in audit] == [
        ("user.create", "system", "cli", None),
        ("user.enrolment_link.issue", "system", "cli", None),
    ]
    # The person opens the link, chooses their own password, enrols TOTP: now an admin
    c = env.client()
    r = env.enrol(c, link.removeprefix(ORIGIN + "/enrol/"))
    assert (
        r.status_code == 303 and r.headers["location"] == "/account/totp"
    )  # admin must enrol TOTP
    env.enrol_totp(c)
    assert c.get("/api/v1/users").status_code == 200


# --- enrolment links (admin never sets passwords) ------------------------------------------------------------


def test_admin_cannot_set_a_password_by_any_endpoint(env: Env) -> None:
    admin, _ = env.user_client("root", [("admin", "global")])
    h = env.headers(admin)
    r = admin.post(
        "/api/v1/users", json={"username": "bob", "password": "chosen-by-admin-1"}, headers=h
    )
    assert r.status_code == 422
    r = admin.post("/api/v1/users", json={"username": "bob", "display_name": "Bob"}, headers=h)
    assert r.status_code == 201, r.text
    assert "enrolment_link" in r.json() and not any("password" in k for k in r.json())
    [bob] = env.sql(
        "SELECT state, password_hash, created_by, created_via FROM app_user WHERE username='bob'"
    )
    assert (
        bob.state == "pending_enrolment"
        and bob.password_hash is None
        and bob.created_via == "admin"
    )
    # Bob cannot log in before enrolling, with any password
    assert env.api_login(env.client(), "bob", "chosen-by-admin-1").status_code == 401


def test_only_the_owner_can_submit_a_password_structural() -> None:
    """The only inputs named ``password`` belong to the user's own login, re-auth and enrolment."""
    from ovlm.api.app import create_app
    from ovlm.config import Settings

    app = create_app(Settings(), start_metrics_server=False, probe=None)
    found: set[tuple[str, str]] = set()
    for route in iter_api_routes(app):
        names = {p.name for p in route.dependant.body_params} | {
            p.name for p in route.dependant.query_params
        }
        for p in route.dependant.body_params:
            model = getattr(p.field_info, "annotation", None)
            fields = getattr(model, "model_fields", {})
            names |= set(fields)
        if any("password" in n for n in names):
            found |= {(m, route.path) for m in route.methods}
    assert found == {
        ("POST", "/login"),
        ("POST", "/enrol/{link}"),
        ("POST", "/api/v1/session"),
        ("POST", "/api/v1/session/reauth"),
        ("POST", "/account/stepup"),  # the UI form for the same reauth call
    }


def test_enrolment_link_is_single_use_expiring_and_replaced_by_a_newer_one(env: Env) -> None:
    link = env.create_user("carol", [("viewer", "global")])
    c = env.client()
    assert c.get(f"/enrol/{link}").status_code == 200
    # a weak password does not burn the link
    assert env.enrol(c, link, "short").status_code == 422
    assert env.enrol(c, link, "passwordpassword").status_code == 422
    r = env.enrol(c, link)
    assert r.status_code == 303 and r.headers["location"] == "/"
    # second use, from any client: nothing
    other = env.client()
    assert other.get(f"/enrol/{link}").status_code == 404
    tok = env.form_token(other, "/login")  # any page that issues the double-submit cookie
    again = other.post(
        f"/enrol/{link}",
        data={"password": PASSWORD, "password_confirm": PASSWORD, "csrf_token": tok},
        headers={"Origin": ORIGIN},
    )
    assert again.status_code == 404
    # only the hash is stored
    [row] = env.sql("SELECT secret_hash, used_at FROM enrolment_link")
    assert link.split(".", 1)[1] not in row.secret_hash and row.used_at is not None

    # expiry
    link2 = env.create_user("dave", [("viewer", "global")])
    env.sql(
        "UPDATE enrolment_link SET expires_at = now() - interval '1 second' WHERE user_id IN "
        "(SELECT id FROM app_user WHERE username='dave')"
    )
    assert env.client().get(f"/enrol/{link2}").status_code == 404
    # a newer link revokes the older one
    from ovlm.auth import users

    with env.session() as db:
        uid = db.execute(
            __import__("sqlalchemy").text("SELECT id FROM app_user WHERE username='dave'")
        ).scalar_one()
        _, newer = users.issue_link(db, env.settings, user_id=uid, purpose="enrol", created_by=None)
        _, newest = users.issue_link(
            db, env.settings, user_id=uid, purpose="enrol", created_by=None
        )
        db.commit()
    assert env.client().get(f"/enrol/{newer}").status_code == 404
    assert env.client().get(f"/enrol/{newest}").status_code == 200
    assert env.client().get("/enrol/garbage").status_code == 404


def test_credential_reset_link_clears_totp_sessions_and_records_provenance(env: Env) -> None:
    admin, _ = env.user_client("root", [("admin", "global")])
    victim, secret = env.user_client("alice", [("approver", "global")])
    [alice] = env.sql("SELECT id FROM app_user WHERE username='alice'")
    r = admin.post(f"/api/v1/users/{alice.id}/enrolment-link", headers=env.headers(admin))
    assert r.status_code == 200 and r.json()["purpose"] == "reset"
    link = r.json()["enrolment_link"].removeprefix(f"{ORIGIN}/enrol/")
    assert victim.get("/api/v1/session").status_code == 200  # still valid until the link is used
    fresh = env.client()
    assert env.enrol(fresh, link, "a brand new passphrase 77").status_code == 303
    assert victim.get("/api/v1/session").status_code == 401  # old sessions ended
    [u] = env.sql(
        "SELECT totp_confirmed_at, totp_secret_enc, credential_reset_by, credential_reset_at, "
        "id FROM app_user WHERE username='alice'"
    )
    assert (
        u.totp_confirmed_at is None
        and u.totp_secret_enc is None
        and u.credential_reset_at is not None
    )
    [root] = env.sql("SELECT id FROM app_user WHERE username='root'")
    assert u.credential_reset_by == root.id
    me = fresh.get("/api/v1/session").json()
    assert (
        me["totp"]["enrolment_required"] is True and me["roles"] == []
    )  # approver suspended until TOTP


# --- login (10.1) -------------------------------------------------------------------------------------------


def test_password_is_stored_as_argon2id(env: Env) -> None:
    env.user_client("erin", [("viewer", "global")])
    [row] = env.sql("SELECT password_hash FROM app_user WHERE username='erin'")
    assert row.password_hash.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert PASSWORD not in row.password_hash


def test_login_errors_are_identical_for_unknown_user_and_wrong_password(env: Env) -> None:
    env.user_client("frank", [("viewer", "global")])
    a = env.api_login(env.client(), "frank", "wrong password entirely")
    b = env.api_login(env.client(), "nobody-here", "wrong password entirely")
    c = env.api_login(env.client(), "x", "y")  # not even a valid username
    assert (a.status_code, b.status_code, c.status_code) == (401, 401, 401)
    assert a.json() == b.json() == c.json()
    assert a.json()["detail"] == "Invalid username, password or code."
    # HTML form: same page for both
    bodies = []
    for name in ("frank", "nobody-here"):
        page = env.client()
        tok = env.form_token(page, "/login")
        r = page.post(
            "/login",
            data={"username": name, "password": "bad password 123", "csrf_token": tok},
            headers={"Origin": ORIGIN},
        )
        assert r.status_code == 401
        bodies.append(r.text.replace(tok, "T"))
    assert bodies[0].split("csrf_token")[0] == bodies[1].split("csrf_token")[0]
    assert "Invalid username, password or code." in bodies[0]


@pytest.mark.parametrize("env", [{"login_failure_threshold": 3}], indirect=True)
def test_rate_limit_backs_off_after_repeated_failures_without_hard_lockout(env: Env) -> None:
    env.user_client("gina", [("viewer", "global")])
    c = env.client()
    codes = [env.api_login(c, "gina", f"wrong password {i}").status_code for i in range(6)]
    assert codes[:3] == [401, 401, 401]
    assert 429 in codes
    r = env.api_login(c, "gina", "wrong password again")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    assert r.json()["code"] == "rate-limited"
    # the backoff is time-bounded: expiring the failures lifts it (no permanent lockout)
    env.sql("UPDATE login_attempt SET ts = now() - interval '1 hour'")
    assert env.api_login(c, "gina").status_code == 200
    # failures of a user do not affect another account
    assert env.api_login(env.client(), "someone-else", "x" * 12).status_code in (401, 429)


def test_session_cookie_attributes_and_new_session_id_at_login(env: Env) -> None:
    env.user_client("hana", [("viewer", "global")])
    ids = []
    for _ in range(2):
        r = env.api_login(env.client(), "hana")
        assert r.status_code == 200, r.text
        cookie = r.headers["set-cookie"]
        assert cookie.startswith("__Host-ovlm_session=")
        low = cookie.lower()
        assert "httponly" in low and "secure" in low and "samesite=lax" in low and "path=/" in low
        assert "domain" not in low
        ids.append(cookie.split(";")[0].split("=", 1)[1])
    assert ids[0] != ids[1]
    # only a hash is stored server side
    hashes = {r.id_hash for r in env.sql("SELECT id_hash FROM auth_session")}
    assert all(i not in hashes for i in ids)
    assert hashlib.sha256(ids[0].encode()).hexdigest() in hashes
    assert "set-cookie" not in env.client().get("/healthz").headers


def test_logout_idle_and_absolute_timeouts(env: Env) -> None:
    c, _ = env.user_client("ivan", [("viewer", "global")])
    assert c.get("/api/v1/session").status_code == 200
    env.sql("UPDATE auth_session SET last_seen_at = now() - interval '31 minutes'")
    assert c.get("/api/v1/session").status_code == 401  # idle 30 min
    c = env.client()
    assert env.api_login(c, "ivan").status_code == 200
    env.sql("UPDATE auth_session SET expires_at = now() - interval '1 second'")
    assert c.get("/api/v1/session").status_code == 401  # absolute 12 h
    c = env.client()
    env.api_login(c, "ivan")
    before = env.sql("SELECT count(*) FROM auth_session")[0][0]
    assert c.delete("/api/v1/session", headers=env.headers(c)).status_code == 204
    assert c.get("/api/v1/session").status_code == 401
    assert env.sql("SELECT count(*) FROM auth_session")[0][0] == before - 1


# --- CSRF (10.2) ----------------------------------------------------------------------------------------------

PRE_AUTH = {("POST", "/login"), ("POST", "/enrol/{link}"), ("POST", "/api/v1/session")}


def _unsafe_routes(env: Env) -> list[tuple[str, str]]:
    out = []
    for route in iter_api_routes(env.app):
        if not route.path.startswith("/_t"):
            for m in sorted(route.methods - {"GET", "HEAD", "OPTIONS"}):
                out.append((m, route.path))
    return out


def _fill(path: str) -> str:
    return (
        path.replace("{link}", "x")
        .replace("{token_id}", str(uuid4()))
        .replace("{user_id}", str(uuid4()))
        .replace("{binding_id}", str(uuid4()))
    )


def test_every_unsafe_authenticated_route_enforces_csrf_and_origin(env: Env) -> None:
    admin, _ = env.user_client("root", [("admin", "global")])
    routes = [r for r in _unsafe_routes(env) if r not in PRE_AUTH]
    assert len(routes) >= 12  # the table is real, not empty
    csrf = admin.get("/api/v1/session").json()["csrf_token"]
    for method, path in routes:
        url = _fill(path)
        kw: dict[str, Any] = {"json": {}} if path.startswith("/api") else {"data": {}}
        no_token = admin.request(method, url, headers={"Origin": ORIGIN}, **kw)
        bad_token = admin.request(
            method, url, headers={"Origin": ORIGIN, "X-CSRF-Token": "x" * 40}, **kw
        )
        foreign = admin.request(
            method, url, headers={"Origin": "https://evil.example", "X-CSRF-Token": csrf}, **kw
        )
        no_origin = admin.request(method, url, headers={"X-CSRF-Token": csrf}, **kw)
        for name, r in (
            ("no token", no_token),
            ("bad token", bad_token),
            ("foreign origin", foreign),
            ("no origin", no_origin),
        ):
            assert r.status_code == 403, (method, path, name, r.status_code)
            code = (
                r.json()["code"]
                if r.headers["content-type"].startswith("application/")
                else re.search(r'data-code="([^"]+)"', r.text).group(1)  # type: ignore[union-attr]
            )  # UI pages are HTML: the error page carries the same code
            assert code == "csrf-failed", (method, path, name)
    # and the same routes are reachable with a correct token + origin (not CSRF-blocked)
    r = admin.post(
        "/api/v1/users",
        json={"username": "newbie"},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )
    assert r.status_code == 201
    denials = env.sql("SELECT count(*) FROM audit_event WHERE action = 'auth.csrf.refused'")
    assert denials[0][0] >= len(routes) * 4


def test_csrf_token_may_also_arrive_as_a_form_field_and_tokens_skip_csrf(env: Env) -> None:
    c, _ = env.user_client("jules", [("viewer", "global")])
    csrf = c.get("/api/v1/session").json()["csrf_token"]
    r = c.post("/account/totp/enrol", data={"csrf_token": csrf}, headers={"Origin": ORIGIN})
    assert r.status_code == 200 and "Key:" in r.text
    r = c.post("/account/totp/enrol", data={"csrf_token": "nope"}, headers={"Origin": ORIGIN})
    assert r.status_code == 403
    # Bearer tokens carry no cookie and are exempt (no Origin, no CSRF token needed)
    raw = c.post(
        "/api/v1/tokens",
        json={"name": "t", "scopes": ["read"]},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    ).json()["token"]
    bare = env.client()
    assert (
        bare.get("/api/v1/session", headers={"Authorization": f"Bearer {raw}"}).status_code == 200
    )


def test_pre_session_forms_need_origin_and_double_submit_cookie(env: Env) -> None:
    env.user_client("kate", [("viewer", "global")])

    def attempt(origin: str | None, *, forged: bool = False, cookie: bool = True) -> Any:
        c = env.client()
        tok = env.form_token(c, "/login")
        if not cookie:
            c.cookies.clear()
        body = {"username": "kate", "password": PASSWORD, "csrf_token": "forged" if forged else tok}
        headers = {"Origin": origin} if origin else {}
        return c.post("/login", data=body, headers=headers, follow_redirects=False)

    assert attempt("https://evil.example").status_code == 403
    assert attempt(None).status_code == 403  # neither Origin nor Referer
    assert attempt(ORIGIN, forged=True).status_code == 403
    assert attempt(ORIGIN, cookie=False).status_code == 403  # no double-submit cookie
    r = attempt(ORIGIN)
    assert r.status_code == 303 and "__Host-ovlm_session" in r.headers["set-cookie"]
    # JSON login: a foreign Origin is refused; non-browser clients (no Origin) are fine
    foreign = env.client().post(
        "/api/v1/session",
        json={"username": "kate", "password": PASSWORD},
        headers={"Origin": "https://evil.example"},
    )
    assert foreign.status_code == 403
    # enrolment form
    link = env.create_user("lena", [("viewer", "global")])

    def enrol_attempt(origin: str) -> Any:
        e = env.client()
        t = env.form_token(e, f"/enrol/{link}")
        body = {"password": PASSWORD, "password_confirm": PASSWORD, "csrf_token": t}
        return e.post(
            f"/enrol/{link}", data=body, headers={"Origin": origin}, follow_redirects=False
        )

    assert enrol_attempt("https://evil.example").status_code == 403
    assert enrol_attempt(ORIGIN).status_code == 303


def test_security_headers_present_on_auth_pages(env: Env) -> None:
    r = env.client().get("/login")
    assert r.status_code == 200
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert not re.search(r"<script(?![^>]*\bsrc=)", r.text)  # no inline script under the CSP
    assert "X-Request-ID" in r.headers or "x-request-id" in r.headers
