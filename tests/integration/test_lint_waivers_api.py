# ruff: noqa: F811
"""Lint waiver API against PostgreSQL (automation-contract.md 9, SEC-R-36; security follow-up SF-13).

An approver with a TOTP step-up grants an audited waiver for one profile version, scoped to a rule and a path glob,
with a reason; lists and revokes it. RBAC: operators, viewers and API tokens cannot; separation of duties: the
version's author cannot waive their own version, even where the installation allows operator+approver. The table is
append-only for the ``ovlm_api`` role."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from tests.integration.auth_support import PASSWORD
from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.conftest import API_PW
from tests.integration.test_auth_authz import bearer, mint_token
from tests.integration.test_profiles_api import make_profile
from tests.integration.test_registry_api import Env, Session
from tests.integration.test_registry_api import env as env  # noqa: F401

REASON = "a read-only probe outside the lint allowlist, reviewed by hand"


def _user(env: Env, name: str, roles: list[tuple[str, str]]) -> tuple[Session, str | None]:
    client, secret = env.auth.user_client(name, roles)
    return Session(client, UUID(client.get("/api/v1/session").json()["user_id"])), secret


def _stepup(env: Env, who: Session, secret: str | None, action: str, target: str) -> str:
    env.auth.clock.advance()
    body: dict[str, Any] = {"password": PASSWORD, "action": action, "target_id": target}
    if secret:
        body["totp_code"] = env.auth.code(secret)
    r = who.post("/api/v1/session/reauth", json=body)
    assert r.status_code == 200, r.text
    return str(r.json()["stepup_id"])


def _version(env: Env) -> tuple[str, str]:
    created, _ = make_profile(env)
    return created["id"], created["latest"]["id"]


def _grant(who: Session, profile: str, stepup: str | None, **kw: Any) -> Any:
    body = {"rule": "check_mode_forced", "path_glob": "roles/probe/*", "reason": REASON, **kw}
    if stepup is not None:
        body["stepup_id"] = stepup
    return who.post(f"/api/v1/profiles/{profile}/versions/1/lint-waivers", json=body)


def test_approver_grants_lists_and_revokes_with_a_totp_stepup(env: Env) -> None:
    profile, version = _version(env)  # authored by the operator
    ap, secret = _user(env, "approver1", [("approver", "global")])
    url = f"/api/v1/profiles/{profile}/versions/1/lint-waivers"

    assert _grant(ap, profile, None).status_code == 422  # a step-up is required
    wrong_target = _stepup(env, ap, secret, "lint_waiver.grant", str(uuid4()))
    assert _grant(ap, profile, wrong_target).json()["code"] == "stepup-invalid"
    sid = _stepup(env, ap, secret, "lint_waiver.grant", version)
    bad_rule = _grant(ap, profile, sid, rule="formatting")  # data-safety rules are never waivable
    assert bad_rule.status_code == 422 and bad_rule.json()["code"] == "invalid-lint-waiver"
    for glob in ("/etc/*", "../x", "roles/../../etc"):
        assert _grant(ap, profile, sid, path_glob=glob).status_code == 422
    assert _grant(ap, profile, sid, reason="short").status_code == 422

    ok = _grant(ap, profile, sid)  # the step-up was not spent by the refusals above
    assert ok.status_code == 201, ok.text
    w = ok.json()
    assert (w["rule"], w["path_glob"], w["state"], w["profile_version"]) == (
        "check_mode_forced", "roles/probe/*", "active", 1,
    )  # fmt: skip
    assert w["granted_by"] == str(ap.user_id) and w["stepup_id"] == sid
    replay = _grant(ap, profile, sid)
    assert replay.status_code == 403 and replay.json()["code"] == "stepup-invalid"

    listed = env.client.get(url).json()["items"]  # a viewer-level read (the operator)
    assert [x["id"] for x in listed] == [w["id"]]
    [a] = env.auth.sql(
        "SELECT actor_id, project_scope, after FROM audit_event WHERE action = 'lint_waiver.grant'"
    )
    assert str(a.actor_id) == str(ap.user_id) and a.project_scope == f"project:{env.project}"
    assert a.after["rule"] == "check_mode_forced" and a.after["stepup_id"] == sid
    assert a.after["reason"] == REASON and a.after["profile_version_id"] == version

    revoke = f"/api/v1/lint-waivers/{w['id']}/revoke"
    rsid = _stepup(env, ap, secret, "lint_waiver.revoke", w["id"])
    no_reason = ap.post(revoke, json={"reason": "no", "stepup_id": rsid})
    assert no_reason.status_code == 422
    done = ap.post(revoke, json={"reason": "the probe moved into the allowlist", "stepup_id": rsid})
    assert done.status_code == 200 and done.json()["state"] == "revoked", done.text
    assert done.json()["revoked_by"] == str(ap.user_id)
    assert env.client.get(url).json()["items"] == []
    assert [x["state"] for x in env.client.get(f"{url}?include_revoked=true").json()["items"]] == [
        "revoked"
    ]
    again = ap.post(
        revoke,
        json={"reason": "the probe moved into the allowlist", "stepup_id": _stepup(env, ap, secret, "lint_waiver.revoke", w["id"])},
    )  # fmt: skip
    assert again.status_code == 409
    assert env.auth.sql("SELECT 1 FROM audit_event WHERE action = 'lint_waiver.revoke'")


def test_rbac_operators_viewers_and_tokens_cannot_waive(env: Env) -> None:
    profile, version = _version(env)
    op = env.users["operator"]
    sid = _stepup(
        env, op, None, "lint_waiver.grant", version
    )  # password-only (operators have no TOTP)
    assert _grant(op, profile, sid).status_code == 403
    assert _grant(env.users["viewer"], profile, str(uuid4())).status_code == 403
    token = mint_token(env.auth, op.client, "operate")
    as_token = op.client.post(
        f"/api/v1/profiles/{profile}/versions/1/lint-waivers", headers=bearer(token),
        json={"rule": "check_mode_forced", "path_glob": "*", "reason": REASON, "stepup_id": sid},
    )  # fmt: skip
    assert as_token.status_code == 403
    # an approver of another project neither sees nor waives this version
    other, secret = _user(env, "approver-other", [("approver", f"project:{uuid4()}")])
    elsewhere = _grant(other, profile, _stepup(env, other, secret, "lint_waiver.grant", version))
    assert elsewhere.status_code == 404
    assert not env.auth.sql("SELECT 1 FROM lint_waiver")


def test_the_author_cannot_waive_their_own_version_whatever_the_setting(env: Env) -> None:
    env.auth.sql(
        "INSERT INTO installation_setting (key, value, changed_by, reason) VALUES ('allow_operator_approver', "
        "'true', (SELECT id FROM app_user WHERE username = 'admin'), 'test')"
    )
    both, secret = _user(env, "both", [("operator", "global"), ("approver", "global")])
    env.users["both"] = both
    env.as_("both")
    profile, version = _version(env)  # authored by "both"
    refused = _grant(both, profile, _stepup(env, both, secret, "lint_waiver.grant", version))
    assert refused.status_code == 403 and refused.json()["code"] == "sod-violation"
    assert "authored" in refused.json()["detail"]
    assert env.auth.sql(
        "SELECT 1 FROM audit_event WHERE action = 'lint_waiver.grant.refused' AND result = 'denied'"
    )
    assert not env.auth.sql("SELECT 1 FROM lint_waiver")
    ap, ap_secret = _user(env, "approver2", [("approver", "global")])
    assert (
        _grant(ap, profile, _stepup(env, ap, ap_secret, "lint_waiver.grant", version)).status_code
        == 201
    )


def test_the_api_role_cannot_delete_or_rewrite_a_waiver(env: Env) -> None:
    profile, version = _version(env)
    ap, secret = _user(env, "approver3", [("approver", "global")])
    wid = _grant(ap, profile, _stepup(env, ap, secret, "lint_waiver.grant", version)).json()["id"]
    api = env.auth.role_engine("ovlm_api", API_PW)
    try:
        for stmt in (
            "DELETE FROM lint_waiver",
            "UPDATE lint_waiver SET path_glob = '*'",
            "UPDATE lint_waiver SET rule = 'no_log_secret'",
        ):
            with pytest.raises(DBAPIError), api.begin() as c:
                c.execute(text(stmt))
        # never waivable, whoever writes the row (review SFR-5): a real, consumed step-up that passes the api guard
        # and a specific glob, so only the rule CHECK can refuse it
        valid = _stepup_row(env, ap.user_id, "lint_waiver.grant", version)
        with pytest.raises(DBAPIError, match="lint_waiver_rule_check"), api.begin() as c:
            c.execute(
                text("INSERT INTO lint_waiver (id, profile_version_id, rule, path_glob, reason, granted_by, stepup_id) "
                     "SELECT :i, profile_version_id, 'formatting', 'roles/probe/*', reason, granted_by, :s "
                     "FROM lint_waiver"),
                {"i": uuid4(), "s": valid},
            )  # fmt: skip
        with api.begin() as c:  # the same row with a waivable rule is accepted: the CHECK alone refused it
            c.execute(
                text("INSERT INTO lint_waiver (id, profile_version_id, rule, path_glob, reason, granted_by, stepup_id) "
                     "SELECT :i, profile_version_id, 'no_log_secret', 'roles/probe/*', reason, granted_by, :s "
                     "FROM lint_waiver"),
                {"i": uuid4(), "s": valid},
            )  # fmt: skip
    finally:
        api.dispose()
    assert (
        env.auth.sql("SELECT path_glob FROM lint_waiver WHERE id = :i", i=wid)[0][0]
        == "roles/probe/*"
    )
    assert not env.auth.sql("SELECT 1 FROM lint_waiver WHERE rule = 'formatting'")


def _stepup_row(
    env: Env,
    user: UUID | str,
    action: str,
    target: str,
    *,
    method: str = "password+totp",
    consumed: bool = True,
) -> str:
    """A step-up row written as the owner (what the api would have stored), consumed or not."""
    sid = str(uuid4())
    env.auth.sql(
        "INSERT INTO stepup (id, user_id, session_id_hash, action, target_id, auth_method, created_at, expires_at, "
        "consumed_at) VALUES (:i, :u, 'sess', :a, :t, :m, now() - interval '1 minute', now() + interval '4 minutes', "
        "CASE WHEN :c THEN now() END)",
        i=sid, u=str(user), a=action, t=target, m=method, c=consumed,
    )  # fmt: skip
    return sid


CATCH_ALL = ("*", "**", "*/*", "**/*", "*/**", "[a-z]*")


def test_sfr2_a_catch_all_glob_is_refused_by_the_api_and_the_database(env: Env) -> None:
    """Review SFR-2: a glob with no literal path segment waives the rule for the whole repository."""
    profile, version = _version(env)
    ap, secret = _user(env, "approver4", [("approver", "global")])
    sid = _stepup(env, ap, secret, "lint_waiver.grant", version)
    for glob in CATCH_ALL:
        refused = _grant(ap, profile, sid, path_glob=glob)
        assert refused.status_code == 422 and "literal path segment" in refused.json()["detail"], (
            glob
        )
    for glob in ("roles/probe/*", "*/tasks/main.yml", "playbooks/configure.yml"):
        ok = _grant(
            ap, profile, _stepup(env, ap, secret, "lint_waiver.grant", version), path_glob=glob
        )
        assert ok.status_code == 201, (glob, ok.text)
    # the CHECK holds whoever writes the row (the owner here, which the api guard does not cover)
    for glob in CATCH_ALL:
        with pytest.raises(DBAPIError, match="lint_waiver_path_glob_check"):
            env.auth.sql(
                "INSERT INTO lint_waiver (id, profile_version_id, rule, path_glob, reason, granted_by, stepup_id) "
                "VALUES (:i, :v, 'no_log_secret', :g, :why, :u, :s)",
                i=str(uuid4()), v=version, g=glob, why=REASON, u=str(ap.user_id),
                s=_stepup_row(env, ap.user_id, "lint_waiver.grant", version),
            )  # fmt: skip


def _insert(engine: Any, **row: Any) -> None:
    with engine.begin() as c:
        c.execute(
            text("INSERT INTO lint_waiver (id, profile_version_id, rule, path_glob, reason, granted_by, stepup_id) "
                 "VALUES (:i, :v, :r, :g, :why, :u, :s)"),
            {"i": str(uuid4()), "r": "no_log_secret", "g": "roles/probe/*", "why": REASON, **row},
        )  # fmt: skip


def test_sfr1_the_api_role_cannot_forge_a_waiver_or_a_revocation(env: Env) -> None:
    """Review SFR-1: ``ovlm_api`` held INSERT on every column, so a compromised api could write a waiver in anyone's
    name with any step-up. The guard (``lint_waiver_api_guard``) now asks, for every member of ``ovlm_api``, the
    granter's own consumed password+TOTP step-up for ``lint_waiver.grant`` on that version, and a granter other than
    the author; the same for a revocation (``lint_waiver.revoke`` on the waiver id)."""
    profile, version = _version(env)
    author = str(
        env.auth.sql("SELECT created_by FROM profile_version WHERE id = :v", v=version)[0][0]
    )
    ap, _ = _user(env, "approver5", [("approver", "global")])
    other, _ = _user(env, "approver6", [("approver", "global")])
    me = str(ap.user_id)
    api = env.auth.role_engine("ovlm_api", API_PW)
    try:
        # the reviewer's probe: the author as granter, an unconsumed step-up bound to another action and target
        unrelated = _stepup_row(env, author, "approval.decide", str(uuid4()), consumed=False)
        with pytest.raises(DBAPIError, match="lint waiver"):
            _insert(api, v=version, u=author, s=unrelated)
        # each defect alone is refused
        defects = {
            "another user's step-up": (
                me,
                _stepup_row(env, other.user_id, "lint_waiver.grant", version),
            ),
            "another action": (me, _stepup_row(env, me, "lint_waiver.revoke", version)),
            "another target": (me, _stepup_row(env, me, "lint_waiver.grant", str(uuid4()))),
            "password alone": (
                me,
                _stepup_row(env, me, "lint_waiver.grant", version, method="password"),
            ),
            "not consumed": (
                me,
                _stepup_row(env, me, "lint_waiver.grant", version, consumed=False),
            ),
            "the author": (author, _stepup_row(env, author, "lint_waiver.grant", version)),
        }
        for name, (granter, sid) in defects.items():
            with pytest.raises(DBAPIError, match="lint waiver"):
                _insert(api, v=version, u=granter, s=sid)
            assert not env.auth.sql("SELECT 1 FROM lint_waiver"), name
        # what the api writes after consuming the right step-up passes
        _insert(api, v=version, u=me, s=_stepup_row(env, me, "lint_waiver.grant", version))
        [wid] = [str(r[0]) for r in env.auth.sql("SELECT id FROM lint_waiver")]

        revoke = (
            "UPDATE lint_waiver SET revoked_by = :u, revoked_at = now(), revoke_stepup_id = :s, "
            "revoke_reason = 'no longer needed here' WHERE id = :i"
        )
        for granter, sid in (
            (
                author,
                _stepup_row(env, author, "lint_waiver.grant", version),
            ),  # the reviewer's probe
            (
                me,
                _stepup_row(env, me, "lint_waiver.revoke", version),
            ),  # bound to the version, not the waiver
            (me, _stepup_row(env, me, "lint_waiver.revoke", wid, consumed=False)),
            (me, _stepup_row(env, other.user_id, "lint_waiver.revoke", wid)),
            (me, _stepup_row(env, me, "lint_waiver.revoke", wid, method="password")),
        ):
            with pytest.raises(DBAPIError, match="lint waiver"), api.begin() as c:
                c.execute(text(revoke), {"u": granter, "s": sid, "i": wid})
        with api.begin() as c:
            c.execute(
                text(revoke),
                {"u": me, "s": _stepup_row(env, me, "lint_waiver.revoke", wid), "i": wid},
            )
    finally:
        api.dispose()
    assert env.auth.sql("SELECT revoked_by FROM lint_waiver")[0][0] == ap.user_id
