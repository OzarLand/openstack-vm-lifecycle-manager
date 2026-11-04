# ruff: noqa: F811
"""Separation of duties against a real PostgreSQL (security-model.md 3.2; section 10 items 7, 20, 24).

* role bindings: operator+approver in one scope refused by default, allowed once an admin turns the installation
  setting on (TOTP step-up + typed confirmation, audited, history kept);
* an admin cannot change their own bindings while another admin exists;
* the api's ``check_approval_eligibility`` reads the live setting;
* the worker's ``revalidate_approval_evidence``, connected as ``ovlm_worker``, evaluates the seven checks as of
  ``decided_at`` from the role-binding history, the step-up record and the setting history.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from ovlm.auth.principal import Principal
from ovlm.auth.sod import (
    ApprovalRecord,
    Gate,
    RecomputedFacts,
    RequesterSet,
    check_approval_eligibility,
    revalidate_approval_evidence,
)
from tests.integration.auth_support import PASSWORD, Env, env  # noqa: F401
from tests.integration.conftest import WORKER_PW

SCOPE = f"project:{uuid4()}"
ACTION = "approval.decide"


def uid(env: Env, username: str) -> UUID:
    return UUID(str(env.sql("SELECT id FROM app_user WHERE username = :u", u=username)[0][0]))


def admin(env: Env, name: str = "root") -> tuple[TestClient, str]:
    c, secret = env.user_client(name, [("admin", "global")])
    assert secret
    return c, secret


def stepup(env: Env, c: TestClient, secret: str, action: str, target: str) -> str:
    env.clock.advance()
    r = c.post(
        "/api/v1/session/reauth",
        json={
            "password": PASSWORD,
            "totp_code": env.code(secret),
            "action": action,
            "target_id": target,
        },
        headers=env.headers(c),
    )
    assert r.status_code == 200, r.text
    return str(r.json()["stepup_id"])


def set_allow(env: Env, c: TestClient, secret: str, value: bool) -> Any:
    sid = stepup(env, c, secret, "settings.auth.update", "allow_operator_approver")
    return c.put(
        "/api/v1/settings/auth",
        json={
            "allow_operator_approver": value,
            "stepup_id": sid,
            "typed_confirmation": f"allow_operator_approver={str(value).lower()}",
            "reason": "solo lab",
        },
        headers=env.headers(c),
    )


# --- role bindings ------------------------------------------------------------------------------------------------


def test_operator_and_approver_in_one_scope_is_refused_by_default(env: Env) -> None:
    c, secret = admin(env)
    h = env.headers(c)
    env.create_user("dual", [("operator", "global")])
    dual = str(uid(env, "dual"))
    r = c.post(
        "/api/v1/role-bindings",
        json={"user_id": dual, "role": "approver", "scope": SCOPE},
        headers=h,
    )
    assert r.status_code == 409 and r.json()["code"] == "sod-binding", r.text
    r = c.post(
        "/api/v1/users",
        json={
            "username": "both",
            "roles": [{"role": "operator"}, {"role": "approver", "scope": SCOPE}],
        },
        headers=h,
    )
    assert r.status_code == 409 and r.json()["code"] == "sod-binding"
    assert env.sql("SELECT count(*) FROM app_user WHERE username = 'both'")[0][0] == 0
    # disjoint project scopes are fine
    env.create_user("split", [("operator", SCOPE)])
    split = str(uid(env, "split"))
    other = f"project:{uuid4()}"
    r = c.post(
        "/api/v1/role-bindings",
        json={"user_id": split, "role": "approver", "scope": other},
        headers=h,
    )
    assert r.status_code == 201, r.text
    # once the installation allows it, the binding is accepted
    assert set_allow(env, c, secret, True).status_code == 200
    r = c.post(
        "/api/v1/role-bindings",
        json={"user_id": dual, "role": "approver", "scope": SCOPE},
        headers=env.headers(c),
    )
    assert r.status_code == 201, r.text
    listed = c.get("/api/v1/role-bindings", params={"user_id": dual}).json()["items"]
    assert {(b["role"], b["scope"]) for b in listed} == {
        ("operator", "global"),
        ("approver", SCOPE),
    }


def test_binding_for_unknown_user_is_404(env: Env) -> None:
    c, _ = admin(env)
    r = c.post(
        "/api/v1/role-bindings",
        json={"user_id": str(uuid4()), "role": "viewer"},
        headers=env.headers(c),
    )
    assert r.status_code == 404


def test_admin_cannot_change_own_bindings_unless_the_only_admin(env: Env) -> None:
    c, _ = admin(env)
    me = str(uid(env, "root"))
    r = c.post(
        "/api/v1/role-bindings", json={"user_id": me, "role": "viewer"}, headers=env.headers(c)
    )
    assert r.status_code == 201, r.text  # the only admin: allowed, audited as such
    assert (
        env.sql("SELECT count(*) FROM audit_event WHERE action = 'role_binding.create.own'")[0][0]
        == 1
    )
    c2, _ = admin(env, "root2")
    r = c2.post("/api/v1/role-bindings", json={"user_id": str(uid(env, "root2")), "role": "viewer"},
                headers=env.headers(c2))  # fmt: skip
    assert r.status_code == 403 and r.json()["code"] == "own-bindings"
    own = c2.get("/api/v1/role-bindings", params={"user_id": str(uid(env, "root2"))}).json()[
        "items"
    ]
    r = c2.delete(f"/api/v1/role-bindings/{own[0]['id']}", headers=env.headers(c2))
    assert r.status_code == 403
    # another admin may change them
    root_bindings = c2.get("/api/v1/role-bindings", params={"user_id": me}).json()["items"]
    viewer = next(b for b in root_bindings if b["role"] == "viewer")
    assert (
        c2.delete(f"/api/v1/role-bindings/{viewer['id']}", headers=env.headers(c2)).status_code
        == 204
    )


def test_user_detail_shows_bindings_and_provenance(env: Env) -> None:
    c, _ = admin(env)
    r = c.post(
        "/api/v1/users",
        json={"username": "second", "roles": [{"role": "approver"}]},
        headers=env.headers(c),
    )
    assert r.status_code == 201 and not {"password", "password_hash"} & set(r.json())
    d = c.get(f"/api/v1/users/{r.json()['user_id']}").json()
    assert d["roles"] == [{"role": "approver", "scope": "global"}]
    assert d["provenance"]["created_by"] == "root" and d["provenance"]["created_via"] == "admin"
    assert c.get(f"/api/v1/users/{uuid4()}").status_code == 404


# --- installation setting ---------------------------------------------------------------------------------------


def test_setting_change_needs_admin_stepup_and_typed_confirmation_and_keeps_history(
    env: Env,
) -> None:
    c, secret = admin(env)
    assert c.get("/api/v1/settings/auth").json()["allow_operator_approver"] is False
    # no / foreign step-up
    body = {"allow_operator_approver": True, "stepup_id": str(uuid4()),
            "typed_confirmation": "allow_operator_approver=true"}  # fmt: skip
    r = c.put("/api/v1/settings/auth", json=body, headers=env.headers(c))
    assert r.status_code == 403 and r.json()["code"] == "stepup-invalid"
    other = stepup(env, c, secret, "approval.decide", "allow_operator_approver")
    r = c.put("/api/v1/settings/auth", json={**body, "stepup_id": other}, headers=env.headers(c))
    assert r.status_code == 403
    # wrong typed confirmation: refused before the step-up is spent
    sid = stepup(env, c, secret, "settings.auth.update", "allow_operator_approver")
    r = c.put("/api/v1/settings/auth", json={**body, "stepup_id": sid, "typed_confirmation": "yes"},
              headers=env.headers(c))  # fmt: skip
    assert r.status_code == 422 and r.json()["code"] == "confirmation-mismatch"
    r = c.put("/api/v1/settings/auth", json={**body, "stepup_id": sid}, headers=env.headers(c))
    assert r.status_code == 200, r.text
    # replaying the spent step-up fails
    r = c.put("/api/v1/settings/auth", json={**body, "stepup_id": sid}, headers=env.headers(c))
    assert r.status_code == 403
    assert set_allow(env, c, secret, False).status_code == 200
    got = c.get("/api/v1/settings/auth").json()
    assert got["allow_operator_approver"] is False
    assert [h["value"] for h in got["history"]] == [False, True]
    rows = env.sql(
        "SELECT before, after FROM audit_event WHERE action = 'settings.auth.update' ORDER BY id"
    )
    assert [(r[0]["value"], r[1]["value"]) for r in rows] == [(False, True), (True, False)]
    # history cannot be rewritten
    with pytest.raises(DBAPIError):
        env.sql("UPDATE installation_setting SET value = 'true'")
    with pytest.raises(DBAPIError):
        env.sql("DELETE FROM installation_setting")


def test_setting_is_admin_only_and_never_by_token(env: Env) -> None:
    op, _ = env.user_client("ops", [("operator", "global")])
    assert op.get("/api/v1/settings/auth").status_code == 403
    ap, _ = env.user_client("appr", [("approver", "global")])
    assert ap.get("/api/v1/settings/auth").status_code == 403
    r = op.post(
        "/api/v1/tokens", json={"name": "t", "scopes": ["operate"]}, headers=env.headers(op)
    )
    raw = r.json()["token"]
    anon = env.client()
    assert (
        anon.get("/api/v1/settings/auth", headers={"Authorization": f"Bearer {raw}"}).status_code
        == 403
    )


# --- api-side eligibility ---------------------------------------------------------------------------------------


def _principal(user_id: UUID, *grants: tuple[str, str], method: str = "password+totp") -> Principal:
    return Principal(user_id, "x", "human", method, frozenset(grants), session_hash="s")


def test_check_approval_eligibility_reads_the_live_setting(env: Env) -> None:
    c, secret = admin(env)
    me = uuid4()
    p = _principal(me, ("operator", "global"), ("approver", SCOPE))
    with env.session() as db:
        e = check_approval_eligibility(
            db, p, gate=Gate.PLAN, scope=SCOPE, requester_set=RequesterSet()
        )
        assert not e.allowed and e.problem().code == "sod-violation"
    assert set_allow(env, c, secret, True).status_code == 200
    author = RequesterSet(profile_version_author=me)
    with env.session() as db:
        e = check_approval_eligibility(db, p, gate=Gate.CUTOVER, scope=SCOPE, requester_set=author)
        assert e.allowed and e.self_approved
        e = check_approval_eligibility(
            db, p, gate=Gate.RETIREMENT, scope=SCOPE, requester_set=author
        )
        assert not e.allowed
        # a token-like or password-only principal never decides
        e = check_approval_eligibility(
            db, _principal(uuid4(), ("approver", SCOPE), method="password"), gate=Gate.PLAN, scope=SCOPE,
            requester_set=RequesterSet(),
        )  # fmt: skip
        assert e.problem().code == "human-session-required"


# --- worker-side re-validation (renewal-workflow.md 3.1) -----------------------------------------------------------


class World:
    """An approval and the facts around it, written directly as the table owner (the approval table is E5-5)."""

    def __init__(self, env: Env) -> None:
        self.env = env
        env.create_user("author", [("operator", SCOPE)])
        env.create_user("alice", [("approver", SCOPE)])
        env.create_user("bob", [("approver", "global")])
        self.author, self.alice, self.bob = (uid(env, n) for n in ("author", "alice", "bob"))
        env.sql("UPDATE role_binding SET created_at = now() - interval '1 day'")
        self.decided_at = datetime.now(UTC) - timedelta(minutes=10)
        self.approval_id = uuid4()

    def step(self, user: UUID, *, target: str | None = None, action: str = ACTION, age_s: int = 30,
             method: str = "password+totp", consumed: bool = True) -> UUID:  # fmt: skip
        sid = uuid4()
        created = self.decided_at - timedelta(seconds=age_s)
        self.env.sql(
            """
            INSERT INTO stepup (id, user_id, session_id_hash, action, target_id, auth_method,
                                created_at, expires_at, consumed_at)
            VALUES (:id, :u, 'sess', :a, :t, :m, :c, :c + interval '5 minutes', :consumed)
            """,
            id=sid, u=user, a=action, t=target or str(self.approval_id), m=method, c=created,
            consumed=self.decided_at if consumed else None,
        )  # fmt: skip
        return sid

    def setting(self, value: bool, at: datetime) -> None:
        self.env.sql(
            "INSERT INTO installation_setting (key, value, changed_by, changed_at) "
            "VALUES ('allow_operator_approver', CAST(:v AS jsonb), :by, :at)",
            v="true" if value else "false", by=self.bob, at=at,
        )  # fmt: skip

    def approval(self, decider: UUID, gate: Gate = Gate.PLAN, **kw: Any) -> ApprovalRecord:
        base = ApprovalRecord(
            id=self.approval_id, gate=gate, scope=SCOPE, bound_hash="h" * 64, decision="approved",
            decided_by=decider, decided_at=self.decided_at, auth_method="password+totp",
            stepup_id=self.step(decider), typed_confirmation="app01 3f9c2a", self_approved=False,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )  # fmt: skip
        return replace(base, **kw)

    def facts(self, **kw: Any) -> RecomputedFacts:
        base = RecomputedFacts(
            plan_hash="h" * 64,
            requester_set=RequesterSet(
                profile_version_author=self.author,
                plan_creator=self.author,
                approval_requester=self.author,
            ),  # fmt: skip
            stepup_action=ACTION,
            stepup_target=str(self.approval_id),
            expected_confirmation="app01 3f9c2a",
            now=datetime.now(UTC),
        )
        return replace(base, **kw)

    def check(self, approval: ApprovalRecord, facts: RecomputedFacts | None = None) -> set[int]:
        engine = self.env.role_engine("ovlm_worker", WORKER_PW)
        try:
            with Session(engine) as db:
                result = revalidate_approval_evidence(db, approval, facts or self.facts())
        finally:
            engine.dispose()
        assert result.ok == (not result.failures())
        assert result.evidence["approval_id"] == str(approval.id)
        return {c.number for c in result.failures()}


@pytest.fixture
def world(env: Env) -> World:
    return World(env)


def test_valid_evidence_passes_all_seven_checks(world: World) -> None:
    assert world.check(world.approval(world.alice)) == set()
    assert (
        world.check(world.approval(world.bob, Gate.CUTOVER)) == set()
    )  # global approver covers the scope


def test_profile_author_approving_is_refused(world: World) -> None:
    world.env.sql("INSERT INTO role_binding (id, user_id, role, scope, created_at) "
                  "VALUES (:i, :u, 'approver', 'global', now() - interval '1 day')", i=uuid4(), u=world.author)  # fmt: skip
    failed = world.check(world.approval(world.author))
    assert 2 in failed and 6 in failed  # requester set and operator+approver


@pytest.mark.parametrize("role", ["profile_version_author", "plan_creator", "run_starter", "policy_editor",
                                  "approval_requester"])  # fmt: skip
def test_every_requester_set_member_is_refused(world: World, role: str) -> None:
    facts = world.facts(requester_set=RequesterSet(**{role: world.alice}))
    assert world.check(world.approval(world.alice), facts) == {2}


def test_self_approval_at_g3_is_refused_even_with_the_setting_on(world: World) -> None:
    world.setting(True, world.decided_at - timedelta(hours=1))
    facts = world.facts(requester_set=RequesterSet(run_starter=world.alice))
    g2 = world.approval(world.alice, Gate.CUTOVER, self_approved=True)
    assert world.check(g2, facts) == set()  # allowed and flagged at G2
    g3 = world.approval(world.alice, Gate.RETIREMENT, self_approved=True)
    assert {2, 7} <= world.check(g3, facts)
    g3_unflagged = world.approval(world.alice, Gate.RETIREMENT)
    assert 2 in world.check(g3_unflagged, facts)


def test_g3_needs_a_different_person_than_g1_no_revert_and_not_expired(world: World) -> None:
    g3 = world.approval(world.bob, Gate.RETIREMENT)
    assert world.check(g3) == set()
    assert world.check(g3, world.facts(prior_gate_deciders=frozenset({world.bob}))) == {7}
    assert world.check(g3, world.facts(revert_after_approval=True)) == {7}
    expired = replace(g3, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    assert world.check(expired) == {7}


def test_checks_are_historical(world: World) -> None:
    """A role revoked, a user disabled or the setting switched off after decided_at never trips the check."""
    world.setting(True, world.decided_at - timedelta(hours=1))
    world.env.sql("INSERT INTO role_binding (id, user_id, role, scope, created_at) "
                  "VALUES (:i, :u, 'operator', :s, now() - interval '1 day')", i=uuid4(), u=world.alice, s=SCOPE)  # fmt: skip
    approval = world.approval(world.alice, Gate.CUTOVER, self_approved=True)
    assert world.check(approval) == set()
    world.env.sql("UPDATE role_binding SET revoked_at = now() WHERE user_id = :u", u=world.alice)
    world.env.sql(
        "UPDATE app_user SET state = 'disabled', password_hash = 'x', disabled_at = now() WHERE id = :u",
        u=world.alice,
    )
    world.setting(False, datetime.now(UTC))
    assert world.check(approval) == set()


def test_role_or_setting_gained_after_the_decision_does_not_count(world: World) -> None:
    carol_link = world.env.create_user("carol", [])
    assert carol_link
    carol = uid(world.env, "carol")
    world.env.sql("INSERT INTO role_binding (id, user_id, role, scope) VALUES (:i, :u, 'approver', :s)",
                  i=uuid4(), u=carol, s=SCOPE)  # fmt: skip
    assert world.check(world.approval(carol)) == {3}
    # operator held then, setting turned on only afterwards: refused even though flagged
    world.setting(True, datetime.now(UTC))
    flagged = world.approval(world.author, Gate.CUTOVER, self_approved=True)
    world.env.sql("INSERT INTO role_binding (id, user_id, role, scope, created_at) "
                  "VALUES (:i, :u, 'approver', :s, now() - interval '1 day')", i=uuid4(), u=world.author, s=SCOPE)  # fmt: skip
    assert {2, 6} <= world.check(flagged)


def test_self_approved_flag_without_the_setting_is_refused(world: World) -> None:
    assert 2 in world.check(world.approval(world.alice, self_approved=True))


@pytest.mark.parametrize(
    "mutation",
    [
        "foreign_target",
        "foreign_action",
        "other_user",
        "too_old",
        "not_consumed",
        "password_only",
        "missing",
    ],
)
def test_stepup_evidence(world: World, mutation: str) -> None:
    w = world
    makers: dict[str, Callable[[], UUID | None]] = {
        "foreign_target": lambda: w.step(w.alice, target=str(uuid4())),
        "foreign_action": lambda: w.step(w.alice, action="run.revert"),
        "other_user": lambda: w.step(w.bob),
        "too_old": lambda: w.step(w.alice, age_s=301),
        "not_consumed": lambda: w.step(w.alice, consumed=False),
        "password_only": lambda: w.step(w.alice, method="password"),
        "missing": lambda: None,
    }
    sid = makers[mutation]()
    assert w.check(w.approval(w.alice, stepup_id=sid)) == {4}


def test_hash_confirmation_decision_and_interactive_session(world: World) -> None:
    a = world.approval(world.alice)
    assert world.check(a, world.facts(plan_hash="0" * 64)) == {1}
    assert world.check(a, world.facts(expected_confirmation="app01 000000")) == {5}
    assert world.check(replace(a, typed_confirmation=None)) == {5}
    assert (
        world.check(replace(a, typed_confirmation=None), world.facts(expected_confirmation=None))
        == set()
    )
    assert world.check(replace(a, void_reason="hash_changed")) == {0}
    assert world.check(replace(a, decision="rejected")) == {0}
    assert world.check(replace(a, auth_method="token")) == {3}


def test_distinct_approvers_policy_for_cutover(world: World) -> None:
    a = world.approval(world.alice, Gate.CUTOVER)
    facts = world.facts(prior_gate_deciders=frozenset({world.alice}))
    assert world.check(a, facts) == set()
    assert world.check(a, replace(facts, require_distinct_approvers=True)) == {7}
