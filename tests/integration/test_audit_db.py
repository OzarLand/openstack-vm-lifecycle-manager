# ruff: noqa: F811
"""Append-only audit log (security-model.md section 8 and section 10 items 12 and 14), against real PostgreSQL."""

from __future__ import annotations

import io
import json
import logging
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from ovlm import audit
from ovlm.observability.context import bind_context
from ovlm.observability.logging import JsonFormatter
from ovlm.observability.redaction import RedactionFilter
from tests.integration.auth_support import ORIGIN, PASSWORD, Env, env, log_lines  # noqa: F401

API_PW, WORKER_PW = "api-pw-test", "worker-pw-test"


def insert(conn: object) -> None:
    conn.execute(  # type: ignore[attr-defined]
        text(
            "INSERT INTO audit_event (principal_type, auth_method, action, target_type, result) "
            "VALUES ('system', 'cli', 'x.y', 'x', 'success')"
        )
    )


# --- DB-level enforcement (item 14) ---------------------------------------------------------------------------


@pytest.mark.parametrize(("role", "pw"), [("ovlm_api", API_PW), ("ovlm_worker", WORKER_PW)])
def test_runtime_roles_can_insert_and_select_but_not_change_history(
    env: Env, role: str, pw: str
) -> None:
    eng = env.role_engine(role, pw)
    with eng.begin() as c:
        insert(c)
        n = c.execute(text("SELECT count(*) FROM audit_event")).scalar_one()
        assert n >= 1
    for stmt in (
        "UPDATE audit_event SET action = 'tampered'",
        "UPDATE audit_event SET result = 'success' WHERE id = 1",
        "DELETE FROM audit_event",
        "DELETE FROM audit_event WHERE id = 1",
        "TRUNCATE audit_event",
        "DROP TABLE audit_event",
        "ALTER TABLE audit_event DISABLE TRIGGER ALL",
        "DROP TRIGGER audit_event_no_update_delete ON audit_event",
        "CREATE OR REPLACE FUNCTION audit_event_refuse_change() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'",
    ):
        with (
            eng.connect() as c,
            pytest.raises(ProgrammingError, match="permission denied|must be owner"),
        ):
            c.execute(text(stmt))
    with eng.connect() as c:
        assert (
            c.execute(
                text("SELECT count(*) FROM audit_event WHERE action = 'tampered'")
            ).scalar_one()
            == 0
        )
    eng.dispose()


def test_triggers_refuse_update_delete_truncate_even_for_the_table_owner(env: Env) -> None:
    """Catches a mis-grant: the owner holds every privilege, so only the trigger stands in the way."""
    env.sql(
        "INSERT INTO audit_event (principal_type, auth_method, action, target_type, result) "
        "VALUES ('system', 'cli', 'seed', 'x', 'success')"
    )
    for stmt in (
        "UPDATE audit_event SET action = 'tampered'",
        "DELETE FROM audit_event",
        "TRUNCATE audit_event",
    ):
        with pytest.raises(DBAPIError, match="append-only"):
            env.sql(stmt)
    assert env.sql("SELECT action FROM audit_event") == [("seed",)]


def test_mis_granted_runtime_role_is_still_stopped_by_the_trigger(env: Env) -> None:
    env.sql("GRANT UPDATE, DELETE, TRUNCATE ON audit_event TO ovlm_api")
    env.sql(
        "INSERT INTO audit_event (principal_type, auth_method, action, target_type, result) "
        "VALUES ('system', 'cli', 'seed', 'x', 'success')"
    )
    eng = env.role_engine("ovlm_api", API_PW)
    for stmt in (
        "UPDATE audit_event SET action = 'tampered'",
        "DELETE FROM audit_event",
        "TRUNCATE audit_event",
    ):
        with eng.connect() as c, pytest.raises(DBAPIError, match="append-only"):
            c.execute(text(stmt))
    eng.dispose()


def test_worker_sees_only_what_it_needs_of_the_auth_tables(env: Env) -> None:
    env.user_client("root", [("admin", "global")])
    eng = env.role_engine("ovlm_worker", WORKER_PW)
    with eng.connect() as c:
        assert c.execute(text("SELECT id, username, state, totp_confirmed_at FROM app_user")).all()
        assert c.execute(text("SELECT count(*) FROM role_binding")).scalar_one() == 1
        assert c.execute(text("SELECT count(*) FROM stepup")).scalar_one() == 0
    for stmt in (
        "SELECT password_hash FROM app_user",
        "SELECT totp_secret_enc FROM app_user",
        "SELECT * FROM app_user",
        "SELECT * FROM auth_session",
        "SELECT * FROM api_token",
        "SELECT * FROM enrolment_link",
        "UPDATE app_user SET state = 'disabled'",
        "INSERT INTO role_binding (id, user_id, role, scope) VALUES (gen_random_uuid(), gen_random_uuid(), 'admin', 'global')",
        "UPDATE stepup SET consumed_at = now()",
    ):
        with eng.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
            c.execute(text(stmt))
    eng.dispose()


def test_api_role_cannot_delete_users_bindings_tokens_or_history(env: Env) -> None:
    env.user_client("root", [("admin", "global")])
    eng = env.role_engine("ovlm_api", API_PW)
    for table in ("app_user", "role_binding", "api_token", "stepup", "enrolment_link"):
        with eng.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
            c.execute(text(f"DELETE FROM {table}"))  # noqa: S608
    eng.dispose()


# --- record(): same transaction, mirror after commit ---------------------------------------------------------


def capture() -> tuple[io.StringIO, logging.Handler]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter("test"))
    handler.addFilter(RedactionFilter())
    logging.getLogger("ovlm.audit").addHandler(handler)
    logging.getLogger("ovlm.audit").setLevel(logging.INFO)
    return stream, handler


def audit_lines(stream: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(x) for x in stream.getvalue().splitlines() if '"event": "audit"' in x]


def test_record_is_transactional_and_mirrors_each_committed_row_to_the_log(env: Env) -> None:
    audit.register_entity("widget", ["name", "size"], secret_fields=["secret_value"])
    stream, handler = capture()
    try:
        rid = uuid.uuid4()
        with bind_context(request_id="req-0123456789"), env.session() as db:
            row_id = audit.record(
                db,
                action="widget.update",
                target_type="widget",
                target_id="w1",
                actor_id=uuid.uuid4(),
                auth_method="password+totp",
                source_ip="203.0.113.9",
                project_scope="project:a",
                before={
                    "name": "old",
                    "size": 1,
                    "secret_value": "S3CRET-OLD",
                    "internal_note": "n",
                },
                after={
                    "name": "new",
                    "size": 2,
                    "secret_value": "S3CRET-NEW",
                    "internal_note": "n",
                },
                run_id=rid,
                authority_ref="approval-1",
            )
            assert audit_lines(stream) == []  # nothing is mirrored before the commit
            db.commit()
        [line] = audit_lines(stream)
        assert line["audit_id"] == row_id and line["request_id"] == "req-0123456789"
        assert line["before"] == {"name": "old", "size": 1}
        assert line["after"] == {"name": "new", "size": 2, "changed_fields": ["secret_value"]}
        assert line["run_id"] == str(rid) and line["authority_ref"] == "approval-1"
        [row] = env.sql("SELECT * FROM audit_event WHERE id = :i", i=row_id)
        assert row.before == line["before"] and row.after == line["after"]
        assert row.request_id == "req-0123456789" and row.source_ip == "203.0.113.9"
        assert row.ts is not None and row.project_scope == "project:a"
        assert "S3CRET" not in json.dumps(row.after) + json.dumps(row.before) + stream.getvalue()

        # a rolled-back transaction leaves no row and no log line
        stream.truncate(0)
        stream.seek(0)
        with env.session() as db:
            audit.record(
                db,
                action="widget.delete",
                target_type="widget",
                target_id="w2",
                auth_method="password",
            )
            db.rollback()
        assert audit_lines(stream) == []
        assert env.sql("SELECT count(*) FROM audit_event WHERE action = 'widget.delete'") == [(0,)]
    finally:
        logging.getLogger("ovlm.audit").removeHandler(handler)


def test_audit_insert_failure_rolls_back_the_change_it_records(env: Env) -> None:
    """Written in the same transaction as the change: if the audit row cannot be written, the change is lost."""
    with env.session() as db:
        db.execute(text("INSERT INTO schema_meta VALUES ('x', 'y')")) if False else None
        db.execute(
            text(
                "INSERT INTO login_attempt (kind, username, success) VALUES ('login', 'probe', true)"
            )
        )
        with pytest.raises(DBAPIError):
            audit.record(db, action="", target_type="x", auth_method="cli")  # CHECK (action <> '')
        db.rollback()
    assert env.sql("SELECT count(*) FROM login_attempt WHERE username = 'probe'") == [(0,)]


def test_record_refuses_an_entity_without_an_allowlist(env: Env) -> None:
    with env.session() as db, pytest.raises(audit.AllowlistError):
        audit.record(
            db, action="a.b", target_type="unregistered", auth_method="cli", after={"x": 1}
        )


def test_list_events_filters_newest_first(env: Env) -> None:
    actor = uuid.uuid4()
    with env.session() as db:
        for i in range(5):
            audit.record(
                db,
                action=f"t.{i}",
                target_type="endpoint",
                target_id=f"e{i % 2}",
                actor_id=actor if i < 3 else None,
                auth_method="password",
            )
        db.commit()
    with env.session() as db:
        rows = audit.list_events(db, actor_id=actor)
        assert [r.action for r in rows] == ["t.2", "t.1", "t.0"]
        assert [
            r.action for r in audit.list_events(db, target_type="endpoint", target_id="e1")
        ] == ["t.3", "t.1"]
        assert len(audit.list_events(db, limit=2)) == 2
        assert [r.action for r in audit.list_events(db, actions=["t.4"])] == ["t.4"]


# --- end to end: correlation, mirror and the secret canary (item 12) ------------------------------------------


def test_http_request_id_reaches_audit_rows_and_the_log_stream(env: Env) -> None:
    env.user_client("kim", [("viewer", "global")])
    c = env.client()
    r = c.post(
        "/api/v1/session",
        json={"username": "kim", "password": PASSWORD},
        headers={"Origin": ORIGIN, "X-Request-ID": "corr-abcdef-123456"},
    )
    assert r.status_code == 200 and r.headers["x-request-id"] == "corr-abcdef-123456"
    [row] = env.sql(
        "SELECT id, request_id, actor_id, principal_type, auth_method, source_ip "
        "FROM audit_event WHERE action = 'auth.login.success' ORDER BY id DESC LIMIT 1"
    )
    assert row.request_id == "corr-abcdef-123456" and row.principal_type == "human"
    mirrored = [
        x for x in log_lines(env) if x.get("event") == "audit" and x.get("audit_id") == row.id
    ]
    assert len(mirrored) == 1 and mirrored[0]["request_id"] == "corr-abcdef-123456"


def test_every_committed_audit_row_appears_in_the_log_stream(env: Env) -> None:
    admin, secret = env.user_client("root", [("admin", "global")])
    h = env.headers(admin)
    admin.post("/api/v1/users", json={"username": "newbie"}, headers=h)
    env.api_login(env.client(), "root", "wrong password entirely")
    admin.post("/_t/operator", headers=h)  # denied
    rows = env.sql("SELECT id, action FROM audit_event ORDER BY id")
    mirrored = {x["audit_id"]: x for x in log_lines(env) if x.get("event") == "audit"}
    assert {r.id for r in rows} == set(mirrored), (
        "DB rows and audit log lines must match one to one"
    )
    assert {r.id: r.action for r in rows} == {i: m["action"] for i, m in mirrored.items()}
    full = env.sql(
        "SELECT id, before, after, actor_id, result, target_id FROM audit_event ORDER BY id"
    )
    for row in full:  # the mirror carries the same content as the row, not just the same ids
        line = mirrored[row.id]
        assert (line["before"], line["after"], line["result"], line["target_id"]) == (
            row.before,
            row.after,
            row.result,
            row.target_id,
        )
        assert line["actor_id"] == (str(row.actor_id) if row.actor_id else None)


def test_secret_canary_never_appears_in_audit_rows_or_logs(env: Env) -> None:
    canary_pw = "CANARY-pw-9f3a7c1e-correct-horse"
    admin, _ = env.user_client("root", [("admin", "global")])
    h = env.headers(admin)
    r = admin.post(
        "/api/v1/users", json={"username": "tess", "roles": [{"role": "operator"}]}, headers=h
    )
    link = r.json()["enrolment_link"].removeprefix(f"{ORIGIN}/enrol/")
    link_secret = link.split(".", 1)[1]
    user = env.client()
    assert env.enrol(user, link, canary_pw).status_code == 303
    env.api_login(
        env.client(), "tess", canary_pw + "-wrong"
    )  # failed login with a canary-like password
    env.api_login(env.client(), "nobody", canary_pw)  # password typed into an unknown account
    cookie = user.cookies.get("__Host-ovlm_session")
    token = user.post(
        "/api/v1/tokens", json={"name": "t", "scopes": ["operate"]}, headers=env.headers(user)
    ).json()["token"]
    totp_secret = env.secrets["totp_secret"]
    user.post(
        "/api/v1/session/reauth",
        json={"password": canary_pw, "action": "a", "target_id": "t"},
        headers=env.headers(user),
    )
    admin.post(f"/api/v1/users/{r.json()['user_id']}/enrolment-link", headers=env.headers(admin))
    csrf = user.get("/api/v1/session").json()["csrf_token"]

    dump = json.dumps([dict(x._mapping) for x in env.sql("SELECT * FROM audit_event")], default=str)
    logs = env.log_stream.getvalue()
    haystack = dump + logs
    for name, value in {
        "password": canary_pw,
        "enrolment link secret": link_secret,
        "session id": cookie,
        "api token": token,
        "api token secret": token.split("_")[2],
        "totp secret": totp_secret,
        "totp key": env.secrets["totp_key"],
        "csrf token": csrf,
        "password hash": env.sql("SELECT password_hash FROM app_user WHERE username='tess'")[0][0],
    }.items():
        assert value and value not in haystack, f"{name} leaked into audit rows or logs"
    # users sometimes type a password in the username field: the unknown name is stored only as a short hash
    assert "nobody" not in dump
    assert "unknown:" in dump
