# ruff: noqa: F811
"""``GET /api/v1/automation-runs/{id}/artefacts``: restricted artefacts for operator/admin of the run's project,
audited; viewers get 403, callers outside the project get 404. The api reads the table as ``ovlm_api`` and imports
no automation code."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text

from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.lifecycle_support import audit_rows
from tests.integration.test_registry_api import Env, Session, env  # noqa: F401

SECRET = "vault-decrypted-workload-secret"


def _insert_run(env: Env, scope: str, *, store_diffs: bool = True) -> str:
    """One ``automation_run`` row. The workflow rows it references are outside this test: the FK is bypassed with a
    superuser connection (``session_replication_role = replica``), exactly for this fixture."""
    run_id = str(uuid4())
    eng = create_engine(env.auth.admin_url.set(database=env.auth.db))
    try:
        with eng.begin() as c:
            c.execute(text("SET session_replication_role = replica"))
            c.execute(
                text(
                    """
                    INSERT INTO automation_run (id, step_id, attempt, phase, target_role, project_scope, repo, sha,
                      requirements_hash, ansible_core_version, extravars_sha256, extravars_keys, classification,
                      host_key_mode, log, events, diff, store_diffs, artifact_expires_at)
                    VALUES (:id, :step, 1, 'configure', 'new', :scope, 'https://git.example.org/a.git', :sha,
                      'b', '2.19.4', 'c', ARRAY['k'], 'ok', 'pinned', :log, CAST(:events AS jsonb), :diff,
                      :sd, :exp)
                    """
                ),
                {
                    "id": run_id, "step": str(uuid4()), "scope": scope, "sha": "a" * 40,
                    "log": f"TASK {SECRET}", "events": json.dumps([{"event": "runner_on_ok"}]),
                    "diff": "--- a\n+++ b\n" if store_diffs else None, "sd": store_diffs,
                    "exp": datetime.now(UTC) + timedelta(days=30),
                },
            )  # fmt: skip
    finally:
        eng.dispose()
    return run_id


def _client(env: Env, name: str, roles: list[tuple[str, str]]) -> Session:
    client, _ = env.auth.user_client(name, roles)
    return Session(client, UUID(client.get("/api/v1/session").json()["user_id"]))


def test_operator_and_admin_read_restricted_artefacts_and_it_is_audited(env: Env) -> None:
    scope = f"project:{env.project}"
    run_id = _insert_run(env, scope)
    scoped = _client(env, "proj-op", [("operator", scope)])
    for who in (scoped, env.users["operator"], env.users["admin"]):
        r = who.get(f"/api/v1/automation-runs/{run_id}/artefacts")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["log"] == f"TASK {SECRET}" and body["events"] == [{"event": "runner_on_ok"}]
        assert body["diff"].startswith("--- a") and body["label"] == "reported by guest"
        assert body["purged_at"] is None
    rows = audit_rows(env, "automation_artefact.view")
    assert len(rows) == 3 and all(r.project_scope == scope for r in rows)
    assert all(
        SECRET not in json.dumps([str(c) for c in r]) for r in rows
    )  # the content is never audited


def test_viewer_gets_403_and_outsider_404_both_audited_as_denied(env: Env) -> None:
    scope = f"project:{env.project}"
    run_id = _insert_run(env, scope)
    r = env.users["viewer"].get(f"/api/v1/automation-runs/{run_id}/artefacts")
    assert r.status_code == 403 and SECRET not in r.text
    elsewhere = _client(env, "other-op", [("operator", f"project:{uuid4()}")])
    r = elsewhere.get(f"/api/v1/automation-runs/{run_id}/artefacts")
    assert r.status_code == 404 and SECRET not in r.text
    unknown = env.users["operator"].get(f"/api/v1/automation-runs/{uuid4()}/artefacts")
    assert unknown.status_code == 404
    assert r.json()["code"] == unknown.json()["code"]  # no existence oracle
    results = env.auth.sql(
        "SELECT result FROM audit_event WHERE action = 'automation_artefact.view' ORDER BY id"
    )
    assert [x[0] for x in results] == ["denied", "denied"]


def test_diff_only_with_the_profile_opt_in_and_purged_runs_are_empty(env: Env) -> None:
    scope = f"project:{env.project}"
    run_id = _insert_run(env, scope, store_diffs=False)
    body = env.users["operator"].get(f"/api/v1/automation-runs/{run_id}/artefacts").json()
    assert body["diff"] is None and body["store_diffs"] is False
    env.auth.sql(
        "UPDATE automation_run SET log = NULL, events = NULL, diff = NULL, artifacts_purged_at = now() WHERE id = :i",
        i=run_id,
    )
    body = env.users["operator"].get(f"/api/v1/automation-runs/{run_id}/artefacts").json()
    assert body["log"] is None and body["events"] is None and body["purged_at"] is not None


def test_anonymous_and_operate_less_tokens_are_refused(env: Env) -> None:
    run_id = _insert_run(env, f"project:{env.project}")
    anon = env.auth.client().get(f"/api/v1/automation-runs/{run_id}/artefacts")
    assert anon.status_code == 401
    token = env.users["operator"].post("/api/v1/tokens", json={"name": "ro", "scopes": ["read"]})
    assert token.status_code == 201, token.text
    r = env.auth.client().get(
        f"/api/v1/automation-runs/{run_id}/artefacts",
        headers={"Authorization": f"Bearer {token.json()['token']}"},
    )
    assert r.status_code in (403, 404) and SECRET not in r.text


@pytest.mark.parametrize("bad", ["not-a-uuid", "123"])
def test_malformed_ids_are_validation_errors(env: Env, bad: str) -> None:
    assert env.users["operator"].get(f"/api/v1/automation-runs/{bad}/artefacts").status_code == 422
