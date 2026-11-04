# ruff: noqa: F811
"""Profiles and immutable versions against a real PostgreSQL, connected as the ``ovlm_api`` role (E3-3, SEC-R-36)."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.lifecycle_support import audit_rows
from tests.integration.test_registry_api import Env, env  # noqa: F401
from tests.unit.test_profile_spec_unit import SPEC, spec_with


def make_profile(
    env: Env, slug: str = "app01", spec: dict[str, Any] | None = None
) -> tuple[dict[str, Any], str]:
    svc = env.make_service(slug)
    r = env.client.post(
        f"/api/v1/services/{svc['id']}/profiles", json={"name": "main", "spec": spec or SPEC}
    )
    assert r.status_code == 201, r.text
    return r.json(), svc["id"]


def test_create_profile_stores_version_one_with_hash_and_etag(env: Env) -> None:
    created, service_id = make_profile(env)
    assert (
        created["service_id"] == service_id
        and created["latest_version"] == 1
        and created["version"] == 1
    )
    v = created["latest"]
    assert v["number"] == 1 and len(v["spec_hash"]) == 64 and v["automation_sha"] == "a" * 40
    assert v["lint_status"] == "pending" and v["lint_result"] is None
    # the image is a match rule as written, never a resolved id (SEC-R-29)
    assert v["spec"]["image"] == {"name": "ubuntu-24.04"}

    r = env.client.get(f"/api/v1/profiles/{created['id']}")
    assert r.status_code == 200 and r.headers["ETag"] == '"1"' and r.json()["latest"]["number"] == 1
    listed = env.client.get(f"/api/v1/services/{service_id}/profiles").json()["items"]
    assert [p["id"] for p in listed] == [created["id"]]


def test_one_profile_per_service(env: Env) -> None:
    _, service_id = make_profile(env)
    again = env.client.post(
        f"/api/v1/services/{service_id}/profiles", json={"name": "other", "spec": SPEC}
    )
    assert again.status_code == 409 and again.json()["code"] == "profile-exists"
    assert again.headers["content-type"].startswith("application/problem+json")


def test_new_versions_need_if_match_and_never_change_old_ones(env: Env) -> None:
    created, _ = make_profile(env)
    url = f"/api/v1/profiles/{created['id']}/versions"
    second = spec_with(flavor="m1.large")
    assert env.client.post(url, json={"spec": second}).status_code == 428
    stale = env.client.post(url, json={"spec": second}, headers={"If-Match": '"7"'})
    assert stale.status_code == 412 and stale.json()["code"] == "etag-mismatch"
    junk = env.client.post(url, json={"spec": second}, headers={"If-Match": "nonsense"})
    assert junk.status_code == 412

    ok = env.client.post(url, json={"spec": second}, headers={"If-Match": '"1"'})
    assert ok.status_code == 201 and ok.headers["ETag"] == '"2"' and ok.json()["number"] == 2
    assert ok.headers["Location"].endswith(f"/profiles/{created['id']}/versions/2")
    replay = env.client.post(
        url, json={"spec": second}, headers={"If-Match": '"1"'}
    )  # the same ETag again: lost the race
    assert replay.status_code == 412

    v1 = env.client.get(f"{url}/1").json()
    assert (
        v1["spec"]["flavor"] == "m1.small"
        and env.client.get(f"{url}/2").json()["spec"]["flavor"] == "m1.large"
    )
    assert v1["spec_hash"] != env.client.get(f"{url}/2").json()["spec_hash"]
    profile = env.client.get(f"/api/v1/profiles/{created['id']}")
    assert profile.json()["latest_version"] == 2 and profile.headers["ETag"] == '"2"'

    items = env.client.get(url).json()
    assert [i["number"] for i in items["items"]] == [1, 2] and "spec" not in items["items"][0]
    page = env.client.get(url, params={"limit": 1}).json()
    assert [i["number"] for i in page["items"]] == [1] and page["next_cursor"]
    rest = env.client.get(url, params={"limit": 1, "cursor": page["next_cursor"]}).json()
    assert [i["number"] for i in rest["items"]] == [2] and rest["next_cursor"] is None
    assert env.client.get(url, params={"cursor": "garbage"}).json()["code"] == "invalid-cursor"
    assert env.client.get(f"{url}/9").json()["code"] == "profile-version-not-found"


def test_invalid_specs_are_422_problem_json_with_field_errors_and_no_echoed_values(
    env: Env,
) -> None:
    created, service_id = make_profile(env)
    bad = spec_with()
    bad["automation"] = {
        **SPEC["automation"],
        "sha": "main",
        "secret_refs": {"vault": "hunter2-literal-password"},
    }
    bad["image"] = {"name": "latest"}
    for r in (
        env.client.post(
            f"/api/v1/profiles/{created['id']}/versions",
            json={"spec": bad},
            headers={"If-Match": '"1"'},
        ),
    ):
        assert r.status_code == 422 and r.headers["content-type"].startswith(
            "application/problem+json"
        )
        body = r.json()
        assert body["code"] == "invalid-profile-spec" and body["next_action"]
        assert {"automation.sha", "automation.secret_refs", "image"} <= {
            e["field"] for e in body["errors"]
        }
        assert "hunter2" not in r.text
    # nothing was stored, and the failed attempt did not consume the ETag
    assert env.client.get(f"/api/v1/profiles/{created['id']}").json()["latest_version"] == 1
    # a malformed body is a problem+json too
    r = env.client.post(f"/api/v1/services/{service_id}/profiles", json={"name": "", "extra": 1})
    assert r.status_code == 422 and r.json()["code"] in ("validation-error", "profile-exists")
    r = env.client.post(
        f"/api/v1/profiles/{created['id']}/versions", json={}, headers={"If-Match": '"1"'}
    )
    assert (
        r.status_code == 422
        and r.json()["code"] == "validation-error"
        and r.json()["errors"][0]["field"] == "spec"
    )


def test_unknown_things_are_404_problem_json(env: Env) -> None:
    for url in (
        f"/api/v1/profiles/{uuid4()}",
        f"/api/v1/profiles/{uuid4()}/versions",
        f"/api/v1/services/{uuid4()}/profiles",
    ):
        r = env.client.get(url)
        assert r.status_code == 404 and r.headers["content-type"].startswith(
            "application/problem+json"
        )
    assert (
        env.client.post(
            f"/api/v1/services/{uuid4()}/profiles", json={"name": "x", "spec": SPEC}
        ).status_code
        == 404
    )
    assert (
        env.client.post(
            f"/api/v1/profiles/{uuid4()}/versions", json={"spec": SPEC}, headers={"If-Match": '"1"'}
        ).status_code
        == 404
    )


def test_roles_viewer_reads_operator_writes(env: Env) -> None:
    created, service_id = make_profile(env)
    env.as_("viewer")
    assert env.client.get(f"/api/v1/profiles/{created['id']}").status_code == 200
    denied = env.client.post(
        f"/api/v1/profiles/{created['id']}/versions",
        json={"spec": SPEC},
        headers={"If-Match": '"1"'},
    )
    assert denied.status_code == 403
    assert (
        env.client.post(
            f"/api/v1/services/{service_id}/profiles", json={"name": "x", "spec": SPEC}
        ).status_code
        == 403
    )
    env.as_("admin")  # admin does not inherit operator
    assert (
        env.client.post(
            f"/api/v1/profiles/{created['id']}/versions",
            json={"spec": SPEC},
            headers={"If-Match": '"1"'},
        ).status_code
        == 403
    )
    anonymous = env.auth.client()
    assert anonymous.get(f"/api/v1/profiles/{created['id']}").status_code == 401
    assert env.client.get(f"/api/v1/profiles/{created['id']}/versions/1").status_code == 200


def test_changes_are_audited_with_allowlisted_fields_only(env: Env) -> None:
    created, _ = make_profile(env)
    env.client.post(
        f"/api/v1/profiles/{created['id']}/versions",
        json={"spec": spec_with(flavor="m1.large")},
        headers={"If-Match": '"1"'},
    )
    rows = audit_rows(env, "profile.version.create")
    assert (
        len(rows) == 2
        and rows[0].actor_id == env.operator_id
        and rows[0].project_scope == f"project:{env.project}"
    )
    assert rows[1].after["number"] == 2 and rows[1].after["automation_sha"] == "a" * 40
    for row in rows:
        assert (
            "spec" not in row.after
            and "secret_refs" not in str(row.after)
            and "ovlm-secret" not in str(row.after)
        )
    assert audit_rows(env, "profile.create")[0].after["name"] == "main"
    assert audit_rows(env, "profile.update")[0].after["latest_version"] == 2


# --- immutability is enforced by the database, not only by the api code (SEC-R-36) ----------------------------------------


def test_api_role_can_insert_but_never_update_or_delete_a_version(env: Env) -> None:
    created, _ = make_profile(env)
    vid = created["latest"]["id"]
    for stmt in (
        "UPDATE profile_version SET spec = '{}'::jsonb",
        "UPDATE profile_version SET lint_result = '{}'::jsonb",
        "UPDATE profile_version SET created_by = NULL",
        "DELETE FROM profile_version",
        "TRUNCATE profile_version",
    ):
        with env.api.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
            c.execute(text(stmt))
    with env.api.connect() as c:
        assert (
            c.execute(
                text("SELECT count(*) FROM profile_version WHERE id = :i"), {"i": vid}
            ).scalar_one()
            == 1
        )


def test_worker_may_set_lint_result_and_nothing_else(env: Env) -> None:
    created, _ = make_profile(env)
    vid = created["latest"]["id"]
    with env.worker.begin() as c:
        c.execute(
            text("UPDATE profile_version SET lint_result = '{\"ok\": true}'::jsonb WHERE id = :i"),
            {"i": vid},
        )
    assert (
        env.client.get(f"/api/v1/profiles/{created['id']}/versions/1").json()["lint_status"]
        == "done"
    )
    for stmt in (
        "UPDATE profile_version SET spec = '{}'::jsonb",
        "DELETE FROM profile_version",
        "UPDATE profile SET name = 'x'",
    ):
        with env.worker.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
            c.execute(text(stmt))


def test_trigger_blocks_spec_changes_even_for_the_table_owner(env: Env) -> None:
    created, _ = make_profile(env)
    with pytest.raises(DBAPIError, match="immutable"):
        env.auth.sql(
            "UPDATE profile_version SET spec = '{}'::jsonb WHERE id = :i", i=created["latest"]["id"]
        )
    with pytest.raises(DBAPIError, match="immutable"):
        env.auth.sql("DELETE FROM profile_version WHERE id = :i", i=created["latest"]["id"])
    env.auth.sql(
        "UPDATE profile_version SET lint_result = '{}'::jsonb WHERE id = :i",
        i=created["latest"]["id"],
    )  # allowed


def test_version_numbers_are_unique_per_profile(env: Env) -> None:
    created, _ = make_profile(env)
    with pytest.raises(DBAPIError, match="duplicate key"):
        env.auth.sql(
            "INSERT INTO profile_version (id, profile_id, number, spec, spec_hash) "
            "VALUES (gen_random_uuid(), :p, 1, '{}'::jsonb, :h)",
            p=created["id"], h="0" * 64,
        )  # fmt: skip
