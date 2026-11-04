# ruff: noqa: F811
"""Readiness end to end against a real PostgreSQL: the api (as ``ovlm_api``) requests an assessment, the worker's
``readiness`` definition (as ``ovlm_worker``) runs it from the DB inventory written by the real sync job with the
fake cloud, and the api reads the result. Also the append-only rule, auth, scoping and audit."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from ovlm.readiness.checks import CHECKS
from ovlm.readiness.job import ReadinessDefinition, store_assessment
from ovlm.workflow.engine import WorkflowEngine
from ovlm.workflow.registry import Registry
from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.lifecycle_support import audit_rows
from tests.integration.test_registry_api import Env, Session, env  # noqa: F401
from tests.integration.workflow.conftest import TEST_CONFIG
from tests.unit.test_profile_spec_unit import SHA, SPEC, spec_with


def good_spec(env: Env, **changes: Any) -> dict[str, Any]:
    spec = spec_with(
        image={"name": "ubuntu"},
        data_volume={**SPEC["data_volume"], "volume_id": env.ids["vol"]},
        cutover={"floating_ip_id": env.ids["fip"]},
    )
    spec.update(changes)
    return spec


def setup_vm(env: Env, spec: dict[str, Any] | bool | None = None) -> dict[str, Any]:
    svc = env.make_service()
    r = env.client.post(
        f"/api/v1/services/{svc['id']}/managed-vms",
        json={"observed_server_id": env.observed_id(env.ids["blue"])},
    )
    assert r.status_code == 201, r.text
    if spec is not False:
        assert not isinstance(spec, bool)
        p = env.client.post(
            f"/api/v1/services/{svc['id']}/profiles",
            json={"name": "main", "spec": spec or good_spec(env)},
        )
        assert p.status_code == 201, p.text
    return r.json()  # type: ignore[no-any-return]


def run_worker(env: Env) -> WorkflowEngine:
    engine = WorkflowEngine(env.worker, Registry([ReadinessDefinition(env.worker)]), TEST_CONFIG)
    for _ in range(20):
        engine.run_once()
        pending = env.auth.sql(
            "SELECT count(*) FROM workflow_run WHERE kind='readiness' AND state NOT IN ('completed','failed','rejected')"
        )
        if pending[0][0] == 0:
            break
    return engine


def assess(env: Env, vm: dict[str, Any]) -> dict[str, Any]:
    r = env.client.post(f"/api/v1/managed-vms/{vm['id']}/assessments")
    assert r.status_code == 202, r.text
    run_worker(env)
    items = env.client.get(f"/api/v1/managed-vms/{vm['id']}/assessments").json()["items"]
    detail = env.client.get(f"/api/v1/assessments/{items[0]['id']}")
    assert detail.status_code == 200, detail.text
    return detail.json()  # type: ignore[no-any-return]


def by_key(a: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["key"]: c for c in a["checks"]}


def test_request_is_202_run_then_worker_stores_a_ready_assessment(env: Env) -> None:
    vm = setup_vm(env)
    r = env.client.post(f"/api/v1/managed-vms/{vm['id']}/assessments")
    assert r.status_code == 202
    body = r.json()
    assert body["run"]["state"] == "requested" and body["already_pending"] is False
    assert r.headers["Location"] == f"/api/v1/managed-vms/{vm['id']}/assessments"
    # the api wrote nothing but the request: no assessment exists until the worker ran
    listing = env.client.get(f"/api/v1/managed-vms/{vm['id']}/assessments").json()
    assert listing["items"] == [] and listing["runs"][0]["id"] == body["run"]["id"]

    again = env.client.post(f"/api/v1/managed-vms/{vm['id']}/assessments").json()
    assert again["already_pending"] is True and again["run"]["id"] == body["run"]["id"]

    run_worker(env)
    run = env.auth.sql(
        "SELECT kind, state, strategy FROM workflow_run WHERE id = :i", i=body["run"]["id"]
    )[0]
    assert tuple(run) == ("readiness", "completed", "readiness")
    items = env.client.get(f"/api/v1/managed-vms/{vm['id']}/assessments").json()["items"]
    assert (
        len(items) == 1
        and items[0]["level"] == "ready"
        and items[0]["workflow_run_id"] == body["run"]["id"]
    )

    a = env.client.get(f"/api/v1/assessments/{items[0]['id']}").json()
    keys = by_key(a)
    assert list(keys) == [c.key for c in CHECKS]  # catalogue order, every check present
    assert all(c["version"] >= 1 for c in a["checks"])
    expect = {"automation.pinned_sha": "pass", "data.separate_volume": "pass", "data.volume_type_explicit": "pass",
              "vm.state_supported": "pass", "vm.root_disk_image_booted": "pass", "network.floating_ip": "pass",
              "platform.flavor_resolvable": "pass", "platform.image_resolvable": "pass",
              "validation.health_check_defined": "pass", "automation.drift_unchecked": "unknown",
              "platform.quota_headroom": "unknown", "external.human_attestations": "unknown"}  # fmt: skip
    assert {k: v["result"] for k, v in keys.items()} == expect
    assert a["summary"]["orientation_only"] is True and a["summary"]["failed_blockers"] == []
    assert (
        a["live_code_run"] is False and a["profile_version_id"] and a["observed_server_revision_id"]
    )
    snap = a["input_snapshot"]
    assert snap["live_code_run"] is False and snap["server"]["openstack_id"] == env.ids["blue"]
    assert snap["attachments"][0]["volume_openstack_id"] == env.ids["vol"]
    assert snap["profile"]["spec"]["automation"]["sha"] == SHA
    assert "secret_refs" not in snap["profile"]["spec"]["automation"] and "ovlm-secret" not in str(
        snap
    )
    assert a["recommendations"] and all(
        x["text"] for x in a["recommendations"]
    )  # the unknown ones explain themselves


def test_each_assessment_is_new_and_old_ones_never_change(env: Env) -> None:
    vm = setup_vm(env)
    first = assess(env, vm)
    assert first["level"] == "ready"
    env.fake.lock_server(env.ids["blue"], "someone")
    env.sync(kind="full")
    second = assess(env, vm)
    assert second["id"] != first["id"] and second["level"] == "not-ready"
    assert by_key(second)["vm.state_supported"]["result"] == "fail"
    assert second["summary"]["failed_blockers"] == ["vm.state_supported"]
    assert [b["key"] for b in second["blockers"]] == ["vm.state_supported"]
    assert (
        second["observed_server_revision_id"] != first["observed_server_revision_id"]
    )  # a new revision was seen
    again = env.client.get(f"/api/v1/assessments/{first['id']}").json()
    assert (
        again["level"] == "ready"
        and again["checks"] == first["checks"]
        and again["input_snapshot"] == first["input_snapshot"]
    )
    listed = env.client.get(f"/api/v1/managed-vms/{vm['id']}/assessments").json()["items"]
    assert [i["id"] for i in listed] == [second["id"], first["id"]]  # newest first
    page = env.client.get(f"/api/v1/managed-vms/{vm['id']}/assessments", params={"limit": 1}).json()
    assert [i["id"] for i in page["items"]] == [second["id"]] and page["next_cursor"]
    rest = env.client.get(
        f"/api/v1/managed-vms/{vm['id']}/assessments",
        params={"limit": 1, "cursor": page["next_cursor"]},
    ).json()
    assert [i["id"] for i in rest["items"]] == [first["id"]] and rest["next_cursor"] is None


def test_a_vm_without_a_profile_is_partially_ready_at_most(env: Env) -> None:
    a = assess(env, setup_vm(env, spec=False))
    assert a["level"] == "partially-ready" and a["profile_version_id"] is None
    assert by_key(a)["automation.pinned_sha"]["result"] == "unknown"


def test_a_bad_profile_makes_it_not_ready_with_recommendations(env: Env) -> None:
    spec = good_spec(env, flavor="no-such-flavor", image={"name": "no-such-image"})
    a = assess(env, setup_vm(env, spec))
    assert a["level"] == "not-ready"
    assert set(a["summary"]["failed_blockers"]) == {
        "platform.flavor_resolvable",
        "platform.image_resolvable",
    }
    recs = {r["check"]: r["text"] for r in a["recommendations"]}
    assert (
        "flavor" in recs["platform.flavor_resolvable"].lower()
        and "image" in recs["platform.image_resolvable"].lower()
    )


def test_assessments_and_results_are_append_only_and_the_api_cannot_write_them(env: Env) -> None:
    a = assess(env, setup_vm(env))
    for who, engine in (("owner", env.auth.owner), ("worker", env.worker)):
        for stmt in (
            "UPDATE readiness_assessment SET level = 'ready'",
            "DELETE FROM readiness_assessment",
            "UPDATE check_result SET result = 'pass'",
            "DELETE FROM check_result",
        ):
            with pytest.raises((DBAPIError, ProgrammingError)), engine.begin() as c:
                c.execute(text(stmt))
            assert who
    with pytest.raises(ProgrammingError), env.api.begin() as c:
        c.execute(
            text(
                "INSERT INTO check_result (id, assessment_id, check_key, check_version, category, result, severity, seq) "
                "VALUES (gen_random_uuid(), :a, 'x', 1, 'dependencies', 'pass', 'info', 99)"
            ),
            {"a": a["id"]},
        )
    with pytest.raises(ProgrammingError), env.api.begin() as c:
        c.execute(
            text(
                "INSERT INTO readiness_assessment (id, managed_vm_id, input_snapshot, level, summary, workflow_run_id) "
                "VALUES (gen_random_uuid(), gen_random_uuid(), '{}', 'ready', '{}', gen_random_uuid())"
            )
        )
    assert len(env.client.get(f"/api/v1/assessments/{a['id']}").json()["checks"]) == len(CHECKS)


def test_a_retried_step_stores_one_assessment_per_run(env: Env) -> None:
    vm = setup_vm(env)
    run = env.client.post(f"/api/v1/managed-vms/{vm['id']}/assessments").json()["run"]["id"]
    first = store_assessment(env.worker, run, UUID(vm["id"]), None)
    replay = store_assessment(
        env.worker, run, UUID(vm["id"]), None
    )  # a second attempt after a lost response
    assert first and first["assessment_id"] and replay == {"assessment_id": None, "replayed": True}
    assert (
        env.auth.sql("SELECT count(*) FROM readiness_assessment WHERE workflow_run_id = :r", r=run)[
            0
        ][0]
        == 1
    )
    assert env.auth.sql("SELECT count(*) FROM check_result")[0][0] == len(CHECKS)
    run_worker(env)  # the step finds the stored one and completes without writing another
    assert env.auth.sql("SELECT count(*) FROM readiness_assessment")[0][0] == 1
    assert env.auth.sql("SELECT state FROM workflow_run WHERE id = :r", r=run)[0][0] == "completed"


def test_audit_records_the_request_and_the_completion(env: Env) -> None:
    vm = setup_vm(env)
    a = assess(env, vm)
    req = audit_rows(env, "readiness.request")
    assert (
        len(req) == 1 and req[0].actor_id == env.operator_id and req[0].target_id
        if hasattr(req[0], "target_id")
        else True
    )
    assert (
        req[0].after["managed_vm_id"] == vm["id"]
        and req[0].after["run_repo_code_on_live_vm"] is False
    )
    done = env.auth.sql(
        "SELECT principal_type, run_id FROM audit_event WHERE action = 'readiness.assessment.complete'"
    )
    assert len(done) == 1 and done[0][0] == "worker" and str(done[0][1]) == a["workflow_run_id"]


def test_live_code_run_is_refused_not_silently_downgraded(env: Env) -> None:
    vm = setup_vm(env)
    r = env.client.post(
        f"/api/v1/managed-vms/{vm['id']}/assessments",
        json={"run_repo_code_on_live_vm": True, "typed_confirmation": "blue abcdef"},
    )
    assert r.status_code == 409 and r.json()["code"] == "live-code-run-unavailable"
    assert env.auth.sql("SELECT count(*) FROM workflow_run WHERE kind = 'readiness'")[0][0] == 0
    assert (
        env.client.post(
            f"/api/v1/managed-vms/{vm['id']}/assessments", json={"surprise": 1}
        ).status_code
        == 422
    )
    # and a run asking for it directly is rejected by the worker's admission
    with env.api.begin() as c:
        from ovlm.workflow.requests import request_run

        rid = request_run(c, kind="readiness", strategy="readiness", strategy_version="1",
                          subject={"managed_vm_id": vm["id"], "run_repo_code_on_live_vm": True})  # fmt: skip
    run_worker(env)
    assert env.auth.sql("SELECT state FROM workflow_run WHERE id = :r", r=rid)[0][0] == "rejected"


def test_unknown_vm_and_assessment_are_404(env: Env) -> None:
    assert (
        env.client.post(f"/api/v1/managed-vms/{uuid4()}/assessments").json()["code"]
        == "managed-vm-not-found"
    )
    assert env.client.get(f"/api/v1/managed-vms/{uuid4()}/assessments").status_code == 404
    assert env.client.get(f"/api/v1/assessments/{uuid4()}").json()["code"] == "assessment-not-found"
    assert env.client.get("/api/v1/managed-vms/not-a-uuid/assessments").status_code == 422


def test_catalogue_endpoint(env: Env) -> None:
    items = env.client.get("/api/v1/checks").json()["items"]
    assert [i["key"] for i in items] == [c.key for c in CHECKS] and all(
        i["version"] >= 1 for i in items
    )
    assert {i["category"] for i in items} == {c.category.value for c in CHECKS}


def test_roles_viewer_reads_operator_requests_and_anonymous_is_refused(env: Env) -> None:
    vm = setup_vm(env)
    a = assess(env, vm)
    env.as_("viewer")
    assert env.client.get(f"/api/v1/assessments/{a['id']}").status_code == 200
    assert env.client.get("/api/v1/checks").status_code == 200
    assert env.client.get(f"/api/v1/managed-vms/{vm['id']}/assessments").status_code == 200
    assert env.client.post(f"/api/v1/managed-vms/{vm['id']}/assessments").status_code == 403
    env.as_("admin")  # admin does not inherit operator (security-model.md 3.1)
    assert env.client.post(f"/api/v1/managed-vms/{vm['id']}/assessments").status_code == 403
    anon = env.auth.client()
    for method, url in (("GET", "/api/v1/checks"), ("GET", f"/api/v1/assessments/{a['id']}"),
                        ("GET", f"/api/v1/managed-vms/{vm['id']}/assessments")):  # fmt: skip
        assert anon.request(method, url).status_code == 401
    assert anon.post(f"/api/v1/managed-vms/{vm['id']}/assessments").status_code in (401, 403)
    assert (
        env.auth.sql("SELECT count(*) FROM workflow_run WHERE kind='readiness'")[0][0] == 1
    )  # only the operator's


def test_project_scope_is_enforced(env: Env) -> None:
    vm = setup_vm(env)
    a = assess(env, vm)
    elsewhere = f"project:{uuid4()}"
    client, _ = env.auth.user_client("other_op", [("operator", elsewhere), ("viewer", elsewhere)])
    other = Session(client, UUID(client.get("/api/v1/session").json()["user_id"]))
    assert other.get(f"/api/v1/managed-vms/{vm['id']}/assessments").status_code == 404
    assert other.get(f"/api/v1/assessments/{a['id']}").status_code == 404
    denied = other.post(f"/api/v1/managed-vms/{vm['id']}/assessments")
    assert denied.status_code == 404  # an operator of another project cannot even see the VM
    denied_rows = env.auth.sql(
        "SELECT actor_id FROM audit_event WHERE action = 'readiness.request' AND result = 'denied'"
    )
    assert [r[0] for r in denied_rows] == [other.user_id]
    assert (
        env.auth.sql("SELECT count(*) FROM workflow_run WHERE kind='readiness'")[0][0] == 1
    )  # only the operator's own
    mine = f"project:{env.project}"
    client2, _ = env.auth.user_client("proj_op", [("operator", mine)])
    inside = Session(client2, UUID(client2.get("/api/v1/session").json()["user_id"]))
    assert inside.post(f"/api/v1/managed-vms/{vm['id']}/assessments").status_code == 202
    assert inside.get(f"/api/v1/assessments/{a['id']}").status_code == 200


def test_table_definitions_match_the_migration(env: Env) -> None:
    from ovlm.readiness.tables import metadata

    for name, table in metadata.tables.items():
        cols = {
            r[0]
            for r in env.auth.sql(
                "SELECT column_name FROM information_schema.columns WHERE table_name = :t", t=name
            )
        }
        assert cols == {c.name for c in table.columns}, name
