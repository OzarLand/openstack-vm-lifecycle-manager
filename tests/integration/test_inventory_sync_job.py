# ruff: noqa: F811
"""The ``inventory_sync`` workflow end to end against PostgreSQL: the api queues it (``POST /projects/{id}/syncs``),
the worker opens the project's **read** credential from the encrypted store (real key ring, Keystone validation
replaced by a double), the fake cloud stands in for the guarded SDK read client, and the sync files the inventory
under the **real** project connection id. Also: every credential state, the project check, RBAC and token scopes,
409 on a duplicate, the periodic job, and a canary secret hunted in logs, audit rows and sync records."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from ovlm.connections.credentials import AppCredential, CredentialStore
from ovlm.inventory import job
from ovlm.inventory.requests import KIND, SCHEDULE_KIND
from ovlm.inventory.sync import SyncConfig
from ovlm.openstack.errors import OpenStackError
from ovlm.openstack.fake import FakeOpenStack
from ovlm.secrets.keyring import Keyring, generate_private_pem
from ovlm.workflow.engine import WorkflowEngine
from ovlm.workflow.registry import Registry
from tests.integration.auth_support import Env, env  # noqa: F401
from tests.integration.test_auth_authz import bearer, mint_token
from tests.integration.test_credential_store import APP_R, CANARY, PROJECT, Store, _hunt
from tests.integration.workflow.conftest import TEST_CONFIG

OTHER_PROJECT = "fedcba9876543210fedcba9876543210"


class Cloud:
    """The worker's read access: the real credential store, and the fake cloud instead of the SDK client."""

    def __init__(self, store: CredentialStore, project_id: str = PROJECT) -> None:
        self.fake = FakeOpenStack(project_id=project_id, role="reader")
        self.fake.add_network("tenant")
        self.fake.add_image("ubuntu")
        self.fake.add_flavor("m1.small")
        self.blue = self.fake.add_server("blue")
        self.seen: list[AppCredential] = []
        self.access = job.StoreReadAccess(store, connect=self.connect)

    def connect(self, cred: AppCredential, ca: Path | None, *, process_role: str) -> FakeOpenStack:
        assert process_role == "worker" and cred.kind == "os_read"
        self.seen.append(cred)
        return self.fake


@pytest.fixture
def st(env: Env, tmp_path: Path) -> Iterator[Store]:
    s = Store(env, tmp_path)
    yield s
    s.worker_engine.dispose()


def _read_ready(st: Store, name: str = "lab", project: str = PROJECT, app: str = APP_R) -> str:
    pc = st.connection(name, project)
    st.facts_for(app, "reader", project=project)
    assert st.upload(pc, "os_read", CANARY, app, name=name).status_code == 202
    assert st.validator.run_once() == {"active": 1}
    return pc


def _engine(st: Store, cloud: Cloud) -> WorkflowEngine:
    defs = [
        job.InventorySyncDefinition(st.worker_engine, cloud.access, SyncConfig()),
        job.InventorySyncScheduleDefinition(st.worker_engine),
    ]
    return WorkflowEngine(st.worker_engine, Registry(defs), TEST_CONFIG)


def _drive(st: Store, cloud: Cloud) -> None:
    eng = _engine(st, cloud)
    for _ in range(30):
        eng.run_once()
        open_runs = st.env.sql(
            "SELECT count(*) FROM workflow_run WHERE kind IN (:a, :b) AND finished_at IS NULL",
            a=KIND, b=SCHEDULE_KIND,
        )[0][0]  # fmt: skip
        if open_runs == 0:
            return
    raise AssertionError("sync runs did not finish")


def _operator(st: Store, name: str = "operator1", scope: str = "global") -> TestClient:
    c, _ = st.env.user_client(name, [("operator", scope)])
    return c


def _post_sync(st: Store, c: TestClient, pc: str, **headers: str) -> Any:
    h = headers or st.env.headers(c)
    return c.post(f"/api/v1/projects/{pc}/syncs", headers=h)


def _runs(st: Store, pc: str) -> list[Any]:
    """The project's sync runs, oldest first, with the reason a run ended (as ``GET .../syncs`` shows it)."""
    from ovlm.inventory.requests import recent_runs

    with st.worker_engine.connect() as c:
        runs = list(reversed(recent_runs(c, pc, limit=50)))
    return [type("Run", (), {**r, "subject": {"origin": r["origin"]}})() for r in runs]


# --- the sync under the real connection id ------------------------------------------------------------------------


def test_requested_sync_files_the_inventory_under_the_real_connection_id(st: Store) -> None:
    pc = _read_ready(st)
    cloud = Cloud(st.store)
    op = _operator(st)
    r = _post_sync(st, op, pc)
    assert r.status_code == 202, r.text
    run = r.json()["run"]
    assert run["state"] == "requested" and r.headers["Location"] == f"/api/v1/projects/{pc}/syncs"
    _drive(st, cloud)

    assert [c.secret for c in cloud.seen] == [
        CANARY
    ]  # the stored read credential, decrypted in memory
    assert set(cloud.fake.calls) <= {
        "list_servers",
        "list_volumes",
        "list_ports",
        "list_floating_ips",
        "list_networks",
        "list_images",
        "list_flavors",
    }  # fmt: skip  (a reader credential: any write would have raised)
    [server] = st.env.sql(
        "SELECT project_connection_id::text AS pc, openstack_id FROM observed_server"
    )
    assert (server.pc, server.openstack_id) == (pc, cloud.blue)
    [wr] = _runs(st, pc)
    assert (wr.id, wr.state) == (run["id"], "completed")

    listing = op.get(f"/api/v1/projects/{pc}/syncs").json()
    [item] = listing["items"]
    assert item["status"] == "succeeded" and item["kind"] == "full" and item["error"] is None
    assert item["workflow_run_id"] == run["id"] and item["counts"]["server"]["created"] == 1
    assert listing["runs"][0]["id"] == run["id"] and listing["runs"][0]["state"] == "completed"
    assert listing["runs"][0]["origin"] == "api"

    # a second request is incremental (inventory/sync.py decides), still under the same connection
    cloud.fake.now = datetime.now(
        UTC
    )  # the fake's clock follows the wall clock the delta is computed from
    cloud.fake.add_server("green")
    assert _post_sync(st, op, pc).status_code == 202
    _drive(st, cloud)
    newest = op.get(f"/api/v1/projects/{pc}/syncs").json()["items"][0]
    assert newest["status"] == "succeeded" and newest["kind"] == "servers_delta"
    assert (
        len(
            st.env.sql(
                "SELECT 1 FROM observed_server WHERE project_connection_id = CAST(:p AS uuid)", p=pc
            )
        )
        == 2
    )

    audit = st.env.sql(
        "SELECT target_id, project_scope FROM audit_event WHERE action = 'inventory.sync.request'"
    )
    assert [(a.target_id, a.project_scope) for a in audit][0] == (run["id"], f"project:{pc}")
    _hunt(st.env, CANARY, extra=(str(listing), str(st.env.sql("SELECT * FROM sync_run")),
                                 str(st.env.sql("SELECT * FROM workflow_run")),
                                 str(st.env.sql("SELECT * FROM workflow_step"))))  # fmt: skip


def test_a_token_scoped_to_another_project_is_refused_and_nothing_is_synced(st: Store) -> None:
    pc = _read_ready(st)
    cloud = Cloud(st.store, project_id=OTHER_PROJECT)  # Keystone scoped the token elsewhere
    assert _post_sync(st, _operator(st), pc).status_code == 202
    _drive(st, cloud)
    [wr] = _runs(st, pc)
    assert (
        wr.state == "failed"
        and "ProjectMismatch" in wr.end_reason
        and OTHER_PROJECT in wr.end_reason
    )
    [row] = st.env.sql("SELECT status, error FROM sync_run")
    assert row.status == "failed" and row.error["type"] == "ProjectMismatch"
    assert st.env.sql("SELECT count(*) FROM observed_server")[0][0] == 0
    assert cloud.fake.calls == []  # nothing listed


def _sync_once(st: Store, pc: str, cloud: Cloud) -> Any:
    with st.worker_engine.begin() as c:
        from ovlm.inventory.requests import request_sync

        request_sync(c, pc, requested_by=None, origin="test")
    _drive(st, cloud)
    return _runs(st, pc)[-1]


def test_no_read_credential_is_a_clear_failure(st: Store) -> None:
    pc = st.connection()
    run = _sync_once(st, pc, Cloud(st.store))
    assert run.state == "failed" and "no validated read application credential" in run.end_reason
    [row] = st.env.sql("SELECT status, error, kind FROM sync_run")
    assert (
        row.status == "failed"
        and row.error["type"] == "CredentialUnavailable"
        and row.kind == "full"
    )


def test_a_pending_credential_is_not_used(st: Store) -> None:
    pc = st.connection()
    st.facts_for(APP_R, "reader")
    assert st.upload(pc, "os_read", CANARY, APP_R).status_code == 202  # uploaded, not validated yet
    cloud = Cloud(st.store)
    run = _sync_once(st, pc, cloud)
    assert run.state == "failed" and "no validated read" in run.end_reason and cloud.seen == []


def test_a_credential_that_failed_validation_is_refused(st: Store) -> None:
    pc = _read_ready(st)
    st.env.sql(
        """UPDATE credential_ref SET validation_result = '{"ok": false, "reason": "Keystone refused"}'"""
    )
    cloud = Cloud(st.store)
    run = _sync_once(st, pc, cloud)
    assert (
        run.state == "failed"
        and "failed its last validation" in run.end_reason
        and cloud.seen == []
    )


def test_an_expired_credential_is_refused(st: Store) -> None:
    pc = _read_ready(st)
    st.env.sql("UPDATE credential_ref SET verified_expires_at = now() - interval '1 minute'")
    cloud = Cloud(st.store)
    run = _sync_once(st, pc, cloud)
    assert run.state == "failed" and "expired" in run.end_reason and cloud.seen == []


def test_a_credential_bound_to_another_endpoint_is_refused(st: Store) -> None:
    pc = _read_ready(st)
    st.env.sql("UPDATE cloud SET region = 'R2'")  # the endpoint changed after upload
    cloud = Cloud(st.store)
    run = _sync_once(st, pc, cloud)
    assert run.state == "failed" and "endpoint" in run.end_reason and cloud.seen == []


def test_a_secret_sealed_to_an_unknown_key_is_a_reason_not_a_crash(
    st: Store, tmp_path: Path
) -> None:
    pc = _read_ready(st)
    from cryptography.hazmat.primitives import serialization

    other = Keyring(serialization.load_pem_private_key(generate_private_pem(), password=None))  # type: ignore[arg-type]
    cloud = Cloud(CredentialStore(st.worker_engine, other, tmp_path / "ca2"))
    run = _sync_once(st, pc, cloud)
    assert (
        run.state == "failed"
        and "cannot be decrypted by this worker" in run.end_reason
        and cloud.seen == []
    )


def test_a_disabled_connection_is_rejected_at_admission(st: Store) -> None:
    pc = _read_ready(st)
    st.env.sql("UPDATE project_connection SET enabled = false")
    run = _sync_once(st, pc, Cloud(st.store))
    assert run.state == "rejected"
    assert _post_sync(st, _operator(st), pc).json()["code"] == "project-disabled"


def test_without_a_worker_key_every_sync_says_why(st: Store) -> None:
    pc = _read_ready(st)
    status, reason = job.sync_project(st.worker_engine, job.NoReadAccess(), pc, config=SyncConfig())
    assert status == "failed" and "kek.private_key_file" in (reason or "")


def test_the_secret_never_reaches_logs_or_records_even_when_the_cloud_echoes_it(st: Store) -> None:
    pc = _read_ready(st)
    cloud = Cloud(st.store)
    cloud.fake.fail("list_volumes", OpenStackError(f"upstream said: bad secret {CANARY}"))
    run = _sync_once(st, pc, cloud)
    assert run.state == "failed" and CANARY not in run.end_reason
    [row] = st.env.sql("SELECT error FROM sync_run")
    assert row.error["type"] == "OpenStackError" and CANARY not in row.error["message"]
    _hunt(st.env, CANARY, extra=(str(st.env.sql("SELECT * FROM sync_run")),
                                 str(st.env.sql("SELECT * FROM workflow_run")),
                                 str(st.env.sql("SELECT * FROM workflow_step"))))  # fmt: skip


# --- api: RBAC, scopes, 404, 409 ----------------------------------------------------------------------------------


def test_duplicate_request_is_409_while_one_is_queued(st: Store) -> None:
    pc = _read_ready(st)
    op = _operator(st)
    first = _post_sync(st, op, pc).json()["run"]
    again = _post_sync(st, op, pc)
    assert again.status_code == 409 and again.json()["code"] == "sync-already-pending"
    assert first["id"] in again.json()["detail"]
    assert len(_runs(st, pc)) == 1
    _drive(st, Cloud(st.store))
    assert _post_sync(st, op, pc).status_code == 202  # finished: a new one may be queued


def test_rbac_matrix_and_token_scopes(st: Store) -> None:
    pc = _read_ready(st)
    other = st.connection("other", OTHER_PROJECT)
    viewer, _ = st.env.user_client("viewer1", [("viewer", "global")])
    assert _post_sync(st, viewer, pc).status_code == 403
    approver, _ = st.env.user_client("approver1", [("approver", "global")])
    assert _post_sync(st, approver, pc).status_code == 403
    # admin may trigger a sync (security-model.md 3.1)
    assert _post_sync(st, st.admin, pc).status_code == 202
    assert _post_sync(st, st.admin, pc).status_code == 409

    scoped = _operator(st, "op-scoped", f"project:{other}")
    assert (
        _post_sync(st, scoped, pc).status_code == 404
    )  # invisible project: not found, not forbidden
    assert scoped.get(f"/api/v1/projects/{pc}/syncs").status_code == 404
    assert _post_sync(st, scoped, other).status_code == 202
    assert _post_sync(st, scoped, str(uuid4())).status_code == 404

    op = _operator(st, "op-tokens")
    anon = st.env.client()
    read_token = mint_token(st.env, op, "read")
    r = anon.post(f"/api/v1/projects/{other}/syncs", headers=bearer(read_token))
    assert r.status_code == 403  # a token without inventory:sync
    assert (
        anon.get(f"/api/v1/projects/{other}/syncs", headers=bearer(read_token)).status_code == 200
    )
    _drive(st, Cloud(st.store, project_id=OTHER_PROJECT))
    sync_token = mint_token(st.env, op, "inventory:sync")
    r = anon.post(f"/api/v1/projects/{other}/syncs", headers=bearer(sync_token))
    assert r.status_code == 202, r.text
    denied = st.env.sql("SELECT count(*) FROM audit_event WHERE result = 'denied'")[0][0]
    assert denied >= 2


# --- periodic -----------------------------------------------------------------------------------------------------


def test_periodic_job_queues_one_sync_per_eligible_connection_without_duplicates(st: Store) -> None:
    ok = _read_ready(st, "ok")
    st.connection("nocred", OTHER_PROJECT)  # no read credential: not eligible
    disabled = _read_ready(st, "off", "aa" * 16, app="d" * 32)
    st.env.sql(
        "UPDATE project_connection SET enabled = false WHERE id = CAST(:p AS uuid)", p=disabled
    )

    assert job.enqueue_periodic(st.worker_engine) == {"queued": 1, "already_pending": 0}
    assert job.enqueue_periodic(st.worker_engine) == {
        "queued": 0,
        "already_pending": 1,
    }  # still queued
    op = _operator(st)
    assert _post_sync(st, op, ok).status_code == 409  # the api sees the periodic one
    [run] = _runs(st, ok)
    assert run.subject["origin"] == "periodic"
    _drive(st, Cloud(st.store))
    assert _runs(st, ok)[0].state == "completed"

    # the scheduler creates the periodic run itself; its step queues the syncs
    eng = WorkflowEngine(
        st.worker_engine,
        Registry([job.InventorySyncDefinition(st.worker_engine, Cloud(st.store).access),
                  job.InventorySyncScheduleDefinition(st.worker_engine)]),
        TEST_CONFIG,
    )  # fmt: skip
    eng.registry.periodic.append(job.periodic_job(900))
    assert eng.run_scheduler() == 1
    assert eng.run_scheduler() == 0  # not due again within the interval
    _drive(st, Cloud(st.store))
    assert [r.state for r in _runs(st, ok)] == ["completed", "completed"]
    assert st.env.sql("SELECT count(*) FROM sync_run WHERE status = 'succeeded'")[0][0] == 2


def test_worker_registry_wires_the_sync_and_the_periodic_job(st: Store) -> None:
    from ovlm.worker.main import build_registry

    settings = st.env.settings.model_copy(update={"process_role": "worker"})
    reg = build_registry(settings, st.worker_engine)
    assert reg.resolve(KIND, KIND, "1") is not None and reg.resolve(
        "host_key_scan", "host_key_scan", "1"
    )
    assert [p.interval for p in reg.periodic if p.kind == SCHEDULE_KIND] == [900.0]
    off = settings.model_copy(
        update={"inventory": settings.inventory.model_copy(update={"sync_interval": 0})}
    )
    assert not [
        p for p in build_registry(off, st.worker_engine).periodic if p.kind == SCHEDULE_KIND
    ]
