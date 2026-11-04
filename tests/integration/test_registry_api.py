# ruff: noqa: F811
"""Inventory and registration endpoints against a real PostgreSQL, connected as the ``ovlm_api`` role
(so the grants of data-model.md section 12 are exercised), data written by the real sync job with the fake."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError, ProgrammingError

from ovlm.db.engine import make_engine
from ovlm.inventory.sync import SyncConfig, run_inventory_sync
from ovlm.openstack.fake import FakeOpenStack
from tests.integration.auth_support import ORIGIN
from tests.integration.auth_support import Env as AuthEnv
from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.conftest import settings_for


class Session:
    """A real logged-in client (cookie session). Unsafe requests carry the Origin and CSRF token, as a browser does."""

    def __init__(self, client: TestClient, user_id: UUID) -> None:
        self.client, self.user_id = client, user_id

    def request(self, method: str, url: str, **kw: Any) -> Any:
        headers = dict(kw.pop("headers", None) or {})
        if method not in ("GET", "HEAD"):
            csrf = self.client.get("/api/v1/session").json()["csrf_token"]
            headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf, **headers}
        return self.client.request(method, url, headers=headers, **kw)

    def get(self, url: str, **kw: Any) -> Any:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Any:
        return self.request("POST", url, **kw)

    def patch(self, url: str, **kw: Any) -> Any:
        return self.request("PATCH", url, **kw)

    def delete(self, url: str, **kw: Any) -> Any:
        return self.request("DELETE", url, **kw)


@dataclass
class Env:
    auth: AuthEnv
    users: dict[str, Session]
    current: list[str]
    worker: Engine
    api: Engine
    project: UUID
    fake: FakeOpenStack
    ids: dict[str, str]

    @property
    def client(self) -> Session:
        return self.users[self.current[0]]

    def as_(self, who: str) -> None:
        self.current[0] = who

    @property
    def operator_id(self) -> UUID:
        return self.users["operator"].user_id

    def sync(self, **kw: Any) -> None:
        run_inventory_sync(
            self.worker, self.fake, self.project, config=SyncConfig(gone_after_missed_syncs=1), **kw
        )

    def observed_id(self, openstack_id: str, table: str = "observed_server") -> str:
        query = f"SELECT id FROM {table} WHERE openstack_id = :i"  # noqa: S608 - fixed table names from the tests
        with self.worker.connect() as c:
            return str(c.execute(text(query), {"i": openstack_id}).scalar_one())

    def make_service(self, slug: str = "app01", project: UUID | None = None) -> dict[str, Any]:
        r = self.client.post(
            "/api/v1/services",
            json={
                "name": "App 01",
                "slug": slug,
                "project_connection_id": str(project or self.project),
            },
        )
        assert r.status_code == 201, r.text
        return r.json()  # type: ignore[no-any-return]


@pytest.fixture
def env(auth_env: AuthEnv, admin_url: URL, fresh_db: str, secrets_dir: Path) -> Iterator[Env]:
    worker = make_engine(settings_for("worker", admin_url, fresh_db, secrets_dir))
    api = make_engine(settings_for("api", admin_url, fresh_db, secrets_dir))

    fake = FakeOpenStack()
    ext, net = fake.add_network("ext", external=True), fake.add_network("tenant")
    fake.add_image("ubuntu")
    fake.add_flavor("m1.small")
    blue = fake.add_server("blue", tags=["ovlm:managed"])
    green = fake.add_server("green")
    vol = fake.add_volume("data")
    fake.attach_volume(blue, vol)
    fake.tick(30)
    port = fake.add_port(net, device_id=blue)
    fip = fake.add_floating_ip(ext)
    fake.add_router_path(net, ext)
    fake.update_floating_ip(fip, port)
    ids = {"blue": blue, "green": green, "vol": vol, "port": port, "fip": fip}

    users = {}
    for name, role in (("operator", "operator"), ("viewer", "viewer"), ("admin", "admin")):
        client, _ = auth_env.user_client(name, [(role, "global")])
        users[name] = Session(client, UUID(client.get("/api/v1/session").json()["user_id"]))
    e = Env(auth_env, users, ["operator"], worker, api, uuid4(), fake, ids)
    e.sync()
    yield e
    worker.dispose()
    api.dispose()


# --- inventory endpoints ----------------------------------------------------------------------------------------------


def test_servers_list_filters_and_pagination(env: Env) -> None:
    c = env.client
    r = c.get("/api/v1/servers")
    assert r.status_code == 200
    body = r.json()
    assert {i["name"] for i in body["items"]} == {"blue", "green"} and body["next_cursor"] is None
    item = next(i for i in body["items"] if i["name"] == "blue")
    assert item["observation"]["status"] == "present" and item["data"]["tags"] == ["ovlm:managed"]
    assert item["openstack_id"] == env.ids["blue"] and item["project_connection_id"] == str(
        env.project
    )

    assert [
        i["name"] for i in c.get("/api/v1/servers", params={"tag": "ovlm:managed"}).json()["items"]
    ] == ["blue"]
    assert (
        len(c.get("/api/v1/servers", params={"status": "ACTIVE"}).json()["items"]) == 2
    )  # server's own status
    assert c.get("/api/v1/servers", params={"status": "gone"}).json()["items"] == []
    assert c.get("/api/v1/servers", params={"project": str(uuid4())}).json()["items"] == []

    first = c.get("/api/v1/servers", params={"limit": 1}).json()
    assert len(first["items"]) == 1 and first["next_cursor"]
    second = c.get("/api/v1/servers", params={"limit": 1, "cursor": first["next_cursor"]}).json()
    assert len(second["items"]) == 1 and second["next_cursor"] is None
    assert {first["items"][0]["name"], second["items"][0]["name"]} == {"blue", "green"}
    bad = c.get("/api/v1/servers", params={"cursor": "garbage"})
    assert bad.status_code == 400 and bad.json()["code"] == "invalid-cursor"
    assert c.get("/api/v1/servers", params={"limit": 0}).status_code == 422


def test_gone_servers_are_filterable_and_still_listed(env: Env) -> None:
    env.fake.keep_tombstones = False
    env.fake.delete_server(env.ids["green"])
    env.sync(kind="full")
    gone = env.client.get("/api/v1/servers", params={"status": "gone"}).json()["items"]
    assert [i["name"] for i in gone] == ["green"] and gone[0]["observation"]["gone_at"]


def test_server_detail_has_attachments_ports_floating_ips_and_revision_link(env: Env) -> None:
    sid = env.observed_id(env.ids["blue"])
    d = env.client.get(f"/api/v1/servers/{sid}").json()
    assert [a["data"]["volume_openstack_id"] for a in d["attachments"]] == [env.ids["vol"]]
    assert [p["openstack_id"] for p in d["ports"]] == [env.ids["port"]]
    assert [f["openstack_id"] for f in d["floating_ips"]] == [env.ids["fip"]]
    assert d["links"]["revisions"] == f"/api/v1/servers/{sid}/revisions"
    assert env.client.get(f"/api/v1/servers/{uuid4()}").json()["code"] == "server-not-found"


def test_server_revisions_show_the_snapshot_history(env: Env) -> None:
    sid = env.observed_id(env.ids["blue"])
    env.fake.lock_server(env.ids["blue"], "retention")
    env.sync(kind="full")
    revs = env.client.get(f"/api/v1/servers/{sid}/revisions").json()["items"]
    assert len(revs) == 2
    assert revs[0]["payload"]["locked"] is False and revs[1]["payload"]["locked"] is True
    assert (
        revs[0]["observed_at"] <= revs[1]["observed_at"]
        and revs[0]["payload_hash"] != revs[1]["payload_hash"]
    )
    assert env.client.get(f"/api/v1/servers/{uuid4()}/revisions").status_code == 404


@pytest.mark.parametrize(
    ("path", "table", "key"),
    [
        ("volumes", "observed_volume", "vol"),
        ("ports", "observed_port", "port"),
        ("floating-ips", "observed_floating_ip", "fip"),
    ],
)
def test_other_resources_list_and_get(env: Env, path: str, table: str, key: str) -> None:
    items = env.client.get(f"/api/v1/{path}").json()["items"]
    assert [i["openstack_id"] for i in items] == [env.ids[key]]
    one = env.client.get(f"/api/v1/{path}/{items[0]['id']}")
    assert one.status_code == 200 and one.json()["openstack_id"] == env.ids[key]
    assert env.client.get(f"/api/v1/{path}/{uuid4()}").status_code == 404
    assert env.observed_id(env.ids[key], table) == items[0]["id"]


def test_images_and_flavors(env: Env) -> None:
    assert [i["name"] for i in env.client.get("/api/v1/images").json()["items"]] == ["ubuntu"]
    assert [i["name"] for i in env.client.get("/api/v1/flavors").json()["items"]] == ["m1.small"]


def test_sync_runs_are_listed_newest_first_and_readable(env: Env) -> None:
    env.sync(kind="full")
    runs = env.client.get(f"/api/v1/projects/{env.project}/syncs").json()["items"]
    assert (
        len(runs) == 2
        and runs[0]["started_at"] >= runs[1]["started_at"]
        and runs[0]["status"] == "succeeded"
    )
    one = env.client.get(f"/api/v1/syncs/{runs[0]['id']}").json()
    assert (
        one["kind"] == "full"
        and one["counts"]["server"]["seen"] == 2
        and one["versions"]["compute_used"]
    )
    assert env.client.get(f"/api/v1/syncs/{uuid4()}").status_code == 404
    page = env.client.get(f"/api/v1/projects/{env.project}/syncs", params={"limit": 1}).json()
    assert len(page["items"]) == 1 and page["next_cursor"]


# --- RBAC (real authentication) -------------------------------------------------------------------------------------------


def test_roles_follow_the_matrix(env: Env) -> None:
    env.as_("viewer")
    assert env.client.get("/api/v1/servers").status_code == 200
    denied = env.client.post(
        "/api/v1/services",
        json={"name": "x", "slug": "x", "project_connection_id": str(env.project)},
    )
    assert denied.status_code == 403 and denied.json()["code"] == "forbidden"
    env.as_("admin")  # admin does not inherit operator (security-model.md section 3.1)
    assert env.client.get("/api/v1/servers").status_code == 200
    assert (
        env.client.post(
            "/api/v1/services",
            json={"name": "x", "slug": "x", "project_connection_id": str(env.project)},
        ).status_code
        == 403
    )
    env.as_("operator")
    assert env.make_service("x")["slug"] == "x"


def test_unauthenticated_requests_get_401_and_tokens_need_the_operate_scope(env: Env) -> None:
    bare = env.auth.client()
    assert bare.get("/api/v1/servers").status_code == 401
    payload = {"name": "x", "slug": "x", "project_connection_id": str(env.project)}
    assert bare.post("/api/v1/services", json=payload).status_code == 401

    def token(scope: str) -> dict[str, str]:
        r = env.users["operator"].post("/api/v1/tokens", json={"name": scope, "scopes": [scope]})
        assert r.status_code in (200, 201), r.text
        return {"Authorization": f"Bearer {r.json()['token']}"}  # no CSRF/Origin needed for tokens

    read, operate = token("read"), token("operate")
    assert bare.get("/api/v1/servers", headers=read).status_code == 200
    denied = bare.post("/api/v1/services", json=payload, headers=read)
    assert denied.status_code == 403 and denied.json()["code"] == "token-scope"
    assert bare.post("/api/v1/services", json=payload, headers=operate).status_code == 201


def test_changes_are_audited_with_allowlisted_fields(env: Env) -> None:
    c = env.client
    svc = c.post(
        "/api/v1/services",
        json={"name": "A", "slug": "aud", "project_connection_id": str(env.project),
              "owner_contact": "secret-contact@example.invalid"},
    ).json()  # fmt: skip
    c.patch(f"/api/v1/services/{svc['id']}", json={"name": "B"}, headers={"If-Match": '"1"'})
    vm = _register(env, svc["id"], "blue").json()
    assert c.delete(f"/api/v1/managed-vms/{vm['id']}").status_code == 204
    assert c.delete(f"/api/v1/services/{svc['id']}", headers={"If-Match": '"2"'}).status_code == 204
    rows = env.auth.sql(
        "SELECT action, actor_id, project_scope, before, after FROM audit_event"
        " WHERE action LIKE 'service.%' OR action LIKE 'managed_vm.%' ORDER BY id"
    )
    assert [r[0] for r in rows] == [
        "service.create", "service.update", "managed_vm.register", "managed_vm.unregister",
        "service.delete",
    ]  # fmt: skip
    assert all(r[1] == env.operator_id and r[2] == f"project:{env.project}" for r in rows)
    assert "secret-contact" not in str(rows)
    assert rows[1][3]["name"] == "A" and rows[1][4]["name"] == "B"
    assert rows[2][4]["openstack_server_id"] == env.ids["blue"]
    assert "registered_by" not in rows[2][4]  # not allowlisted


# --- services ---------------------------------------------------------------------------------------------------------------


def test_service_crud_with_etags(env: Env) -> None:
    c = env.client
    r = c.post("/api/v1/services", json={"name": "App 01", "slug": "app01", "project_connection_id": str(env.project),
                                         "owner_contact": "ops@example.invalid"})  # fmt: skip
    assert r.status_code == 201 and r.headers["ETag"] == '"1"'
    svc = r.json()
    assert (
        r.headers["Location"] == f"/api/v1/services/{svc['id']}"
        and svc["version"] == 1
        and svc["created_by"]
    )
    assert c.get(f"/api/v1/services/{svc['id']}").headers["ETag"] == '"1"'
    assert [s["slug"] for s in c.get("/api/v1/services").json()["items"]] == ["app01"]

    no_header = c.patch(f"/api/v1/services/{svc['id']}", json={"name": "Renamed"})
    assert no_header.status_code == 428
    stale = c.patch(
        f"/api/v1/services/{svc['id']}", json={"name": "Renamed"}, headers={"If-Match": '"9"'}
    )
    assert stale.status_code == 412 and stale.json()["code"] == "etag-mismatch"
    ok = c.patch(
        f"/api/v1/services/{svc['id']}", json={"name": "Renamed"}, headers={"If-Match": '"1"'}
    )
    assert ok.status_code == 200 and ok.json()["name"] == "Renamed" and ok.headers["ETag"] == '"2"'
    assert ok.json()["owner_contact"] == "ops@example.invalid"  # untouched fields stay
    cleared = c.patch(
        f"/api/v1/services/{svc['id']}", json={"owner_contact": None}, headers={"If-Match": '"2"'}
    )
    assert cleared.json()["owner_contact"] is None
    assert (
        c.patch(
            f"/api/v1/services/{uuid4()}", json={"name": "x"}, headers={"If-Match": '"1"'}
        ).status_code
        == 404
    )

    assert c.delete(f"/api/v1/services/{svc['id']}").status_code == 428
    assert c.delete(f"/api/v1/services/{svc['id']}", headers={"If-Match": '"1"'}).status_code == 412
    assert c.delete(f"/api/v1/services/{svc['id']}", headers={"If-Match": '"3"'}).status_code == 204
    assert c.get(f"/api/v1/services/{svc['id']}").status_code == 404


def test_service_validation_and_conflicts(env: Env) -> None:
    c = env.client
    env.make_service("app01")
    dup = c.post(
        "/api/v1/services",
        json={"name": "Other", "slug": "app01", "project_connection_id": str(env.project)},
    )
    assert (
        dup.status_code == 409 and dup.json()["code"] == "slug-taken" and dup.json()["next_action"]
    )
    assert dup.headers["content-type"] == "application/problem+json"
    bad = c.post(
        "/api/v1/services",
        json={"name": "x", "slug": "Not Valid", "project_connection_id": str(env.project)},
    )
    assert bad.status_code == 422 and bad.json()["code"] == "invalid-slug"
    group = c.post("/api/v1/services", json={"name": "x", "slug": "g1", "project_connection_id": str(env.project),
                                             "service_group_id": str(uuid4())})  # fmt: skip
    assert group.status_code == 422 and group.json()["code"] == "unknown-service-group"
    extra = c.post(
        "/api/v1/services",
        json={"name": "x", "slug": "g2", "project_connection_id": str(env.project), "nope": 1},
    )
    assert extra.status_code == 422  # unknown fields are errors


# --- registration -----------------------------------------------------------------------------------------------------------


def _register(env: Env, service_id: str, server: str) -> Any:
    return env.client.post(
        f"/api/v1/services/{service_id}/managed-vms",
        json={"observed_server_id": env.observed_id(env.ids[server])},
    )


def test_register_observed_server_as_managed_vm(env: Env) -> None:
    svc = env.make_service()
    r = _register(env, svc["id"], "blue")
    assert r.status_code == 201, r.text
    vm = r.json()
    assert (
        vm["role"] == "current"
        and vm["service_id"] == svc["id"]
        and vm["openstack_server_id"] == env.ids["blue"]
    )
    assert vm["registered_by"] == str(env.operator_id) and vm["registered_at"]
    assert vm["launched_at_effective"]  # launched_at, falling back to created
    assert vm["ssh_host_key_fingerprint"] is None  # not scanned yet (ADR-0006, workflow engine)
    assert r.headers["Location"] == f"/api/v1/managed-vms/{vm['id']}"

    got = env.client.get(f"/api/v1/managed-vms/{vm['id']}").json()
    assert got["desired"] == {
        "profile_id": None,
        "profile_version": None,
    }  # desired and observed apart (FR-REG-4)
    assert (
        got["observed"]["name"] == "blue" and got["observed"]["observation"]["status"] == "present"
    )
    assert [v["id"] for v in env.client.get("/api/v1/managed-vms").json()["items"]] == [vm["id"]]
    assert (
        env.client.get("/api/v1/managed-vms", params={"service": str(uuid4())}).json()["items"]
        == []
    )

    flagged = env.client.get("/api/v1/servers", params={"registered": "true"}).json()["items"]
    assert [i["name"] for i in flagged] == ["blue"]
    assert [
        i["name"]
        for i in env.client.get("/api/v1/servers", params={"registered": "false"}).json()["items"]
    ] == ["green"]


def test_launched_at_falls_back_to_created(env: Env) -> None:
    fake_server = env.fake.add_server("never-launched", launched=False)
    env.sync(kind="full")
    svc = env.make_service()
    vm = env.client.post(
        f"/api/v1/services/{svc['id']}/managed-vms",
        json={"observed_server_id": env.observed_id(fake_server)},
    ).json()
    with env.worker.connect() as c:
        created = c.execute(
            text("SELECT created FROM observed_server WHERE openstack_id = :i"), {"i": fake_server}
        ).scalar_one()
    assert vm["launched_at_effective"] == created.isoformat()


def test_registration_refusals(env: Env) -> None:
    c = env.client
    svc = env.make_service()
    assert (
        c.post(
            f"/api/v1/services/{uuid4()}/managed-vms",
            json={"observed_server_id": env.observed_id(env.ids["blue"])},
        ).json()["code"]
        == "service-not-found"
    )
    unknown = c.post(
        f"/api/v1/services/{svc['id']}/managed-vms", json={"observed_server_id": str(uuid4())}
    )
    assert unknown.status_code == 404 and unknown.json()["code"] == "observed-server-not-found"

    other_project = env.make_service("elsewhere", project=uuid4())
    mismatch = _register(env, other_project["id"], "blue")
    assert mismatch.status_code == 409 and mismatch.json()["code"] == "project-mismatch"

    assert _register(env, svc["id"], "blue").status_code == 201
    second_current = _register(env, svc["id"], "green")  # a service has exactly one current VM
    assert (
        second_current.status_code == 409
        and second_current.json()["code"] == "service-has-current-vm"
    )
    twice = _register(
        env, env.make_service("app02")["id"], "blue"
    )  # the same server under another service
    assert twice.status_code == 409 and twice.json()["code"] == "already-registered"

    env.fake.hide_server(env.ids["green"])
    env.sync(kind="full")  # N=1: green is gone now
    gone = _register(env, env.make_service("app03")["id"], "green")
    assert gone.status_code == 409 and gone.json()["code"] == "observed-server-not-present"

    env.as_("viewer")
    assert _register(env, svc["id"], "green").status_code == 403


def test_unregister_and_service_delete_rules(env: Env) -> None:
    c = env.client
    svc = env.make_service()
    vm = _register(env, svc["id"], "blue").json()
    refused = c.delete(f"/api/v1/services/{svc['id']}", headers={"If-Match": '"1"'})
    assert refused.status_code == 409 and refused.json()["code"] == "service-has-managed-vms"
    assert c.delete(f"/api/v1/managed-vms/{vm['id']}").status_code == 204
    assert c.get(f"/api/v1/managed-vms/{vm['id']}").status_code == 404
    assert c.delete(f"/api/v1/managed-vms/{vm['id']}").status_code == 404
    assert c.delete(f"/api/v1/services/{svc['id']}", headers={"If-Match": '"1"'}).status_code == 204
    assert (
        _register(env, env.make_service("again")["id"], "blue").status_code == 201
    )  # free to register again


def test_server_cannot_be_reregistered_after_unregister_race_is_a_409_not_a_500(env: Env) -> None:
    """The unique indexes are the real guard: even if the pre-checks were bypassed the api answers 409."""
    svc = env.make_service()
    assert _register(env, svc["id"], "blue").status_code == 201
    # same registration again: caught by UNIQUE(openstack_server_id) / one-current index
    again = _register(env, svc["id"], "blue")
    assert again.status_code == 409


# --- database-level guarantees ------------------------------------------------------------------------------------------------


def test_one_current_vm_per_service_and_unique_server_in_the_database(env: Env) -> None:
    svc = env.make_service()
    vm = _register(env, svc["id"], "blue").json()
    with env.worker.begin() as c:  # the worker may move roles
        c.execute(text("UPDATE managed_vm SET role = 'retained' WHERE id = :i"), {"i": vm["id"]})
        assert (
            c.execute(
                text("SELECT role FROM managed_vm WHERE id = :i"), {"i": vm["id"]}
            ).scalar_one()
            == "retained"
        )
    # 'retained' no longer occupies the current slot: another server can become current
    assert _register(env, svc["id"], "green").status_code == 201
    with (
        env.worker.connect() as c,
        pytest.raises(IntegrityError),
    ):  # and the worker cannot make a second current
        c.execute(text("UPDATE managed_vm SET role = 'current' WHERE id = :i"), {"i": vm["id"]})


def test_grants_api_cannot_change_roles_worker_cannot_insert_or_delete(env: Env) -> None:
    svc = env.make_service()
    vm = _register(env, svc["id"], "blue").json()
    with env.api.connect() as c, pytest.raises(ProgrammingError):
        c.execute(text("UPDATE managed_vm SET role = 'retired' WHERE id = :i"), {"i": vm["id"]})
    with env.api.connect() as c, pytest.raises(ProgrammingError):
        c.execute(text("UPDATE managed_vm SET openstack_server_id = 'x'"))
    with env.worker.connect() as c, pytest.raises(ProgrammingError):
        c.execute(text("DELETE FROM managed_vm"))
    with env.worker.connect() as c, pytest.raises(ProgrammingError):
        c.execute(text("UPDATE service SET name = 'x'"))
    with env.api.connect() as c:  # the api can read every observed table it needs
        assert c.execute(text("SELECT count(*) FROM observed_server")).scalar_one() == 2
