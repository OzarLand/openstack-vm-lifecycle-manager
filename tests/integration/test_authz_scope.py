# ruff: noqa: F811
"""Project scoping on the inventory and registration endpoints (security-model.md 3.3; section 10 item 6).

Two projects, A (``env.project``) and B, both filled by the real sync job. Users bound to one project see only that
project's resources in lists, and get 404 (the same answer as for a missing id) for every resource of the other.
Changes are checked in the resource's own project: invisible -> 404, visible but not allowed -> 403.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from ovlm.inventory.sync import SyncConfig, run_inventory_sync
from ovlm.openstack.fake import FakeOpenStack
from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.test_registry_api import Env, Session, env  # noqa: F401


class Two:
    def __init__(self, env: Env) -> None:
        self.env = env
        self.a = env.project
        self.b = uuid4()
        fake = FakeOpenStack()
        fake._ids = 50_000  # distinct OpenStack ids from project A's fake
        net = fake.add_network("tenant-b")
        self.b_server = fake.add_server("b-server")
        self.b_volume = fake.add_volume("b-data")
        fake.add_port(net, device_id=self.b_server)
        run_inventory_sync(env.worker, fake, self.b, config=SyncConfig(gone_after_missed_syncs=1))
        env.as_("operator")  # global operator sets up one service per project
        self.svc_a = env.make_service("svc-a", self.a)
        self.svc_b = env.make_service("svc-b", self.b)
        r = env.client.post(
            f"/api/v1/services/{self.svc_b['id']}/managed-vms",
            json={"observed_server_id": self.oid("observed_server", self.b_server, self.b)},
        )
        assert r.status_code == 201, r.text
        self.vm_b = r.json()

    def oid(self, table: str, openstack_id: str, project: UUID) -> str:
        q = f"SELECT id FROM {table} WHERE openstack_id = :i AND project_connection_id = :p"  # noqa: S608
        with self.env.worker.connect() as c:
            return str(c.execute(text(q), {"i": openstack_id, "p": project}).scalar_one())

    def sync_id(self, project: UUID) -> str:
        with self.env.worker.connect() as c:
            return str(
                c.execute(
                    text("SELECT id FROM sync_run WHERE project_connection_id = :p LIMIT 1"),
                    {"p": project},
                ).scalar_one()
            )

    def user(self, name: str, roles: list[tuple[str, str]]) -> Session:
        client, _ = self.env.auth.user_client(name, roles)
        return Session(client, UUID(client.get("/api/v1/session").json()["user_id"]))


@pytest.fixture
def two(env: Env) -> Two:
    return Two(env)


def _ids(r: Any) -> set[str]:
    assert r.status_code == 200, r.text
    return {i["id"] for i in r.json()["items"]}


def _projects(r: Any) -> set[str]:
    assert r.status_code == 200, r.text
    return {i["project_connection_id"] for i in r.json()["items"]}


def test_lists_are_filtered_to_the_callers_projects(two: Two) -> None:
    va = two.user("v-a", [("viewer", f"project:{two.a}")])
    a = str(two.a)
    for path in ("/api/v1/servers", "/api/v1/volumes", "/api/v1/ports", "/api/v1/services"):
        assert _projects(va.get(path)) == {a}, path
    assert va.get("/api/v1/servers", params={"project": str(two.b)}).json()["items"] == []
    assert va.get("/api/v1/managed-vms").json()["items"] == []  # B's VM is invisible
    # a global viewer sees both projects
    gv = two.user("g-v", [("viewer", "global")])
    assert _projects(gv.get("/api/v1/servers")) == {a, str(two.b)}
    assert _ids(gv.get("/api/v1/managed-vms")) == {two.vm_b["id"]}
    # an unscoped user (bound to a project id that is no project connection) sees nothing
    nobody = two.user("nobody", [("viewer", "project:nothing-here")])
    assert nobody.get("/api/v1/servers").json()["items"] == []


def test_every_resource_of_another_project_is_404(two: Two) -> None:
    va = two.user("v-a", [("viewer", f"project:{two.a}")])
    b_server = two.oid("observed_server", two.b_server, two.b)
    paths = {
        f"/api/v1/servers/{b_server}": "server-not-found",
        f"/api/v1/servers/{b_server}/revisions": "server-not-found",
        f"/api/v1/volumes/{two.oid('observed_volume', two.b_volume, two.b)}": "volume-not-found",
        f"/api/v1/projects/{two.b}/syncs": "project-not-found",
        f"/api/v1/syncs/{two.sync_id(two.b)}": "sync-not-found",
        f"/api/v1/services/{two.svc_b['id']}": "service-not-found",
        f"/api/v1/managed-vms/{two.vm_b['id']}": "managed-vm-not-found",
    }
    for path, code in paths.items():
        r = va.get(path)
        assert r.status_code == 404 and r.json()["code"] == code, (path, r.status_code, r.text)
        missing = va.get(path.replace(path.split("/")[4], str(uuid4()), 1))
        assert missing.status_code == 404 and missing.json()["code"] == code  # indistinguishable
    # and the same resources of the caller's own project are readable
    a_sync = two.sync_id(two.a)
    assert va.get(f"/api/v1/syncs/{a_sync}").status_code == 200
    assert va.get(f"/api/v1/projects/{two.a}/syncs").status_code == 200
    assert va.get(f"/api/v1/services/{two.svc_a['id']}").status_code == 200


def test_changes_are_checked_in_the_resources_project(two: Two) -> None:
    mix = two.user("mix", [("viewer", f"project:{two.a}"), ("operator", f"project:{two.b}")])
    # visible but only as viewer: 403, audited
    r = mix.patch(
        f"/api/v1/services/{two.svc_a['id']}", json={"name": "x"}, headers={"If-Match": '"1"'}
    )
    assert r.status_code == 403 and r.json()["code"] == "forbidden"
    payload = {"name": "n", "slug": "new-a", "project_connection_id": str(two.a)}
    assert mix.post("/api/v1/services", json=payload).status_code == 403
    # invisible project: 404, never 403
    payload = {"name": "n", "slug": "new-x", "project_connection_id": str(uuid4())}
    r = mix.post("/api/v1/services", json=payload)
    assert r.status_code == 404 and r.json()["code"] == "project-not-found"
    # own project: allowed
    r = mix.patch(
        f"/api/v1/services/{two.svc_b['id']}", json={"name": "B2"}, headers={"If-Match": '"1"'}
    )
    assert r.status_code == 200, r.text
    payload = {"name": "n", "slug": "new-b", "project_connection_id": str(two.b)}
    assert mix.post("/api/v1/services", json=payload).status_code == 201
    # registering a server of project A (visible to mix only as viewer) under B's service: 404, not a hint
    new_b = mix.post("/api/v1/services", json={**payload, "slug": "new-b2"}).json()
    a_server = two.oid("observed_server", two.env.ids["green"], two.a)
    r = mix.post(
        f"/api/v1/services/{new_b['id']}/managed-vms", json={"observed_server_id": a_server}
    )
    assert r.status_code == 404 and r.json()["code"] == "observed-server-not-found"
    denied = two.env.auth.sql(
        "SELECT count(*) FROM audit_event WHERE action = 'authz.denied' AND actor_id = :u",
        u=mix.user_id,
    )[0][0]
    assert denied >= 2


def test_operator_of_another_project_gets_404_on_changes(two: Two) -> None:
    ob = two.user("o-b", [("operator", f"project:{two.b}")])
    r = ob.patch(
        f"/api/v1/services/{two.svc_a['id']}", json={"name": "x"}, headers={"If-Match": '"1"'}
    )
    assert r.status_code == 404 and r.json()["code"] == "service-not-found"
    r = ob.delete(f"/api/v1/services/{two.svc_a['id']}", headers={"If-Match": '"1"'})
    assert r.status_code == 404
    oa = two.user("o-a", [("operator", f"project:{two.a}")])
    r = oa.delete(f"/api/v1/managed-vms/{two.vm_b['id']}")
    assert r.status_code == 404 and r.json()["code"] == "managed-vm-not-found"
    r = oa.post(
        f"/api/v1/services/{two.svc_b['id']}/managed-vms",
        json={"observed_server_id": two.oid("observed_server", two.b_server, two.b)},
    )
    assert r.status_code == 404 and r.json()["code"] == "service-not-found"
    # nothing changed in B
    two.env.as_("operator")
    assert two.env.client.get(f"/api/v1/managed-vms/{two.vm_b['id']}").status_code == 200


def test_project_scoped_token_sees_only_its_project(two: Two) -> None:
    ga = two.user("gop", [("operator", "global")])
    r = ga.post(
        "/api/v1/tokens",
        json={"name": "b-only", "scopes": ["read"], "project_scope": f"project:{two.b}"},
    )
    assert r.status_code == 201, r.text
    bearer = {"Authorization": f"Bearer {r.json()['token']}"}
    anon = two.env.auth.client()
    assert {
        i["project_connection_id"]
        for i in anon.get("/api/v1/servers", headers=bearer).json()["items"]
    } == {str(two.b)}
    assert anon.get(f"/api/v1/services/{two.svc_a['id']}", headers=bearer).status_code == 404
