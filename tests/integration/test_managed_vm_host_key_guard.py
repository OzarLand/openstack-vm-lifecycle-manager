# ruff: noqa: F811
"""Review IS-1 (docs/reviews/review-inventory-sync-host-keys.md) against PostgreSQL: the ``ovlm_api`` role cannot
forge a confirmed host key for a managed VM.

The reviewer's probe, verbatim: as ``ovlm_api``, delete a confirmed ``managed_vm`` and insert it again under the same
id with another fingerprint, already confirmed. Before ``registry_0002`` the insert succeeded and a plan resolved
afterwards pinned the forged key. Now the insert guard, the tombstone and the fingerprint trigger refuse it, and the
role cannot switch them off (the bypasses probed for the credential store in
docs/reviews/verification-credential-store-fixes.md)."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.test_host_key_scan import Guest, _confirm, _drive, _key, _register
from tests.integration.test_registry_api import Env, env  # noqa: F401

FORGED = "SHA256:" + "A" * 43


def _confirmed_vm(env: Env) -> tuple[dict[str, Any], str]:
    guest = Guest()
    key = _key()
    guest.keys["10.0.0.5"] = [key]
    vm = _register(env)
    _drive(env, guest)
    assert _confirm(env, vm["id"], key.fingerprint).status_code == 200
    return vm, key.fingerprint


def _row(env: Env, vm_id: str) -> Any:
    rows = env.auth.sql(
        "SELECT * FROM managed_vm WHERE id = CAST(:i AS uuid)", i=vm_id
    )  # owner's view
    return rows[0] if rows else None


def _insert(conn: Any, row: Any, **override: Any) -> None:
    cols = {
        "id": row.id, "service_id": row.service_id, "observed_server_id": row.observed_server_id,
        "openstack_server_id": row.openstack_server_id, "role": row.role, "registered_at": row.registered_at,
        "ssh_host_key_fingerprint": None, "host_key_confirmed_by": None, "host_key_confirmed_at": None,
    }  # fmt: skip
    cols.update(override)
    names = ", ".join(cols)
    values = ", ".join(f":{k}" for k in cols)
    conn.execute(text(f"INSERT INTO managed_vm ({names}) VALUES ({values})"), cols)  # noqa: S608


def test_is1_reviewer_probe_delete_and_reinsert_with_a_forged_confirmed_key_is_refused(
    env: Env,
) -> None:
    vm, real = _confirmed_vm(env)
    row = _row(env, vm["id"])
    assert row.ssh_host_key_fingerprint == real and row.host_key_confirmed_at is not None

    # the probe: one transaction, as the api role
    with pytest.raises(DBAPIError) as exc, env.api.begin() as c:
        c.execute(text("DELETE FROM managed_vm WHERE id = :i"), {"i": row.id})
        _insert(c, row, ssh_host_key_fingerprint=FORGED, host_key_confirmed_by=env.operator_id,
                host_key_confirmed_at=row.host_key_confirmed_at)  # fmt: skip
    assert "re-inserted" in str(exc.value)  # the tombstone refuses first
    after = _row(env, vm["id"])
    assert (
        after.ssh_host_key_fingerprint == real and after.host_key_confirmed_at is not None
    )  # rolled back

    # committed delete, then the same id even without any host key: the id is tomb-stoned for good
    with env.api.begin() as c:
        c.execute(text("DELETE FROM managed_vm WHERE id = :i"), {"i": row.id})
    [tomb] = env.auth.sql("SELECT id, deleted_by_role FROM managed_vm_tombstone")
    assert (str(tomb.id), tomb.deleted_by_role) == (vm["id"], "ovlm_api")
    with pytest.raises(DBAPIError, match="re-inserted"), env.api.begin() as c:
        _insert(c, row)
    with pytest.raises(DBAPIError, match="re-inserted"), env.auth.owner.begin() as c:
        _insert(c, row)  # every role, the owner included
    assert _row(env, vm["id"]) is None


def test_is1_api_role_inserts_no_fingerprint_and_no_confirmation(env: Env) -> None:
    vm, _ = _confirmed_vm(env)
    row = _row(env, vm["id"])
    with (
        env.api.begin() as c
    ):  # unregister (the api's DELETE), then try to register a forged row under a new id
        c.execute(text("DELETE FROM managed_vm WHERE id = :i"), {"i": row.id})
    for forged in (
        {"ssh_host_key_fingerprint": FORGED},
        {"host_key_confirmed_by": env.operator_id},
        {"ssh_host_key_fingerprint": FORGED, "host_key_confirmed_by": env.operator_id,
         "host_key_confirmed_at": row.host_key_confirmed_at},
    ):  # fmt: skip
        with pytest.raises(DBAPIError) as exc, env.api.begin() as c:
            _insert(c, row, id=uuid4(), **forged)
        assert "no host key and no confirmation" in str(exc.value)
        assert getattr(exc.value.orig, "sqlstate", None) == "42501"  # insufficient_privilege
    with env.api.begin() as c:  # a clean registration under a new id still works
        _insert(c, row, id=uuid4())


def test_is1_registration_after_unregistration_gets_a_new_id_and_works(env: Env) -> None:
    vm, _ = _confirmed_vm(env)
    assert env.client.delete(f"/api/v1/managed-vms/{vm['id']}").status_code == 204
    again = env.client.post(
        f"/api/v1/services/{vm['service_id']}/managed-vms",
        json={"observed_server_id": env.observed_id(env.ids["blue"])},
    )
    assert again.status_code == 201, again.text
    assert again.json()["id"] != vm["id"] and again.json()["ssh_host_key_fingerprint"] is None


def test_is1_a_fingerprint_change_clears_the_confirmation_for_every_role(env: Env) -> None:
    vm, real = _confirmed_vm(env)
    # the worker (column grant on ssh_host_key_fingerprint) without the scan's WHERE guard
    with env.worker.begin() as c:
        c.execute(
            text("UPDATE managed_vm SET ssh_host_key_fingerprint = :f WHERE id = :i"),
            {"f": FORGED, "i": vm["id"]},
        )
    row = _row(env, vm["id"])
    assert row.ssh_host_key_fingerprint == FORGED
    assert row.host_key_confirmed_at is None and row.host_key_confirmed_by is None

    # the owner too; an UPDATE that keeps the fingerprint keeps the confirmation
    env.auth.sql(
        "UPDATE managed_vm SET ssh_host_key_fingerprint = :f WHERE id = CAST(:i AS uuid)",
        f=real,
        i=vm["id"],
    )
    assert _confirm(env, vm["id"], real).status_code == 200
    env.auth.sql(
        "UPDATE managed_vm SET ssh_host_key_fingerprint = :f, updated_at = now() WHERE id = CAST(:i AS uuid)",
        f=real,
        i=vm["id"],
    )
    assert _row(env, vm["id"]).host_key_confirmed_at is not None
    env.auth.sql(
        "UPDATE managed_vm SET ssh_host_key_fingerprint = :f WHERE id = CAST(:i AS uuid)",
        f=FORGED,
        i=vm["id"],
    )
    assert _row(env, vm["id"]).host_key_confirmed_at is None


def test_is1_a_confirmation_needs_a_fingerprint_and_a_confirmer(env: Env) -> None:
    vm = _register(env)  # not scanned: no fingerprint
    with pytest.raises(DBAPIError, match="managed_vm_host_key_confirmation"), env.api.begin() as c:
        c.execute(
            text(
                "UPDATE managed_vm SET host_key_confirmed_by = :u, host_key_confirmed_at = now() WHERE id = :i"
            ),
            {"u": env.operator_id, "i": vm["id"]},
        )
    with pytest.raises(DBAPIError, match="managed_vm_host_key_confirmation"), env.api.begin() as c:
        c.execute(
            text("UPDATE managed_vm SET host_key_confirmed_at = now() WHERE id = :i"),
            {"i": vm["id"]},
        )


_BYPASSES = {
    # TRUNCATE skips the row DELETE trigger, so it would leave no tombstone
    "truncate": "TRUNCATE managed_vm CASCADE",
    "disable_insert_guard": "ALTER TABLE managed_vm DISABLE TRIGGER managed_vm_api_insert_guard",
    "disable_tombstone": "ALTER TABLE managed_vm DISABLE TRIGGER managed_vm_tombstone",
    "disable_all_triggers": "ALTER TABLE managed_vm DISABLE TRIGGER ALL",
    "drop_trigger": "DROP TRIGGER managed_vm_host_key_follow ON managed_vm",
    "replica_role": "SET session_replication_role = replica",
    "temp_shadow": "CREATE TEMP TABLE managed_vm_tombstone (id uuid)",
    "create_in_public": "CREATE TABLE public.managed_vm_tombstone_x (id uuid)",
    "replace_guard": (
        "CREATE OR REPLACE FUNCTION managed_vm_api_insert_guard() RETURNS trigger LANGUAGE plpgsql "
        "AS $$ BEGIN RETURN NEW; END $$"
    ),
    "insert_tombstone": "INSERT INTO managed_vm_tombstone (id, openstack_server_id, deleted_by_role) "
    "VALUES (gen_random_uuid(), 'x', 'x')",
    "delete_tombstone": "DELETE FROM managed_vm_tombstone",
    "update_tombstone": "UPDATE managed_vm_tombstone SET id = gen_random_uuid()",
    "update_fingerprint": "UPDATE managed_vm SET ssh_host_key_fingerprint = 'SHA256:x'",
    "update_id": "UPDATE managed_vm SET id = gen_random_uuid()",
    "drop_constraint": "ALTER TABLE managed_vm DROP CONSTRAINT managed_vm_host_key_confirmation",
}


@pytest.mark.parametrize("probe", sorted(_BYPASSES))
def test_is1_api_role_cannot_bypass_the_guards(env: Env, probe: str) -> None:
    vm, _ = _confirmed_vm(env)
    with pytest.raises(DBAPIError), env.api.begin() as c:
        c.execute(text(_BYPASSES[probe]))
    with env.api.begin() as c:  # the guards still hold afterwards
        c.execute(text("DELETE FROM managed_vm WHERE id = :i"), {"i": vm["id"]})
    assert env.auth.sql("SELECT count(*) FROM managed_vm_tombstone")[0][0] == 1


def test_is1_the_tombstone_function_cannot_be_called_or_altered_by_the_api(env: Env) -> None:
    for stmt in (
        "SELECT managed_vm_tombstone_record()",
        "ALTER FUNCTION managed_vm_tombstone_record() SECURITY INVOKER",
        "ALTER FUNCTION managed_vm_api_insert_guard() RESET search_path",
    ):
        with pytest.raises(DBAPIError), env.api.begin() as c:
            c.execute(text(stmt))
    [cfg] = env.auth.sql(
        "SELECT prosecdef, proconfig FROM pg_proc WHERE proname = 'managed_vm_tombstone_record'"
    )
    assert cfg.prosecdef and cfg.proconfig == ["search_path=pg_catalog, public, pg_temp"]
