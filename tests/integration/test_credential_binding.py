# ruff: noqa: F811
"""Regression tests of the credential store review (docs/reviews/review-credential-store.md, CS-1, CS-2).

Both attacks were demonstrated against ``571ff01``: the worker decrypted a project's application credential and sent
it to an ``auth_url`` chosen by (CS-1) an admin with a password-only session or the ``ovlm_api`` role changing the
cloud row, or (CS-2) the ``ovlm_api`` role deleting a ``credential_ref`` and re-inserting it, same id, under a
connection whose cloud it controls. The Keystone double records every ``(auth_url, secret)`` it is given: the
secret must reach the validated endpoint only."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from alembic import command
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError

from ovlm.connections.credentials import CredentialUnavailableError
from ovlm.connections.validation import TokenFacts
from ovlm.db.engine import make_engine
from ovlm.db.schema import alembic_config
from ovlm.secrets.keyring import Keyring, public_pem_of
from ovlm.secrets.store import kek_usage, orphan_count
from tests.integration.auth_support import Env, env  # noqa: F401
from tests.integration.conftest import API_PW, settings_for
from tests.integration.test_credential_store import APP_R, APP_W, CANARY, PROJECT, Store, _ready

ATTACKER = "https://attacker.example/v3"
GOOD = "https://keystone.test:5000/v3"


class Spy(Store):
    def __init__(self, env: Env, tmp: Path) -> None:
        super().__init__(env, tmp)
        self.sent: list[tuple[str, str]] = []

    def checker(self, auth_url: str, app_id: str, secret: str, verify: bool | str) -> TokenFacts:
        self.sent.append((auth_url, secret))
        return super().checker(auth_url, app_id, secret, verify)

    def leaked(self) -> list[str]:
        return [u for u, s in self.sent if u != GOOD and s == CANARY]


@pytest.fixture
def spy(env: Env, tmp_path: Path) -> Iterator[Spy]:
    s = Spy(env, tmp_path)
    yield s
    s.worker_engine.dispose()


def _cloud_of(st: Store, pc: str) -> dict[str, Any]:
    cloud_id = st.admin.get(f"/api/v1/project-connections/{pc}").json()["cloud_id"]
    return dict(st.admin.get(f"/api/v1/clouds/{cloud_id}").json())


def _use_everything(st: Spy, pc: str) -> None:
    """Every path that decrypts: the validation job (requested and periodic) and a renewal's use."""
    for cred in st.env.sql(
        "SELECT id::text FROM credential_ref WHERE state IN ('pending', 'active')"
    ):
        st.admin.post(f"/api/v1/credentials/{cred.id}/validate", headers=st.h())
    st.validator.run_once()
    with contextlib.suppress(CredentialUnavailableError):
        st.store.app_credential(pc, "os_write")


# --- CS-1 -------------------------------------------------------------------------------------------------------


def test_cs1_endpoint_change_needs_stepup_and_typed_confirmation(spy: Spy) -> None:
    pc = spy.connection()
    _ready(spy, pc)
    cloud = _cloud_of(spy, pc)
    url = f"/api/v1/clouds/{cloud['id']}"
    plain = spy.admin.patch(
        url, headers=spy.h(), json={"version": cloud["version"], "auth_url": ATTACKER}
    )
    assert plain.status_code in (403, 422), (
        plain.text
    )  # a password-only session cannot redirect the secret
    assert _cloud_of(spy, pc)["auth_url"] == GOOD
    step = spy.stepup("cloud.update", cloud["id"])
    wrong = spy.admin.patch(url, headers=spy.h(), json={"version": cloud["version"], "auth_url": ATTACKER,
                                                         "stepup_id": step, "typed_confirmation": "nope"})  # fmt: skip
    assert wrong.status_code == 422 and _cloud_of(spy, pc)["auth_url"] == GOOD
    # every field of a cloud PATCH decides where a secret goes, so every PATCH takes the step-up
    _use_everything(spy, pc)
    assert spy.leaked() == []


def test_cs1_approved_endpoint_change_invalidates_bound_credentials(spy: Spy) -> None:
    """Even a properly approved change (step-up, typed confirmation, audited) never sends the secret to the new
    endpoint: the credentials bound to the old one go back to pending validation and are refused."""
    pc = spy.connection()
    _ready(spy, pc)
    cloud = _cloud_of(spy, pc)
    step = spy.stepup("cloud.update", cloud["id"])
    r = spy.admin.patch(f"/api/v1/clouds/{cloud['id']}", headers=spy.h(), json={
        "version": cloud["version"], "auth_url": ATTACKER, "stepup_id": step, "typed_confirmation": cloud["name"]})  # fmt: skip
    assert r.status_code == 200, r.text
    creds = spy.admin.get(f"/api/v1/project-connections/{pc}/credentials").json()["items"]
    assert {c["validation"]["state"] for c in creds} == {"pending"}
    assert all(c["endpoint_matches"] is False for c in creds)
    with pytest.raises(CredentialUnavailableError, match="endpoint"):
        spy.store.app_credential(pc, "os_write")
    spy.sent.clear()
    assert spy.validator.run_once() == {"active": 2}  # stays active, recorded invalid
    assert spy.sent == []  # nothing decrypted, nothing sent
    creds = spy.admin.get(f"/api/v1/project-connections/{pc}/credentials").json()["items"]
    assert {c["validation"]["state"] for c in creds} == {"invalid"}
    assert all("endpoint" in c["validation"]["reason"] for c in creds)
    _use_everything(spy, pc)
    assert spy.leaked() == []
    [a] = spy.env.sql("SELECT after FROM audit_event WHERE action = 'cloud.update'")
    assert a.after["stepup_id"] == step and a.after["invalidated_count"] == 2
    assert (
        len(spy.env.sql("SELECT 1 FROM audit_event WHERE action = 'credential.endpoint_changed'"))
        == 2
    )


def test_cs1_api_role_redirecting_the_cloud_gets_nothing(spy: Spy) -> None:
    """The ``ovlm_api`` role (or a compromised api) rewrites the cloud row directly: no step-up, no invalidation.
    The worker derives the AAD from the live endpoint, so nothing decrypts for the attacker's URL."""
    pc = spy.connection()
    _ready(spy, pc)
    api = spy.env.role_engine("ovlm_api", API_PW)
    try:
        with api.begin() as c:
            c.execute(text("UPDATE cloud SET auth_url = :u, ca_bundle_pem = NULL, ca_bundle_sha256 = NULL"),
                      {"u": ATTACKER})  # fmt: skip
    finally:
        api.dispose()
    _use_everything(spy, pc)
    assert spy.leaked() == []
    # a project moved to another cloud: the api role may not (cloud_id is not granted), and even the owner role
    # doing it gets nothing out of the worker
    spy.env.sql("UPDATE cloud SET auth_url = :u", u=GOOD)
    other = spy.admin.post("/api/v1/clouds", headers=spy.h(),
                           json={"name": "evil", "auth_url": ATTACKER, "region": "R1"}).json()["id"]  # fmt: skip
    api = spy.env.role_engine("ovlm_api", API_PW)
    try:
        with pytest.raises(DBAPIError), api.begin() as c:
            c.execute(text("UPDATE project_connection SET cloud_id = :c"), {"c": other})
    finally:
        api.dispose()
    spy.env.sql("UPDATE project_connection SET cloud_id = :c", c=other)
    _use_everything(spy, pc)
    assert spy.leaked() == []


def test_cs1_guest_access_change_needs_stepup(spy: Spy) -> None:
    pc = spy.connection()
    got = spy.admin.get(f"/api/v1/project-connections/{pc}").json()
    jump = {"mode": "jump_host", "host": "jump.test", "port": 22,
            "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogusKeyMaterialForTests0123456789"}  # fmt: skip
    url = f"/api/v1/project-connections/{pc}"
    plain = spy.admin.patch(
        url, headers=spy.h(), json={"version": got["version"], "guest_access": jump}
    )
    assert plain.status_code in (403, 422), plain.text
    step = spy.stepup("project_connection.update", pc)
    ok = spy.admin.patch(url, headers=spy.h(), json={"version": got["version"], "guest_access": jump,
                                                      "stepup_id": step, "typed_confirmation": "lab"})  # fmt: skip
    assert ok.status_code == 200, ok.text
    # enabling/disabling or renaming decides nothing about where a secret goes: no step-up
    assert spy.admin.patch(url, headers=spy.h(), json={"version": ok.json()["version"],
                                                        "enabled": False}).status_code == 200  # fmt: skip


# --- CS-2 -------------------------------------------------------------------------------------------------------


def test_cs2_api_role_cannot_rebind_a_credential_to_another_connection(spy: Spy) -> None:
    pc = spy.connection()
    _ready(spy, pc)
    evil_cloud = spy.admin.post("/api/v1/clouds", headers=spy.h(),
                                json={"name": "evil", "auth_url": ATTACKER, "region": "R1"}).json()["id"]  # fmt: skip
    evil = spy.admin.post("/api/v1/project-connections", headers=spy.h(), json={
        "cloud_id": evil_cloud, "openstack_project_id": PROJECT, "openstack_project_name": "x", "name": "evil"}).json()  # fmt: skip
    [victim] = spy.env.sql("SELECT * FROM credential_ref WHERE kind = 'os_write'")
    reinsert = text(
        "INSERT INTO credential_ref (id, project_connection_id, kind, secret_id, app_credential_id, expires_at, "
        "cloud_id, endpoint_sha256) VALUES (:i, :p, 'os_write', :s, :a, :e, :c, :d)"
    )
    params = {"i": victim.id, "p": evil["id"], "s": victim.secret_id, "a": APP_W, "e": victim.expires_at,
              "c": evil_cloud, "d": victim.endpoint_sha256}  # fmt: skip
    api = spy.env.role_engine("ovlm_api", API_PW)
    try:
        # 1. delete + re-insert, same id, under the attacker's connection: refused by the database
        with pytest.raises(DBAPIError, match="deleted credential"), api.begin() as c:
            c.execute(text("DELETE FROM credential_ref WHERE id = :i"), {"i": victim.id})
            c.execute(reinsert, params)
        # 2. nor can the api re-point the row in place
        with pytest.raises(DBAPIError), api.begin() as c:
            c.execute(text("UPDATE credential_ref SET project_connection_id = :p WHERE id = :i"),
                      {"p": evil["id"], "i": victim.id})  # fmt: skip
        [still] = spy.env.sql(
            "SELECT project_connection_id::text AS p FROM credential_ref WHERE id = :i", i=victim.id
        )
        assert still.p == pc
        # 3. a committed delete leaves a tombstone: the id and the secret can never come back
        with api.begin() as c:
            c.execute(text("DELETE FROM credential_ref WHERE id = :i"), {"i": victim.id})
        with pytest.raises(DBAPIError, match="deleted credential"), api.begin() as c:
            c.execute(reinsert, params)
        with pytest.raises(DBAPIError, match="deleted credential"), api.begin() as c:
            c.execute(reinsert, {**params, "i": uuid4()})  # same secret under a new id
        with pytest.raises(DBAPIError), api.begin() as c:  # the api cannot erase the tombstone
            c.execute(text("DELETE FROM credential_ref_tombstone"))
    finally:
        api.dispose()
    _use_everything(spy, pc)
    assert spy.leaked() == []


def test_cs2_ciphertext_rebound_by_the_owner_does_not_decrypt(spy: Spy) -> None:
    """Defence in depth: even a database actor that *can* rebind the row (the owner role, a restore of a tampered
    dump) gets a value that does not authenticate, because the AAD binds the connection, cloud and endpoint."""
    pc = spy.connection()
    _ready(spy, pc)
    evil_cloud = spy.admin.post("/api/v1/clouds", headers=spy.h(),
                                json={"name": "evil", "auth_url": ATTACKER, "region": "R1"}).json()["id"]  # fmt: skip
    evil = spy.admin.post("/api/v1/project-connections", headers=spy.h(), json={
        "cloud_id": evil_cloud, "openstack_project_id": PROJECT, "openstack_project_name": "x", "name": "evil"}).json()  # fmt: skip
    spy.env.sql("ALTER TABLE credential_ref DISABLE TRIGGER USER")
    try:
        spy.env.sql("UPDATE credential_ref SET project_connection_id = :p, validation_requested_at = now() "
                    "WHERE kind = 'os_write'", p=evil["id"])  # fmt: skip
    finally:
        spy.env.sql("ALTER TABLE credential_ref ENABLE TRIGGER USER")
    spy.facts_for(APP_W, "member", "reader")
    spy.validator.run_once()
    with contextlib.suppress(CredentialUnavailableError):
        spy.store.app_credential(evil["id"], "os_write")
    assert spy.leaked() == []


def test_cs2_api_insert_must_name_the_connections_cloud(spy: Spy) -> None:
    pc = spy.connection()
    _ready(spy, pc)
    other = spy.admin.post("/api/v1/clouds", headers=spy.h(),
                           json={"name": "evil", "auth_url": ATTACKER, "region": "R1"}).json()["id"]  # fmt: skip
    api = spy.env.role_engine("ovlm_api", API_PW)
    try:
        with pytest.raises(DBAPIError, match="connection's cloud"), api.begin() as c:
            c.execute(text(
                "INSERT INTO credential_ref (id, project_connection_id, kind, secret_id, app_credential_id, expires_at, "
                "cloud_id, endpoint_sha256) SELECT gen_random_uuid(), project_connection_id, 'os_read', secret_id, "
                "app_credential_id, expires_at, :c, endpoint_sha256 FROM credential_ref WHERE kind = 'os_write'"),
                {"c": other})  # fmt: skip
    finally:
        api.dispose()


# --- CS-3, CS-4, CS-5, CS-7, CS-9 ---------------------------------------------------------------------------------


def test_upload_records_the_destination(spy: Spy) -> None:
    pc = spy.connection()
    r = spy.upload(pc, "os_write", CANARY, APP_W)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["endpoint_matches"] is True and body["cloud_id"] == _cloud_of(spy, pc)["id"]
    assert len(body["endpoint_sha256"]) == 64


def test_cs3_keystone_expiry_is_stored_and_enforced(spy: Spy) -> None:
    pc = spy.connection()
    _ready(spy, pc)  # the double reports a Keystone expiry 30 days ahead; the upload said 90
    [row] = spy.env.sql(
        "SELECT expires_at, verified_expires_at FROM credential_ref WHERE kind = 'os_write'"
    )
    assert row.verified_expires_at is not None and row.verified_expires_at < row.expires_at
    cred = spy.store.app_credential(pc, "os_write")
    assert cred.expires_at == row.verified_expires_at  # the earlier one is enforced
    listed = spy.admin.get(f"/api/v1/project-connections/{pc}/credentials").json()["items"]
    w = next(c for c in listed if c["kind"] == "os_write")
    assert w["expires_in_days"] in (29, 30) and w["validation"]["state"] == "valid"
    # a never-expiring credential is rejected whatever the form said
    spy.facts[APP_R] = TokenFacts(PROJECT, ("reader",), "svc-user", APP_R, True, None, record_status=200,
                                  record_expires_at=None)  # fmt: skip
    rid = spy.upload(pc, "os_read", "read-secret", APP_R).json()["id"]
    assert spy.validator.run_once() == {"rejected": 1}
    got = spy.admin.get(f"/api/v1/credentials/{rid}").json()
    assert got["state"] == "rejected" and "never expires" in got["validation"]["reason"]


def test_cs4_active_credentials_are_revalidated_and_expiry_is_reported(spy: Spy) -> None:
    pc = spy.connection()
    _ready(spy, pc)
    assert spy.validator.run_once() == {}
    spy.sent.clear()
    # a day later the cloud admin widened the role: the periodic re-validation notices it
    spy.env.sql("UPDATE credential_ref SET last_validated_at = now() - interval '25 hours'")
    spy.facts_for(APP_W, "member", "admin")
    assert spy.validator.run_once() == {"active": 2}
    assert [u for u, _ in spy.sent] == [GOOD]
    with pytest.raises(CredentialUnavailableError, match="failed its last validation"):
        spy.store.app_credential(pc, "os_write")
    spy.env.sql(
        "UPDATE credential_ref SET verified_expires_at = now() + interval '5 days' WHERE kind = 'os_write'"
    )
    report = spy.validator.report()
    assert report["7d"] == 1 and report["failing"] == 1 and report["unknown_kek"] == 0
    assert "credential expiring" in spy.env.log_stream.getvalue()


def test_cs5_unknown_key_is_transient_and_the_api_seals_only_to_announced_keys(spy: Spy) -> None:
    pc = spy.connection()
    # the api is switched to a new public key before the worker: refused, nothing sealed
    new = X25519PrivateKey.generate()
    pub = spy.env.app.state.settings.kek.public_key_file
    pub.write_bytes(new.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))  # fmt: skip
    os.utime(pub, ns=(1, 1))
    r = spy.upload(pc, "os_write", CANARY, APP_W)
    assert r.status_code == 503 and r.json()["code"] == "credential-store-key-unknown"
    # restore, upload, then the worker loses the key (misconfigured rotation): pending stays pending
    pub.write_bytes(public_pem_of(spy.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption())))  # fmt: skip
    os.utime(pub, ns=(2, 2))
    spy.facts_for(APP_W, "member", "reader")
    cred = spy.upload(pc, "os_write", CANARY, APP_W).json()["id"]
    spy.store.keyring = Keyring(new)
    assert spy.validator.run_once() == {"pending": 1}
    got = spy.admin.get(f"/api/v1/credentials/{cred}").json()
    assert got["state"] == "pending" and "does not hold" in str(spy.env.sql(
        "SELECT validation_result FROM credential_ref WHERE id = :i", i=cred)[0].validation_result)  # fmt: skip
    assert spy.validator.report()["unknown_kek"] == 0  # pending, not active
    spy.store.keyring = Keyring(new, [spy.key])  # type: ignore[list-item]  # worker first, done right
    assert spy.validator.run_once() == {"active": 1}


def test_cs7_disabled_connection_is_neither_decrypted_nor_sent(spy: Spy) -> None:
    pc = spy.connection()
    spy.facts_for(APP_W, "member", "reader")
    spy.upload(pc, "os_write", CANARY, APP_W)
    v = spy.admin.get(f"/api/v1/project-connections/{pc}").json()["version"]
    spy.admin.patch(
        f"/api/v1/project-connections/{pc}", headers=spy.h(), json={"version": v, "enabled": False}
    )
    assert spy.validator.run_once() == {} and spy.sent == []
    spy.admin.patch(
        f"/api/v1/project-connections/{pc}",
        headers=spy.h(),
        json={"version": v + 1, "enabled": True},
    )
    assert spy.validator.run_once() == {"active": 1}


def test_cs9_orphan_sealed_secrets_are_swept_and_audited(spy: Spy) -> None:
    pc = spy.connection()
    cred = spy.upload(pc, "os_write", CANARY, APP_W).json()["id"]
    spy.env.sql(
        "DELETE FROM credential_ref WHERE id = :i", i=cred
    )  # a database actor leaves the sealed row
    spy.env.sql("UPDATE sealed_secret SET created_at = now() - interval '1 hour'")
    with spy.worker_engine.connect() as c:
        assert kek_usage(c) == {} and orphan_count(c) == 1
    assert spy.validator.run_once() == {"orphans_deleted": 1}
    assert not spy.env.sql("SELECT 1 FROM sealed_secret")
    [a] = spy.env.sql("SELECT after FROM audit_event WHERE action = 'kek.orphans_deleted'")
    assert a.after["orphans_deleted"] == 1


# --- migration connections_0002 -----------------------------------------------------------------------------------


def test_migration_rejects_unbound_legacy_credentials_and_downgrades(
    admin_url: URL, fresh_db: str, secrets_dir: Path
) -> None:
    """Credentials sealed with ``ovlm-env-v1`` (no destination in the AAD) cannot be trusted any more: the upgrade
    rejects every pending or active one with a reason; the downgrade works."""
    s = settings_for("migrate", admin_url, fresh_db, secrets_dir)
    cfg = alembic_config(s.migrations_dir, s.db_url())
    command.upgrade(cfg, "connections_0001")
    owner = make_engine(s)
    cloud, pc, sec, cred = uuid4(), uuid4(), uuid4(), uuid4()
    try:
        with owner.begin() as c:
            c.execute(text("INSERT INTO cloud (id, name, auth_url, region) VALUES (:i, 'c', 'https://k.test/v3', 'R')"),
                      {"i": cloud})  # fmt: skip
            c.execute(text("INSERT INTO project_connection (id, cloud_id, openstack_project_id, openstack_project_name, "
                           "name) VALUES (:i, :c, :p, 'p', 'p')"), {"i": pc, "c": cloud, "p": PROJECT})  # fmt: skip
            c.execute(text("INSERT INTO sealed_secret (id, alg, kek_id, wrapped_dek, nonce, ciphertext) VALUES "
                           "(:i, 'ovlm-env-v1', '0123456789abcdef', :w, :n, :x)"),
                      {"i": sec, "w": b"\0" * 92, "n": b"\0" * 12, "x": b"\0" * 32})  # fmt: skip
            c.execute(text("INSERT INTO credential_ref (id, project_connection_id, kind, secret_id, app_credential_id, "
                           "expires_at, state, last_validated_at, validation_result) VALUES (:i, :p, 'os_write', :s, "
                           ":a, now() + interval '30 days', 'active', now(), '{\"ok\": true}')"),
                      {"i": cred, "p": pc, "s": sec, "a": APP_W})  # fmt: skip
        command.upgrade(cfg, "heads")
        with owner.connect() as c:
            row = c.execute(
                text(
                    "SELECT state, cloud_id, endpoint_sha256, validation_result FROM credential_ref"
                )
            ).one()
        assert row.state == "rejected" and row.cloud_id == cloud and row.endpoint_sha256 == "0" * 64
        assert "upload the credential again" in row.validation_result["reason"]
        command.downgrade(cfg, "connections_0001")
        with owner.connect() as c:
            assert (
                c.execute(text("SELECT count(*) FROM credential_ref")).scalar_one() == 1
            )  # v1 rows kept
        command.upgrade(cfg, "heads")
    finally:
        owner.dispose()
