# ruff: noqa: F811
"""Credential store end to end against PostgreSQL (security-model.md 4.4, 5.1, 5.2, 10 items 6, 12, 13).

Api: admin CRUD, step-up + typed confirmation on upload, write-only secret. Database: the ``ovlm_api`` role cannot
read ciphertext or vouch for a credential. Worker: out-of-band validation (Keystone replaced by a double), atomic
switch on rotation, expired and failed credentials refused, KEK re-wrap. A canary secret is hunted in every
response, audit row, log line and plain column."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from ovlm.config.settings import KekSettings
from ovlm.connections.credentials import CredentialStore, CredentialUnavailableError
from ovlm.connections.validation import CredentialValidator, TokenFacts, rewrap_all
from ovlm.openstack.sdk_write import WriteCredential
from ovlm.renewal.production import SdkCloudPort, StoreCredentialSource
from ovlm.secrets.cli import kek_status_code
from ovlm.secrets.keyring import Keyring, generate_private_pem, public_pem_of
from ovlm.secrets.store import announce_keys, kek_usage, legacy_count
from tests.integration.auth_support import PASSWORD, Env, env, log_lines  # noqa: F401
from tests.integration.conftest import API_PW, WORKER_PW

PROJECT = "0123456789abcdef0123456789abcdef"
APP_W, APP_W2, APP_R = "a" * 32, "b" * 32, "c" * 32
CANARY = "CANARY-app-cred-secret-7c1e9b2f"
CANARY2 = "CANARY-rotated-secret-55d0e8a4"


def _ssh_key() -> tuple[str, str]:
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                           serialization.NoEncryption()).decode()  # fmt: skip
    pub = (
        k.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    return priv, pub


class Store:
    """Admin client, the worker's key ring and engine, and helpers."""

    def __init__(self, env: Env, tmp: Path) -> None:
        self.env = env
        pem = generate_private_pem()
        self.key = serialization.load_pem_private_key(pem, password=None)
        pub = tmp / "kek.pub"
        pub.write_bytes(public_pem_of(pem))
        env.app.state.settings = env.settings.model_copy(
            update={"kek": KekSettings(public_key_file=pub)}
        )
        self.admin, self.totp = env.user_client("root", [("admin", "global")])
        self.worker_engine: Engine = env.role_engine("ovlm_worker", WORKER_PW)
        self.keyring = Keyring(self.key)  # type: ignore[arg-type]
        self.store = CredentialStore(self.worker_engine, self.keyring, tmp / "ca")
        with self.worker_engine.begin() as c:  # the worker announces the key it holds (CS-5)
            announce_keys(c, self.keyring.current_kek_id, self.keyring.kek_ids)
        self.facts: dict[str, TokenFacts] = {}
        self.validator = CredentialValidator(self.store, self.checker)

    def checker(self, auth_url: str, app_id: str, secret: str, verify: bool | str) -> TokenFacts:
        assert verify is True or Path(str(verify)).is_file()
        return self.facts[app_id]

    def h(self) -> dict[str, str]:
        return self.env.headers(self.admin)

    def stepup(self, action: str, target: str) -> str:
        self.env.clock.advance()
        body = {
            "password": PASSWORD,
            "action": action,
            "target_id": target,
            "totp_code": self.env.code(self.totp or ""),
        }
        r = self.admin.post("/api/v1/session/reauth", json=body, headers=self.h())
        assert r.status_code == 200, r.text
        return str(r.json()["stepup_id"])

    def connection(self, name: str = "lab", project: str = PROJECT) -> str:
        r = self.admin.post("/api/v1/clouds", headers=self.h(),
                            json={"name": f"cloud-{name}", "auth_url": "https://keystone.test:5000/v3", "region": "R1"})  # fmt: skip
        assert r.status_code == 201, r.text
        r = self.admin.post("/api/v1/project-connections", headers=self.h(), json={
            "cloud_id": r.json()["id"], "openstack_project_id": project.upper(), "openstack_project_name": "Lab",
            "name": name})  # fmt: skip
        assert r.status_code == 201, r.text
        return str(r.json()["id"])

    def upload(
        self,
        pc: str,
        kind: str,
        secret: str,
        app: str | None = None,
        days: int = 90,
        name: str = "lab",
    ) -> Any:
        body: dict[str, Any] = {"kind": kind, "secret": secret, "stepup_id": self.stepup("credential.upload", pc),
                                "typed_confirmation": name}  # fmt: skip
        if app:
            body |= {
                "app_credential_id": app,
                "expires_at": (datetime.now(UTC) + timedelta(days=days)).isoformat(),
            }
        return self.admin.post(
            f"/api/v1/project-connections/{pc}/credentials", json=body, headers=self.h()
        )

    def facts_for(self, app: str, *roles: str, project: str = PROJECT) -> None:
        self.facts[app] = TokenFacts(project, tuple(roles), "svc-user", app, True, None, record_status=200,
                                     record_unrestricted=False, record_expires_at=datetime.now(UTC) + timedelta(days=30))  # fmt: skip


def _write(st: Store, pc: str) -> WriteCredential:
    creds = StoreCredentialSource(st.store).for_project(pc)
    assert creds is not None
    return creds.write


@pytest.fixture
def st(env: Env, tmp_path: Path) -> Iterator[Store]:
    s = Store(env, tmp_path)
    yield s
    s.worker_engine.dispose()


def _hunt(env: Env, *canaries: str, extra: tuple[str, ...] = ()) -> None:
    """No canary in audit rows, log lines, plain columns of the credential tables, or the given texts."""
    dumps = [
        str(env.sql("SELECT * FROM audit_event")),
        env.log_stream.getvalue(),
        str(env.sql("SELECT * FROM credential_ref")),
        str(
            env.sql(
                "SELECT encode(ciphertext, 'escape') AS c, encode(wrapped_dek, 'escape') AS w FROM sealed_secret"
            )
        ),
        *extra,
    ]
    for c in canaries:
        for d in dumps:
            assert c not in d


# --- connections ------------------------------------------------------------------------------------------------


def test_connection_crud_is_admin_only_audited_and_normalised(st: Store) -> None:
    env = st.env
    pc = st.connection()
    got = st.admin.get(f"/api/v1/project-connections/{pc}").json()
    assert (
        got["openstack_project_id"] == PROJECT
        and got["tls_verify"] is True
        and got["enabled"] is True
    )
    r = st.admin.patch(
        f"/api/v1/project-connections/{pc}", headers=st.h(), json={"version": 1, "enabled": False}
    )
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["version"] == 2
    assert st.admin.patch(f"/api/v1/project-connections/{pc}", headers=st.h(),
                          json={"version": 1, "enabled": True}).status_code == 409  # fmt: skip
    dup = st.admin.post("/api/v1/project-connections", headers=st.h(), json={
        "cloud_id": got["cloud_id"], "openstack_project_id": PROJECT, "openstack_project_name": "x", "name": "other"})  # fmt: skip
    assert dup.status_code == 409
    insecure = st.admin.post("/api/v1/clouds", headers=st.h(),
                             json={"name": "plain", "auth_url": "http://keystone.test/v3", "region": "R1"})  # fmt: skip
    assert insecure.status_code == 422
    actions = [r.action for r in env.sql("SELECT action FROM audit_event WHERE target_type IN "
                                         "('cloud', 'project_connection') ORDER BY id")]  # fmt: skip
    assert actions == ["cloud.create", "project_connection.create", "project_connection.update"]
    op, _ = env.user_client("olga", [("operator", "global")])
    assert op.post("/api/v1/clouds", headers=env.headers(op),
                   json={"name": "x", "auth_url": "https://k.test/v3", "region": "R"}).status_code == 403  # fmt: skip


def test_listing_is_scoped_and_out_of_scope_is_404(st: Store) -> None:
    env = st.env
    a = st.connection("pa", "1" * 32)
    b = st.connection("pb", "2" * 32)
    va, _ = env.user_client("viewer-a", [("viewer", f"project:{a.upper()}")])
    assert [i["id"] for i in va.get("/api/v1/project-connections").json()["items"]] == [a]
    assert va.get(f"/api/v1/project-connections/{b}").status_code == 404
    assert va.get(f"/api/v1/project-connections/{a}").status_code == 200
    [row] = env.sql(
        "SELECT scope FROM role_binding rb JOIN app_user u ON u.id = rb.user_id WHERE username='viewer-a'"
    )
    assert row.scope == f"project:{a}"  # stored lower case (SEC-C-8)


def test_role_binding_needs_an_existing_project_connection(st: Store) -> None:
    env = st.env
    pc = st.connection()
    env.user_client("pcx", [("viewer", "global")])
    [user] = env.sql("SELECT id FROM app_user WHERE username='pcx'")

    def bind(scope: str) -> Any:
        return st.admin.post("/api/v1/role-bindings", headers=st.h(),
                             json={"user_id": str(user.id), "role": "operator", "scope": scope})  # fmt: skip

    assert bind(f"project:{uuid4()}").status_code == 404
    assert bind(f"project:{pc.upper()}").status_code == 201
    assert (
        st.admin.delete(f"/api/v1/project-connections/{pc}", headers=st.h()).status_code == 409
    )  # in use


# --- upload -----------------------------------------------------------------------------------------------------


def test_upload_needs_stepup_and_typed_confirmation_and_never_echoes_the_secret(st: Store) -> None:
    env = st.env
    pc = st.connection()
    base = {"kind": "os_write", "secret": CANARY, "app_credential_id": APP_W,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat()}  # fmt: skip
    url = f"/api/v1/project-connections/{pc}/credentials"
    no_stepup = st.admin.post(
        url, headers=st.h(), json={**base, "stepup_id": str(uuid4()), "typed_confirmation": "lab"}
    )
    assert no_stepup.status_code == 403 and no_stepup.json()["code"] == "stepup-invalid"
    wrong_target = st.stepup("credential.upload", str(uuid4()))
    assert st.admin.post(url, headers=st.h(), json={**base, "stepup_id": wrong_target,
                                                    "typed_confirmation": "lab"}).status_code == 403  # fmt: skip
    step = st.stepup("credential.upload", pc)
    mismatch = st.admin.post(
        url, headers=st.h(), json={**base, "stepup_id": step, "typed_confirmation": "nope"}
    )
    assert mismatch.status_code == 422 and CANARY not in mismatch.text
    invalid = st.admin.post(url, headers=st.h(), json={**base, "expires_at": "2020-01-01T00:00:00Z", "stepup_id": step,
                                                       "typed_confirmation": "lab"})  # fmt: skip
    assert invalid.status_code == 422 and CANARY not in invalid.text
    r = st.upload(pc, "os_write", CANARY, APP_W)
    assert r.status_code == 202, r.text
    body = r.json()
    assert (
        body["state"] == "pending"
        and body["secret_set"] is True
        and body["validation"]["state"] == "pending"
    )
    assert body["kek_id"] == st.keyring.current_kek_id
    replay = st.admin.post(
        url, headers=st.h(), json={**base, "stepup_id": step, "typed_confirmation": "lab"}
    )
    assert replay.status_code in (403, 409)
    again = st.upload(pc, "os_write", CANARY, APP_W)
    assert again.status_code == 409 and again.json()["code"] == "credential-pending"
    listing = st.admin.get(f"/api/v1/project-connections/{pc}/credentials")
    detail = st.admin.get(f"/api/v1/credentials/{body['id']}")
    [audit_row] = env.sql("SELECT after FROM audit_event WHERE action = 'credential.upload'")
    assert audit_row.after["changed_fields"] == ["secret"] and audit_row.after["kind"] == "os_write"
    _hunt(env, CANARY, extra=(r.text, listing.text, detail.text, again.text))


def test_ssh_key_upload_records_only_the_public_key(st: Store) -> None:
    pc = st.connection()
    priv, pub = _ssh_key()
    r = st.upload(pc, "ssh_key", priv)
    assert r.status_code == 202, r.text
    assert r.json()["ssh_public_key"] == pub and r.json()["ssh_public_key_fingerprint"].startswith(
        "SHA256:"
    )
    marker = priv.splitlines()[1]
    _hunt(st.env, marker, extra=(r.text,))
    assert (
        st.upload(pc, "os_read", "x", None).status_code == 422
    )  # application credential needs id and expiry


def test_no_public_key_means_no_upload(st: Store) -> None:
    pc = st.connection()
    st.env.app.state.settings = st.env.settings
    r = st.upload(pc, "os_write", CANARY, APP_W)
    assert r.status_code == 503 and r.json()["code"] == "credential-store-unconfigured"


# --- database: the api cannot decrypt or vouch -------------------------------------------------------------------


def test_api_role_cannot_read_ciphertext_or_activate_a_credential(st: Store) -> None:
    pc = st.connection()
    cred = st.upload(pc, "os_write", CANARY, APP_W).json()["id"]
    api = st.env.role_engine("ovlm_api", API_PW)
    try:
        for sql in (
            "SELECT ciphertext FROM sealed_secret",
            "SELECT wrapped_dek FROM sealed_secret",
            "SELECT * FROM sealed_secret",
            f"UPDATE credential_ref SET state = 'active' WHERE id = '{cred}'",  # noqa: S608 - test ids
            f"UPDATE credential_ref SET validation_result = '{{\"ok\": true}}' WHERE id = '{cred}'",  # noqa: S608
            f"UPDATE sealed_secret SET kek_id = '0000000000000000' WHERE id = '{uuid4()}'",  # noqa: S608
        ):
            with pytest.raises(DBAPIError), api.begin() as c:
                c.execute(text(sql))
        with pytest.raises(DBAPIError, match="pending, unvalidated"), api.begin() as c:
            c.execute(text(
                "INSERT INTO credential_ref (id, project_connection_id, kind, secret_id, app_credential_id, expires_at, "
                "state) SELECT gen_random_uuid(), project_connection_id, 'os_read', secret_id, app_credential_id, "
                "expires_at, 'active' FROM credential_ref LIMIT 1"))  # fmt: skip
        with api.begin() as c:  # metadata stays readable
            assert (
                c.execute(text("SELECT kek_id FROM sealed_secret")).scalar_one()
                == st.keyring.current_kek_id
            )
    finally:
        api.dispose()


# --- worker: validation, switch, refusal -------------------------------------------------------------------------


def _ready(st: Store, pc: str) -> None:
    st.facts_for(APP_W, "member", "reader")
    assert st.upload(pc, "os_write", CANARY, APP_W).status_code == 202
    priv, _ = _ssh_key()
    assert st.upload(pc, "ssh_key", priv).status_code == 202
    assert st.validator.run_once() == {"active": 2}


def test_validation_activates_and_the_renewal_gets_the_credentials_in_memory(st: Store) -> None:
    pc = st.connection()
    port = SdkCloudPort(StoreCredentialSource(st.store))
    assert "no validated write" in (port.unavailable_reason(pc) or "")
    _ready(st, pc)
    assert port.unavailable_reason(pc) is None
    creds = StoreCredentialSource(st.store).for_project(pc)
    assert creds is not None
    assert (
        creds.write.application_credential_secret == CANARY
        and creds.write.application_credential_id == APP_W
    )
    assert (
        creds.write.auth_url == "https://keystone.test:5000/v3" and creds.write.region_name == "R1"
    )
    assert creds.write_user_id == "svc-user" and creds.guest_public_key.startswith("ssh-ed25519 ")
    assert CANARY not in repr(creds) and "PRIVATE" not in repr(creds)
    assert st.validator.run_once() == {}  # nothing due
    rows = st.env.sql(
        "SELECT action, result, principal_type FROM audit_event WHERE action = 'credential.validate'"
    )
    assert [(r.result, r.principal_type) for r in rows] == [("success", "worker")] * 2
    _hunt(st.env, CANARY)


def test_rotation_switches_atomically_and_marks_the_old_one_for_cloud_deletion(st: Store) -> None:
    pc = st.connection()
    _ready(st, pc)
    st.facts_for(APP_W2, "member", "reader")
    new = st.upload(pc, "os_write", CANARY2, APP_W2).json()["id"]
    assert _write(st, pc).application_credential_secret == CANARY
    assert st.validator.run_once() == {"active": 1}
    rows = {r.id: r for r in st.env.sql("SELECT id::text, state, superseded_by::text, cloud_deletion_pending "
                                        "FROM credential_ref WHERE kind = 'os_write'")}  # fmt: skip
    assert rows[new].state == "active"
    [old] = [r for r in rows.values() if r.id != new]
    assert (
        old.state == "superseded"
        and old.superseded_by == new
        and old.cloud_deletion_pending is True
    )
    assert _write(st, pc).application_credential_secret == CANARY2
    assert st.env.sql("SELECT 1 FROM audit_event WHERE action = 'credential.rotate'")
    _hunt(st.env, CANARY, CANARY2)


@pytest.mark.parametrize(
    ("roles", "project", "reason"),
    [
        (("member", "admin"), PROJECT, "other roles"),
        (("reader",), PROJECT, "lacks the role 'member'"),
        (("member",), "f" * 32, "not scoped"),
    ],
)
def test_a_failing_credential_is_rejected_and_the_active_one_stays(
    st: Store, roles: tuple[str, ...], project: str, reason: str
) -> None:
    pc = st.connection()
    _ready(st, pc)
    st.facts_for(APP_W2, *roles, project=project)
    bad = st.upload(pc, "os_write", CANARY2, APP_W2).json()["id"]
    assert st.validator.run_once() == {"rejected": 1}
    got = st.admin.get(f"/api/v1/credentials/{bad}").json()
    assert got["state"] == "rejected" and reason in got["validation"]["reason"]
    assert _write(st, pc).application_credential_id == APP_W


def test_expired_or_invalidated_credential_is_refused(st: Store) -> None:
    pc = st.connection()
    _ready(st, pc)
    port = SdkCloudPort(StoreCredentialSource(st.store))
    st.env.sql(  # the expiry Keystone reported (the uploaded one is immutable)
        "UPDATE credential_ref SET verified_expires_at = now() - interval '1 minute' WHERE kind = 'os_write'"
    )
    assert "expired" in (port.unavailable_reason(pc) or "")
    with pytest.raises(CredentialUnavailableError, match="expired"):
        st.store.app_credential(pc, "os_write")
    # re-validation of an expired active credential marks it invalid; it stays refused
    cred = st.env.sql("SELECT id::text FROM credential_ref WHERE kind = 'os_write'")[0].id
    assert st.admin.post(f"/api/v1/credentials/{cred}/validate", headers=st.h()).status_code == 202
    assert st.validator.run_once() == {"active": 1}
    st.env.sql(
        "UPDATE credential_ref SET verified_expires_at = now() + interval '1 day' WHERE kind = 'os_write'"
    )
    assert "failed its last validation" in (port.unavailable_reason(pc) or "")
    st.env.sql("UPDATE project_connection SET enabled = false")
    assert "disabled" in (port.unavailable_reason(pc) or "")


def test_ciphertext_moved_to_another_credential_does_not_decrypt(st: Store) -> None:
    pc = st.connection()
    _ready(st, pc)
    st.facts_for(APP_R, "reader")
    assert st.upload(pc, "os_read", "read-secret", APP_R).status_code == 202
    assert st.validator.run_once() == {"active": 1}
    # a database attacker swaps the read credential's sealed value into the write credential's row
    st.env.sql(
        "UPDATE sealed_secret w SET wrapped_dek = r.wrapped_dek, nonce = r.nonce, ciphertext = r.ciphertext "
        "FROM sealed_secret r, credential_ref cw, credential_ref cr WHERE cw.kind = 'os_write' AND cr.kind = 'os_read' "
        "AND w.id = cw.secret_id AND r.id = cr.secret_id"
    )
    with pytest.raises(CredentialUnavailableError, match="cannot be decrypted"):
        st.store.app_credential(pc, "os_write")


def test_kek_rotation_rewraps_every_secret(st: Store) -> None:
    pc = st.connection()
    _ready(st, pc)
    old_id = st.keyring.current_kek_id
    new_key = X25519PrivateKey.generate()
    st.store.keyring = Keyring(new_key, [st.key])  # type: ignore[list-item]
    assert rewrap_all(st.store) == {"rewrapped": 2, "unknown_key": 0}
    with st.worker_engine.connect() as c:
        usage = kek_usage(c)
    assert usage == {st.store.keyring.current_kek_id: 2} and old_id not in usage
    st.store.keyring = Keyring(new_key)  # old key removed after the verified pass
    assert _write(st, pc).application_credential_secret == CANARY
    assert st.env.sql("SELECT 1 FROM audit_event WHERE action = 'kek.rewrap'")


def test_sf4_rejected_legacy_credentials_do_not_block_kek_retirement(st: Store) -> None:
    """Review N-3 (SF-4): a rejected ``ovlm-env-v1`` credential keeps its sealed row as metadata. The worker never
    decrypts that format, so a KEK rotation must neither try to re-wrap it nor count it as "in use": otherwise
    ``ovlm kek status`` stays at 3 and the old key can never be retired."""
    pc = st.connection()
    _ready(st, pc)
    # what connections_0002 leaves behind for a credential sealed before the binding: rejected, format v1
    st.env.sql(
        "UPDATE sealed_secret SET alg = 'ovlm-env-v1' FROM credential_ref r "
        "WHERE r.secret_id = sealed_secret.id AND r.kind = 'ssh_key'"
    )
    st.env.sql("UPDATE credential_ref SET state = 'rejected' WHERE kind = 'ssh_key'")
    old_id = st.keyring.current_kek_id
    new_key = X25519PrivateKey.generate()
    st.store.keyring = Keyring(new_key, [st.key])  # type: ignore[list-item]
    assert rewrap_all(st.store) == {"rewrapped": 1, "unknown_key": 0}
    with st.worker_engine.connect() as c:
        usage = kek_usage(c)
        assert legacy_count(c) == 1
    current = st.store.keyring.current_kek_id
    assert usage == {current: 1} and old_id not in usage
    assert kek_status_code(usage, current, frozenset({current})) == 0  # the old key may go
    # the rejected row is still there (an admin deletes it), and still refused
    assert (
        st.env.sql("SELECT state FROM credential_ref WHERE kind = 'ssh_key'")[0].state == "rejected"
    )


def test_delete_credential_needs_stepup_and_removes_the_ciphertext(st: Store) -> None:
    pc = st.connection()
    cred = st.upload(pc, "os_write", CANARY, APP_W).json()["id"]
    body = {"stepup_id": st.stepup("credential.delete", cred), "typed_confirmation": "lab"}
    r = st.admin.request("DELETE", f"/api/v1/credentials/{cred}", json=body, headers=st.h())
    assert r.status_code == 204, r.text
    assert not st.env.sql("SELECT 1 FROM sealed_secret") and not st.env.sql(
        "SELECT 1 FROM credential_ref"
    )
