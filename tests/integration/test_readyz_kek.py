"""``/readyz`` reports an api/worker KEK mismatch (review CS-10, roadmap SF-6).

The api seals credentials to the public key at ``kek.public_key_file``; the worker announces the ids of the keys it
holds (``kek_key``). A swapped or stale public key on the api side used to show up only when an admin uploaded a
credential (503 ``credential-store-key-unknown``). Now ``/readyz`` compares the two fingerprints and answers 503 on a
mismatch, without naming any key id (the endpoint is unauthenticated)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import URL, text

from ovlm.api.app import create_app
from ovlm.api.health import KEK_MISMATCH, DbReadinessProbe
from ovlm.db.engine import make_engine
from ovlm.secrets.envelope import kek_id_of
from ovlm.secrets.store import announce_keys
from tests.integration.conftest import settings_for
from tests.integration.test_migrations import migrate


def _pub(path: Path, key: X25519PrivateKey) -> str:
    path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return kek_id_of(key.public_key())


def test_readyz_reports_a_kek_mismatch_without_key_material(
    admin_url: URL,
    fresh_db: str,
    secrets_dir: Path,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    migrate(admin_url, fresh_db, secrets_dir)
    api = make_engine(settings_for("api", admin_url, fresh_db, secrets_dir))
    worker = make_engine(settings_for("worker", admin_url, fresh_db, secrets_dir))
    pub = tmp_path / "kek.pub"
    worker_key, other_key = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    worker_id, other_id = kek_id_of(worker_key.public_key()), kek_id_of(other_key.public_key())
    probe = DbReadinessProbe(api, settings_for("api", admin_url, fresh_db, secrets_dir).migrations_dir,
                             public_key_file=pub)  # fmt: skip
    client = TestClient(create_app(settings_for("api", admin_url, fresh_db, secrets_dir), probe=probe,
                                   start_metrics_server=False))  # fmt: skip
    try:
        _pub(pub, worker_key)
        # the worker has not announced anything yet (first start): ready, the upload route explains the rest
        r = client.get("/readyz")
        assert r.status_code == 200 and r.json()["checks"]["kek"] == "ok", r.text

        with worker.begin() as c:
            announce_keys(c, worker_id, [worker_id])
        r = client.get("/readyz")
        assert r.status_code == 200 and r.json()["checks"] == {
            "database": "ok", "schema": "ok", "kek": "ok",
        }  # fmt: skip

        # the api's public key file is swapped (host compromise of ./secrets, a mix-up after rotation): not ready
        api_id = _pub(pub, other_key)
        with caplog.at_level(logging.ERROR, logger="ovlm.api.health"):
            r = client.get("/readyz")
        assert r.status_code == 503, r.text
        assert r.json()["status"] == "not_ready" and r.json()["checks"]["kek"] == KEK_MISMATCH
        # fingerprints are compared; no key id, let alone key material, on the unauthenticated endpoint
        assert worker_id not in r.text and api_id not in r.text and "PUBLIC KEY" not in r.text
        [rec] = [x for x in caplog.records if "kek mismatch" in x.getMessage()]
        assert rec.__dict__["api_kek_id"] == other_id and rec.__dict__["worker_kek_ids"] == [
            worker_id
        ]

        # "worker first" rotation: the worker holds the new key as current and the old one; the api still seals
        # to the old one (held): ready. Then the api moves to the new key: ready.
        with worker.begin() as c:
            announce_keys(c, other_id, [other_id, worker_id])
        _pub(pub, worker_key)
        assert client.get("/readyz").status_code == 200
        _pub(pub, other_key)
        assert client.get("/readyz").status_code == 200

        # an unreadable public key is not ready either
        pub.write_text("not a key")
        r = client.get("/readyz")
        assert r.status_code == 503 and "cannot be read" in r.json()["checks"]["kek"]
        with api.connect() as c:  # the api role only reads the announcement
            assert c.execute(text("SELECT count(*) FROM kek_key")).scalar_one() == 2
    finally:
        api.dispose()
        worker.dispose()


def test_readyz_without_a_public_key_has_no_kek_check(
    admin_url: URL, fresh_db: str, secrets_dir: Path
) -> None:
    migrate(admin_url, fresh_db, secrets_dir)
    s = settings_for("api", admin_url, fresh_db, secrets_dir)
    api = make_engine(s)
    try:
        assert [r.name for r in DbReadinessProbe(api, s.migrations_dir).check()] == [
            "database",
            "schema",
        ]
    finally:
        api.dispose()
