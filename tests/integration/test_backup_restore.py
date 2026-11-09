# ruff: noqa: F811
"""Backup, restore and upgrade preflight against PostgreSQL (roadmap P1-3, docs/backup-restore-upgrade.md).

* A populated database (active credentials sealed to a KEK, a TOTP-enrolled admin, audit rows, a closed downtime
  interval) is dumped with ``pg_dump -Fc``, restored with the procedure's own ``deploy/backup/create-database.sql``
  and ``pg_restore --single-transaction`` into a new database, migrated to head, and then: the same KEK decrypts the
  credential, another KEK does not; the audit rows are identical; every trigger, table/column/function privilege,
  owner, the database privileges and ``fencing_seq`` are identical; the append-only triggers still refuse; the api
  serves the restored data to the same admin (password + TOTP); ``ovlm backup check`` passes with the keys of the
  backup and refuses others.
* A dump taken at an older revision restores and migrates to head with the same guards as a fresh install.
* ``ovlm upgrade preflight`` refuses while a run is in its window or restore, or a downtime interval is open, and
  with ``--worker-stopped`` while a worker beats or a step holds a lease.

pg_dump / pg_restore / psql must have the server's major version (``SHOW server_version_num``): a newer pg_dump
writes settings an older server does not know (pg_dump 17 sets ``transaction_timeout``, which a 16 server refuses on
restore), an older one cannot dump a newer server. Resolution: ``OVLM_TEST_PG_BIN`` (a directory), else
``/usr/lib/postgresql/<server major>/bin``, else ``PATH`` if its tools have that major. Otherwise the test fails with
the reason; no silent skip.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError

from ovlm.api.app import create_app
from ovlm.auth.totp import TotpVault
from ovlm.cli import main as ovlm_main
from ovlm.connections.credentials import CredentialStore, CredentialUnavailableError
from ovlm.db.engine import make_engine
from ovlm.db.schema import alembic_config, current_revision, head_revision
from ovlm.maintenance.checks import backup_findings, exit_code, runtime_findings
from ovlm.renewal.production import StoreCredentialSource
from ovlm.secrets.keyring import Keyring, generate_private_pem, public_pem_of
from ovlm.secrets.store import announce_keys
from tests.integration.auth_support import ORIGIN, PASSWORD, Env, _Probe, env  # noqa: F401
from tests.integration.conftest import API_PW, ROOT, WORKER_PW, role_url, settings_for
from tests.integration.test_credential_store import APP_W, CANARY, Store, _ready

CREATE_DB_SQL = ROOT / "deploy" / "backup" / "create-database.sql"


# --- PostgreSQL client tools ------------------------------------------------------------------------------------


PG_TOOLS = ("pg_dump", "pg_restore", "psql")
# (host, port) -> the client directory chosen for that server
_PG_BIN: dict[tuple[str, int], Path] = {}


def server_major(admin_url: URL) -> int:
    eng = create_engine(admin_url)
    try:
        with eng.connect() as c:
            return int(c.execute(text("SHOW server_version_num")).scalar_one()) // 10000
    finally:
        eng.dispose()


def client_major(tool: Path) -> int | None:
    """The major version of a PostgreSQL client tool (``pg_dump (PostgreSQL) 16.15 (Ubuntu ...)`` -> 16)."""
    try:
        out = subprocess.run(
            [str(tool), "--version"], capture_output=True, text=True, check=False, timeout=30
        )
    except OSError:
        return None
    m = re.search(r"\(PostgreSQL\) (\d+)", out.stdout)
    return int(m.group(1)) if m else None


def resolve_pg_bin(major: int) -> Path:
    """The directory holding pg_dump / pg_restore / psql of exactly ``major``, or ``pytest.fail`` with the reason.

    ``OVLM_TEST_PG_BIN`` wins (a wrong version there is an error, not a reason to look elsewhere), then
    ``/usr/lib/postgresql/<major>/bin``, then ``PATH``.
    """
    explicit = os.environ.get("OVLM_TEST_PG_BIN")
    debian = Path(f"/usr/lib/postgresql/{major}/bin")
    if explicit:
        where, d = "OVLM_TEST_PG_BIN", Path(explicit)
    elif (debian / "pg_dump").is_file():
        where, d = "/usr/lib/postgresql", debian
    else:
        found = shutil.which("pg_dump")
        if found is None:
            pytest.fail(
                f"no PostgreSQL {major} client tools: install postgresql-client-{major} or set OVLM_TEST_PG_BIN",
                pytrace=False,
            )
        where, d = "PATH", Path(found).parent
    for name in PG_TOOLS:
        got = client_major(d / name) if (d / name).is_file() else None
        if got != major:
            pytest.fail(
                f"{d / name} (from {where}) is PostgreSQL {got or 'missing'} but the server is {major}: "
                "pg_dump/pg_restore/psql must have the server's major version (a newer pg_dump writes settings "
                f"an older server refuses on restore). Install postgresql-client-{major} or set OVLM_TEST_PG_BIN.",
                pytrace=False,
            )
    return d


def pg_bin(admin_url: URL) -> Path:
    key = (admin_url.host or "", admin_url.port or 5432)
    if key not in _PG_BIN:
        _PG_BIN[key] = resolve_pg_bin(server_major(admin_url))
    return _PG_BIN[key]


def _pg(admin_url: URL, tool: str, *args: str, stdin: bytes | None = None) -> bytes:
    environ = {**os.environ, "PGPASSWORD": admin_url.password or "", "PGCONNECT_TIMEOUT": "10"}
    conn = [
        "-h",
        admin_url.host or "127.0.0.1",
        "-p",
        str(admin_url.port or 5432),
        "-U",
        admin_url.username or "",
    ]
    done = subprocess.run(
        [str(pg_bin(admin_url) / tool), *conn, *args],
        input=stdin,
        env=environ,
        capture_output=True,
        check=False,
    )
    assert done.returncode == 0, f"{tool} failed: {done.stderr.decode(errors='replace')}"
    return done.stdout


def dump(admin_url: URL, db: str, out: Path) -> None:
    """The backup step of the procedure: a custom-format dump (schema, data, grants, triggers, sequences)."""
    _pg(admin_url, "pg_dump", "-d", db, "-Fc", "-f", str(out))
    assert b"audit_event" in _pg(admin_url, "pg_restore", "-l", str(out))  # the archive is readable


def restore(admin_url: URL, archive: Path, db: str) -> None:
    """The restore steps of the procedure (``make restore``): the database from create-database.sql, a
    one-transaction restore, then every restored browser session ended."""
    _pg(admin_url, "psql", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-v", f"dbname={db}",
        stdin=CREATE_DB_SQL.read_bytes())  # fmt: skip
    _pg(admin_url, "pg_restore", "-d", db, "--exit-on-error", "--single-transaction", str(archive))
    _pg(admin_url, "psql", "-d", db, "-v", "ON_ERROR_STOP=1", "-c", "DELETE FROM auth_session")


def migrate_head(admin_url: URL, db: str, secrets_dir: Path) -> None:
    mig = settings_for("migrate", admin_url, db, secrets_dir)
    command.upgrade(alembic_config(mig.migrations_dir, mig.db_url()), "head")


@pytest.fixture
def new_db(admin_url: URL) -> Iterator[list[str]]:
    """Names of databases a test creates through the restore procedure; dropped afterwards."""
    names: list[str] = []
    yield names
    eng = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        for n in names:
            c.execute(text(f"DROP DATABASE IF EXISTS {n} WITH (FORCE)"))
    eng.dispose()


def _name() -> str:
    return f"ovlm_r_{uuid.uuid4().hex[:8]}"


# --- what must survive a backup ---------------------------------------------------------------------------------


def _fingerprint(admin_url: URL, db: str) -> dict[str, Any]:
    """Owners, privileges, triggers, functions and the fencing sequence: everything the security model rests on."""
    eng = create_engine(admin_url.set(database=db))
    q = {
        "triggers": "SELECT c.relname, t.tgname, t.tgenabled, pg_get_triggerdef(t.oid) FROM pg_trigger t "
        "JOIN pg_class c ON c.oid = t.tgrelid WHERE NOT t.tgisinternal ORDER BY 1, 2",
        "relations": "SELECT relname, relkind, pg_get_userbyid(relowner), relacl::text FROM pg_class "
        "WHERE relnamespace = 'public'::regnamespace ORDER BY 1",
        "columns": "SELECT c.relname, a.attname, a.attacl::text FROM pg_attribute a JOIN pg_class c ON c.oid = "
        "a.attrelid WHERE c.relnamespace = 'public'::regnamespace AND a.attacl IS NOT NULL ORDER BY 1, 2",
        "functions": "SELECT proname, prosecdef, proconfig::text, proacl::text, pg_get_userbyid(proowner) "
        "FROM pg_proc WHERE pronamespace = 'public'::regnamespace ORDER BY 1",
        "schema": "SELECT nspacl::text, pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'",
        "database": "SELECT datacl::text, pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()",
        "fencing": "SELECT last_value, is_called FROM fencing_seq",
    }
    with eng.connect() as c:
        out = {k: [tuple(r) for r in c.execute(text(v)).all()] for k, v in q.items()}
    eng.dispose()
    return out


def _guards_refuse(owner: Engine) -> None:
    """The append-only triggers still refuse, even for the table owner (they catch mis-grants)."""
    for stmt in (
        "UPDATE audit_event SET action = 'x'",
        "DELETE FROM audit_event",
        "TRUNCATE audit_event",
        "UPDATE run_downtime SET kind = 'restore'",
        "DELETE FROM run_downtime",
    ):
        with pytest.raises(DBAPIError, match="append-only|not allowed|refused"), owner.begin() as c:
            c.execute(text(stmt))


def _seed_downtime(owner: Engine) -> str:
    """A finished renewal run with its closed downtime interval (append-only table)."""
    run = str(uuid.uuid4())
    with owner.begin() as c:
        c.execute(
            text(
                "INSERT INTO workflow_run (id, kind, strategy, strategy_version, state, phase, started_at, "
                "finished_at, downtime_started_at, downtime_ended_at) VALUES (:r, 'renewal', 'blue_green', '1', "
                "'completed', 'retire', now() - interval '2 hours', now(), now() - interval '90 minutes', "
                "now() - interval '80 minutes')"
            ),
            {"r": run},
        )
        c.execute(
            text(
                "INSERT INTO run_downtime (id, run_id, kind, started_at, started_by_step, ended_at, ended_by_step) "
                "VALUES (gen_random_uuid(), :r, 'window', now() - interval '90 minutes', 'quiesce_old', "
                "now() - interval '80 minutes', 'verify_external')"
            ),
            {"r": run},
        )
    return run


def _worker_store(
    admin_url: URL, db: str, keyring: Keyring, tmp: Path
) -> tuple[Engine, CredentialStore]:
    eng = create_engine(role_url(admin_url, db, "ovlm_worker", WORKER_PW))
    return eng, CredentialStore(eng, keyring, tmp / f"ca-{db}")


def _cli_env(
    monkeypatch: pytest.MonkeyPatch, admin_url: URL, db: str, secrets_dir: Path, **extra: str
) -> None:
    for k, v in {
        "OVLM_CONFIG_FILE": str(secrets_dir / "absent.toml"),
        "OVLM_DEVELOPMENT_MODE": "true",
        "OVLM_DB__HOST": admin_url.host or "127.0.0.1",
        "OVLM_DB__PORT": str(admin_url.port or 5432),
        "OVLM_DB__NAME": db,
        "OVLM_DB__SSLMODE": "disable",
        "OVLM_DB__PASSWORD_FILE": str(secrets_dir / "api"),
        "OVLM_MIGRATIONS_DIR": str(ROOT / "migrations"),
        **extra,
    }.items():
        monkeypatch.setenv(k, v)


# --- tests ------------------------------------------------------------------------------------------------------


def test_dump_restore_migrate_keeps_credentials_audit_privileges_and_guards(
    env: Env,
    admin_url: URL,
    secrets_dir: Path,
    tmp_path: Path,
    new_db: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    st = Store(env, tmp_path)
    pc = st.connection()
    # an active write credential and SSH key, sealed to the KEK; audit rows; a TOTP-enrolled admin
    _ready(st, pc)
    run = _seed_downtime(env.owner)
    audit_before = env.sql("SELECT * FROM audit_event ORDER BY id")
    assert len(audit_before) >= 5
    before = _fingerprint(admin_url, env.db)

    archive = tmp_path / "ovlm.dump"
    dump(admin_url, env.db, archive)
    st.worker_engine.dispose()

    restored = _name()
    new_db.append(restored)
    restore(admin_url, archive, restored)
    migrate_head(admin_url, restored, secrets_dir)
    owner = make_engine(settings_for("migrate", admin_url, restored, secrets_dir))
    assert current_revision(owner) == head_revision(ROOT / "migrations")

    # privileges, owners, triggers, functions, database ACL and the fencing sequence are those of the original
    after = _fingerprint(admin_url, restored)
    assert after == before
    datacl = after["database"][0][0]  # NULL would mean the default: PUBLIC may connect
    assert datacl is not None and not any(a.startswith("=") for a in datacl.strip("{}").split(","))

    # audit rows are byte-identical, the downtime interval is there, and the append-only guards still refuse
    with owner.connect() as c:
        assert [tuple(r) for r in c.execute(text("SELECT * FROM audit_event ORDER BY id"))] == [
            tuple(r) for r in audit_before
        ]
        assert (
            c.execute(
                text("SELECT count(*) FROM run_downtime WHERE run_id = :r"), {"r": run}
            ).scalar()
            == 1
        )
    _guards_refuse(owner)

    # the same KEK decrypts the credential; another KEK does not
    eng, store = _worker_store(admin_url, restored, st.keyring, tmp_path)
    creds = StoreCredentialSource(store).for_project(pc)
    assert creds is not None and creds.write.application_credential_secret == CANARY
    assert creds.write.application_credential_id == APP_W
    other = Keyring(_load(generate_private_pem()))
    eng2, store2 = _worker_store(admin_url, restored, other, tmp_path)
    with eng2.begin() as c:
        announce_keys(c, other.current_kek_id, other.kek_ids)
    with pytest.raises(CredentialUnavailableError):
        StoreCredentialSource(store2).for_project(pc)
    eng.dispose()
    eng2.dispose()

    # ovlm backup check: the keys of the backup pass, a wrong KEK or TOTP key is refused (api role, no private key)
    api_eng = create_engine(role_url(admin_url, restored, "ovlm_api", API_PW))
    totp_key = Path(str(env.settings.auth.totp_key_file))
    with api_eng.connect() as c:
        ok = backup_findings(
            c, frozenset({st.keyring.current_kek_id}), TotpVault.from_file(totp_key)
        )
        assert exit_code(ok) == 0, ok
        wrong = backup_findings(
            c, frozenset({other.current_kek_id}), TotpVault(Fernet.generate_key().decode())
        )
    api_eng.dispose()
    assert {f.code for f in wrong if f.level == "block"} == {"kek-missing", "totp-key-mismatch"}
    pub = tmp_path / "kek.pub"  # written by Store: the public key of the backup's KEK
    _cli_env(monkeypatch, admin_url, restored, secrets_dir,
             OVLM_KEK__PUBLIC_KEY_FILE=str(pub), OVLM_AUTH__TOTP_KEY_FILE=str(totp_key))  # fmt: skip
    capsys.readouterr()
    assert ovlm_main(["backup", "check"]) == 0
    out = capsys.readouterr().out
    assert f"kek_id_given\t{st.keyring.current_kek_id}" in out and "backup check OK" in out
    assert f"schema_revision\t{head_revision(ROOT / 'migrations')}" in out
    other_pub = tmp_path / "other.pub"
    other_pub.write_bytes(public_pem_of(generate_private_pem()))
    assert ovlm_main(["backup", "check", "--kek-public", str(other_pub)]) == 2
    assert "BLOCK\tkek-missing" in capsys.readouterr().out

    # the api serves the restored database to the same admin (password + the restored, still encrypted TOTP)
    settings = env.settings.model_copy(
        update={"db": env.settings.db.model_copy(update={"name": restored})}
    )
    app = create_app(settings, probe=_Probe(), start_metrics_server=False)
    client = TestClient(app, base_url=ORIGIN)
    env.clock.advance(60)
    r = env.api_login(client, "root", PASSWORD, st.totp)
    assert r.status_code == 200, r.text
    r = client.get("/api/v1/project-connections", headers=env.headers(client))
    assert r.status_code == 200 and pc in r.text
    app.state.auth_engine.dispose()

    # only the three roles may connect to the restored database
    _assert_stranger_refused(admin_url, restored)
    owner.dispose()


def test_dump_of_an_older_revision_restores_and_migrates_to_the_guards_of_a_fresh_install(
    admin_url: URL, fresh_db: str, secrets_dir: Path, tmp_path: Path, new_db: list[str]
) -> None:
    mig = settings_for("migrate", admin_url, fresh_db, secrets_dir)
    command.upgrade(alembic_config(mig.migrations_dir, mig.db_url()), "renewal_0003")
    owner = make_engine(mig)
    with owner.begin() as c:
        c.execute(text("INSERT INTO audit_event (principal_type, auth_method, action, target_type, result) "
                       "VALUES ('system', 'none', 'test.before_upgrade', 'test', 'success')"))  # fmt: skip
    _seed_downtime(owner)
    owner.dispose()
    archive = tmp_path / "old.dump"
    dump(admin_url, fresh_db, archive)

    restored, reference = _name(), _name()
    new_db.extend([restored, reference])
    restore(admin_url, archive, restored)
    migrate_head(admin_url, restored, secrets_dir)  # the upgrade after a restore of an older backup
    _pg(admin_url, "psql", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-v", f"dbname={reference}",
        stdin=CREATE_DB_SQL.read_bytes())  # fmt: skip
    migrate_head(admin_url, reference, secrets_dir)  # a fresh install of this release

    got, want = _fingerprint(admin_url, restored), _fingerprint(admin_url, reference)
    for k in ("triggers", "relations", "columns", "functions", "schema", "database"):
        assert got[k] == want[k], k
    eng = make_engine(settings_for("migrate", admin_url, restored, secrets_dir))
    with eng.connect() as c:
        assert (
            c.execute(
                text("SELECT count(*) FROM audit_event WHERE action = 'test.before_upgrade'")
            ).scalar()
            == 1
        )
    _guards_refuse(eng)
    eng.dispose()


def test_upgrade_preflight_refuses_during_a_window_and_until_the_worker_is_stopped(
    env: Env,
    admin_url: URL,
    secrets_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    api = create_engine(
        role_url(admin_url, env.db, "ovlm_api", API_PW)
    )  # the preflight needs SELECT only

    def findings(worker_stopped: bool = False) -> dict[str, str]:
        with api.connect() as c:
            fs = runtime_findings(c, worker_stopped=worker_stopped, live_worker_age=15,
                                  planned_window_horizon=timedelta(hours=2))  # fmt: skip
        return {f.code: f.level for f in fs}

    assert exit_code([]) == 0
    assert "outage-in-progress" not in findings()

    run = str(uuid.uuid4())
    env.sql(
        "INSERT INTO workflow_run (id, kind, strategy, strategy_version, state, phase, started_at, admitted_at, "
        "downtime_started_at) VALUES (:r, 'renewal', 'blue_green', '1', 'running', 'window', now(), now(), now())",
        r=run,
    )
    env.sql(
        "INSERT INTO run_downtime (id, run_id, kind, started_at, started_by_step) "
        "VALUES (gen_random_uuid(), :r, 'window', now(), 'quiesce_old')",
        r=run,
    )
    assert findings()["outage-in-progress"] == "block"

    _cli_env(monkeypatch, admin_url, env.db, secrets_dir)
    capsys.readouterr()
    assert ovlm_main(["upgrade", "preflight"]) == 2
    out = capsys.readouterr().out
    assert (
        f"BLOCK\toutage-in-progress\trun {run} is in phase window" in out
        and "preflight REFUSED" in out
    )
    assert "INFO\tschema-at-head" in out

    # parked in the window (needs_human) still blocks; so does a restore
    env.sql("UPDATE workflow_run SET state = 'needs_human', needs_human_reason = 'post_start_failure' WHERE id = :r",
            r=run)  # fmt: skip
    assert findings()["outage-in-progress"] == "block"
    env.sql("UPDATE workflow_run SET phase = 'restore' WHERE id = :r", r=run)
    assert findings()["outage-in-progress"] == "block"

    # the phase moved on but the downtime interval is still open (service not back yet): still refused
    env.sql("UPDATE workflow_run SET phase = 'retained', state = 'running', needs_human_reason = NULL WHERE id = :r",
            r=run)  # fmt: skip
    f = findings()
    assert "outage-in-progress" not in f and f["downtime-open"] == "block"

    # the window closed: allowed, with a warning that the run resumes after the upgrade
    env.sql(
        "UPDATE run_downtime SET ended_at = now(), ended_by_step = 'verify_external' WHERE run_id = :r",
        r=run,
    )
    f = findings()
    assert f == {"runs-active": "warn", "no-live-worker": "info"}, f
    assert ovlm_main(["upgrade", "preflight"]) == 0
    assert "preflight OK" in capsys.readouterr().out

    # a worker still beating and a step under lease: fine before the stop, refused with --worker-stopped
    env.sql(
        "INSERT INTO worker_heartbeat (worker_id, hostname, version) VALUES ('w-1', 'h', 'test')"
    )
    env.sql(
        "INSERT INTO workflow_step (id, run_id, seq, step_key, state, lease_owner, lease_expires_at, fencing_token) "
        "VALUES (gen_random_uuid(), :r, 1, 'retain_old', 'running', 'w-1', now() + interval '1 minute', 1)",
        r=run,
    )
    f = findings()
    assert f["worker-live"] == "info" and f["step-leased"] == "info"
    f = findings(worker_stopped=True)
    assert f["worker-live"] == "block" and f["step-leased"] == "block"
    assert ovlm_main(["upgrade", "preflight", "--worker-stopped"]) == 2
    out = capsys.readouterr().out
    assert "BLOCK\tworker-live" in out and "BLOCK\tstep-leased" in out

    # the worker stopped (last beat old) and the lease expired: allowed
    env.sql("UPDATE worker_heartbeat SET last_seen_at = now() - interval '5 minutes'")
    env.sql(
        "UPDATE workflow_step SET lease_expires_at = now() - interval '1 second' WHERE run_id = :r",
        r=run,
    )
    assert exit_code_of(findings(worker_stopped=True)) == 0
    assert ovlm_main(["upgrade", "preflight", "--worker-stopped"]) == 0

    # a database migrated by a newer release: refused (no downgrade), whatever the runs do
    env.sql("UPDATE alembic_version SET version_num = 'zz_from_a_newer_release'")
    assert ovlm_main(["upgrade", "preflight", "--worker-stopped"]) == 2
    assert "BLOCK\tdatabase-ahead" in capsys.readouterr().out
    api.dispose()


def exit_code_of(levels: dict[str, str]) -> int:
    return 2 if "block" in levels.values() else 0


def _load(pem: bytes) -> Any:
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_private_key(pem, password=None)


def _assert_stranger_refused(admin_url: URL, db: str) -> None:
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        if not c.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'ovlm_stranger'")).scalar():
            c.execute(text("CREATE ROLE ovlm_stranger LOGIN PASSWORD 'x'"))
    admin.dispose()
    stranger = create_engine(admin_url.set(username="ovlm_stranger", password="x", database=db))
    with pytest.raises(Exception, match="permission denied"), stranger.connect():
        pass
    stranger.dispose()
