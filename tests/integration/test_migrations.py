from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import ProgrammingError

from ovlm.api.app import create_app
from ovlm.api.health import DbReadinessProbe
from ovlm.db.engine import make_engine
from ovlm.db.schema import (
    SchemaNotAtHeadError,
    alembic_config,
    check_schema_at_head,
    current_revision,
    head_revision,
)
from tests.integration.conftest import ROOT, settings_for


def migrate(admin_url: URL, db: str, secrets_dir: Path) -> None:
    s = settings_for("migrate", admin_url, db, secrets_dir)
    command.upgrade(alembic_config(s.migrations_dir, s.db_url()), "head")


def test_baseline_creates_roles_and_schema_meta(
    admin_url: URL, fresh_db: str, secrets_dir: Path
) -> None:
    migrate(admin_url, fresh_db, secrets_dir)
    owner = make_engine(settings_for("migrate", admin_url, fresh_db, secrets_dir))
    with owner.connect() as c:
        assert (
            c.execute(text("SELECT value FROM schema_meta WHERE key='schema_family'")).scalar()
            == "ovlm"
        )
        attrs = c.execute(
            text(
                "SELECT rolname, rolsuper, rolcreatedb, rolreplication, rolbypassrls, rolcanlogin "
                "FROM pg_roles WHERE rolname IN ('ovlm_owner','ovlm_api','ovlm_worker') ORDER BY 1"
            )
        ).all()
        tbl_owner = c.execute(
            text("SELECT tableowner FROM pg_tables WHERE tablename='schema_meta'")
        ).scalar()
    assert [r[0] for r in attrs] == ["ovlm_api", "ovlm_owner", "ovlm_worker"]
    for _, sup, createdb, repl, bypass, login in attrs:
        assert (sup, createdb, repl, bypass, login) == (False, False, False, False, True)
    assert tbl_owner == "ovlm_owner"
    owner.dispose()


def test_migration_is_idempotent_across_databases(
    admin_url: URL, fresh_db: str, secrets_dir: Path
) -> None:
    migrate(admin_url, fresh_db, secrets_dir)
    migrate(admin_url, fresh_db, secrets_dir)  # second run is a no-op
    eng = make_engine(settings_for("migrate", admin_url, fresh_db, secrets_dir))
    assert current_revision(eng) == head_revision(ROOT / "migrations")
    eng.dispose()


@pytest.mark.parametrize("role", ["api", "worker"])
def test_runtime_roles_are_read_only_on_schema_meta(
    admin_url: URL, fresh_db: str, secrets_dir: Path, role: str
) -> None:
    migrate(admin_url, fresh_db, secrets_dir)
    eng = make_engine(settings_for(role, admin_url, fresh_db, secrets_dir))
    with eng.connect() as c:
        assert c.execute(text("SELECT count(*) FROM schema_meta")).scalar() == 1
        assert c.execute(text("SELECT current_user")).scalar() == f"ovlm_{role}"
    for stmt in (
        "INSERT INTO schema_meta VALUES ('x','y')",
        "UPDATE schema_meta SET value='z'",
        "DELETE FROM schema_meta",
        "CREATE TABLE evil (id int)",
        "DROP TABLE schema_meta",
        "UPDATE alembic_version SET version_num='x'",
    ):
        with eng.connect() as c, pytest.raises(ProgrammingError):
            c.execute(text(stmt))
    eng.dispose()


def test_public_cannot_connect(
    admin_url: URL, fresh_db: str, secrets_dir: Path, cluster_roles: None
) -> None:
    migrate(admin_url, fresh_db, secrets_dir)
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        known = c.execute(text("SELECT 1 FROM pg_roles WHERE rolname='ovlm_stranger'")).scalar()
        if not known:
            c.execute(text("CREATE ROLE ovlm_stranger LOGIN PASSWORD 'x'"))
    admin.dispose()
    stranger = create_engine(
        admin_url.set(username="ovlm_stranger", password="x", database=fresh_db)
    )
    with pytest.raises(Exception, match="permission denied"), stranger.connect():
        pass


def test_schema_head_check_and_readyz(admin_url: URL, fresh_db: str, secrets_dir: Path) -> None:
    from fastapi.testclient import TestClient

    api_settings = settings_for("api", admin_url, fresh_db, secrets_dir)
    # Before the migration: connecting as ovlm_api works (CONNECT is only granted by the migration, so use
    # the owner for this negative check of the head comparison on an empty database).
    owner_eng = make_engine(settings_for("migrate", admin_url, fresh_db, secrets_dir))
    with pytest.raises(SchemaNotAtHeadError):
        check_schema_at_head(owner_eng, ROOT / "migrations")
    owner_eng.dispose()

    migrate(admin_url, fresh_db, secrets_dir)
    engine = make_engine(api_settings)
    check_schema_at_head(engine, api_settings.migrations_dir)
    app = create_app(api_settings, probe=DbReadinessProbe(engine, api_settings.migrations_dir),
                     start_metrics_server=False)  # fmt: skip
    r = TestClient(app).get("/readyz")
    assert r.status_code == 200, r.text
    assert r.json()["checks"] == {"database": "ok", "schema": "ok"}
    engine.dispose()


def test_readyz_503_when_database_unreachable(secrets_dir: Path) -> None:
    from fastapi.testclient import TestClient

    from ovlm.config import Settings

    s = Settings(
        process_role="api",
        development_mode=True,
        db={
            "host": "127.0.0.1",
            "port": 1,
            "sslmode": "disable",
            "password_file": secrets_dir / "api",
        },
        migrations_dir=ROOT / "migrations",
    )
    engine = make_engine(s)
    app = create_app(
        s, probe=DbReadinessProbe(engine, s.migrations_dir), start_metrics_server=False
    )
    r = TestClient(app).get("/readyz")
    assert r.status_code == 503
    assert r.json()["checks"]["database"] == "database unreachable"
    assert "api" not in r.text.replace("database", "")  # no password or role detail leaks
    engine.dispose()
