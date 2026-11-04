"""Integration fixtures: a real PostgreSQL.

``OVLM_TEST_DATABASE_URL`` (superuser URL, e.g. the CI service container) is used when set. Otherwise a
throw-away ``postgres`` container is started with Docker for the test session. There is no silent skip: with
neither available the tests error, so a green run always means PostgreSQL really ran.
"""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

from ovlm.config import Settings

PG_IMAGE = os.environ.get("OVLM_TEST_PG_IMAGE", "postgres:16-bookworm")
ROOT = Path(__file__).parents[2]
OWNER_PW, API_PW, WORKER_PW = "owner-pw-test", "api-pw-test", "worker-pw-test"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "integration" in item.nodeid.split("/"):
            item.add_marker(pytest.mark.integration)


def _start_container() -> Iterator[URL]:
    name = f"ovlm-test-pg-{uuid.uuid4().hex[:8]}"
    try:
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_PASSWORD=admin-pw-test",
             "-p", "127.0.0.1::5432", PG_IMAGE],
            check=True, capture_output=True, text=True,
        )  # fmt: skip
    except (OSError, subprocess.CalledProcessError) as exc:
        pytest.fail(
            f"no PostgreSQL available: set OVLM_TEST_DATABASE_URL or make Docker usable ({exc})",
            pytrace=False,
        )
    try:
        port = subprocess.run(
            ["docker", "port", name, "5432/tcp"], check=True, capture_output=True, text=True
        ).stdout.splitlines()[0].rsplit(":", 1)[1]  # fmt: skip
        url = URL.create(
            "postgresql+psycopg", "postgres", "admin-pw-test", "127.0.0.1", int(port), "postgres"
        )
        _wait(url)
        yield url
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


def _wait(url: URL, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            with create_engine(url).connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


@pytest.fixture(scope="session")
def admin_url() -> Iterator[URL]:
    env = os.environ.get("OVLM_TEST_DATABASE_URL")
    if env:
        url = make_url(env)
        _wait(url)
        yield url
    else:
        yield from _start_container()


@pytest.fixture(scope="session")
def cluster_roles(admin_url: URL) -> None:
    """What the Compose Postgres init script does: create the roles (with passwords) before the migration."""
    eng = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        for role, pw, extra in (
            ("ovlm_owner", OWNER_PW, "CREATEROLE"),
            ("ovlm_api", API_PW, ""),
            ("ovlm_worker", WORKER_PW, ""),
        ):
            exists = c.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname=:r"), {"r": role}
            ).scalar()
            verb = "ALTER" if exists else "CREATE"
            c.execute(text(f"{verb} ROLE {role} LOGIN {extra} PASSWORD '{pw}'"))
    eng.dispose()


@pytest.fixture
def fresh_db(admin_url: URL, cluster_roles: None) -> Iterator[str]:
    """An empty database owned by ovlm_owner (as the init script creates it)."""
    name = f"ovlm_t_{uuid.uuid4().hex[:8]}"
    eng = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text(f"CREATE DATABASE {name} OWNER ovlm_owner"))
    try:
        yield name
    finally:
        with eng.connect() as c:
            c.execute(text(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        eng.dispose()


def role_url(admin_url: URL, db: str, role: str, password: str) -> URL:
    return admin_url.set(username=role, password=password, database=db)


@pytest.fixture
def secrets_dir(tmp_path: Path) -> Path:
    for fname, pw in (("owner", OWNER_PW), ("api", API_PW), ("worker", WORKER_PW)):
        (tmp_path / fname).write_text(pw + "\n")
    return tmp_path


def settings_for(role: str, admin_url: URL, db: str, secrets_dir: Path) -> Settings:
    fname = {"migrate": "owner", "api": "api", "worker": "worker"}[role]
    return Settings(
        process_role=role,
        development_mode=True,  # test installation (no external_url unless a test sets it)
        db={
            "host": admin_url.host,
            "port": admin_url.port,
            "name": db,
            "sslmode": "disable",
            "password_file": secrets_dir / fname,
        },
        migrations_dir=ROOT / "migrations",
    )
