"""Schema version checks: api and worker refuse to run when the DB is not at Alembic head."""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, text
from sqlalchemy.engine import URL


class SchemaNotAtHeadError(RuntimeError):
    pass


def alembic_config(migrations_dir: Path, url: URL | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(migrations_dir))
    if url is not None:
        cfg.attributes["url"] = url
    return cfg


def head_revision(migrations_dir: Path) -> str:
    head = ScriptDirectory.from_config(alembic_config(migrations_dir)).get_current_head()
    if head is None:
        raise RuntimeError("no migration scripts found")
    return head


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as conn:
        exists = conn.execute(
            text("SELECT to_regclass('alembic_version') IS NOT NULL")
        ).scalar_one()
        if not exists:
            return None
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()


def check_schema_at_head(engine: Engine, migrations_dir: Path) -> None:
    current, head = current_revision(engine), head_revision(migrations_dir)
    if current != head:
        raise SchemaNotAtHeadError(
            f"database schema is at {current or 'nothing'} but this release needs {head}; "
            "run `ovlm migrate` (the migrate service) before starting api/worker"
        )
