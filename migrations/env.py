"""Alembic environment. Connects as ``ovlm_owner`` (process role ``migrate``)."""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

from ovlm.config import Settings

config = context.config
# No ORM metadata yet: domain tables arrive with their modules (autogenerate is not used for the baseline).
target_metadata = None


def _url() -> object:
    override = config.attributes.get("url")
    if override is not None:
        return override
    return Settings(process_role="migrate").db_url()


def run_migrations_online() -> None:
    connectable = create_engine(_url(), poolclass=pool.NullPool)  # type: ignore[arg-type]
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    raise SystemExit(
        "offline migrations are not supported (roles and grants need a live connection)"
    )
run_migrations_online()
