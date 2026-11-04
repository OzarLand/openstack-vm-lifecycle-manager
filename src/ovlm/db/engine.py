"""Engine and session factory. Each process connects with its own DB role (data-model.md section 12)."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from ovlm.config import Settings


def make_engine(settings: Settings) -> Engine:
    """Engine for ``settings.process_role`` using the role's password file."""
    return create_engine(
        settings.db_url(),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        connect_args={"application_name": f"ovlm-{settings.process_role}"},
    )


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
