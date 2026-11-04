"""Engine and session factory. Each process connects with its own DB role (data-model.md section 12)."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from ovlm.config import Settings


def pool_options(settings: Settings) -> dict[str, float | int]:
    """Pool sizing (SRE-C-4).

    The worker runs up to ``worker.slots`` steps at once; each needs a heartbeat connection plus short checkpoint
    and read connections, and the loop needs one more for signals, admission and claims. The pool is therefore
    ``2 x slots + 4`` with ``slots`` overflow, and a checkout waits at most ``fence_margin / 2`` (>= 1 s): a starved
    heartbeat fails fast as "ownership unknown" well before the fence deadline instead of hanging for 30 s.
    """
    if settings.process_role == "worker":
        slots = settings.worker.slots
        return {
            "pool_size": 2 * slots + 4,
            "max_overflow": slots,
            "pool_timeout": max(1.0, settings.worker.fence_margin / 2),
        }
    return {"pool_size": 5, "max_overflow": 5}


def make_engine(settings: Settings) -> Engine:
    """Engine for ``settings.process_role`` using the role's password file."""
    return create_engine(
        settings.db_url(),
        pool_pre_ping=True,
        connect_args={"application_name": f"ovlm-{settings.process_role}"},
        **pool_options(settings),
    )


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
