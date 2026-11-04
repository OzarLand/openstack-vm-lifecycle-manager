"""``ovlm`` command: ``api``, ``worker``, ``migrate`` (architecture.md section 4) and ``admin create`` (bootstrap).

There are deliberately no secret-bearing options: secrets are read from the files named in the settings.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from ovlm import __version__
from ovlm.config import Settings
from ovlm.observability.logging import configure_logging

log = logging.getLogger("ovlm.cli")


def _run_api() -> int:
    import uvicorn

    from ovlm.api.app import create_app

    settings = Settings(process_role="api")
    configure_logging("api", settings.log.level)
    # One uvicorn worker: /metrics is per process (no multiprocess mode yet).
    uvicorn.run(
        create_app(settings),
        host=settings.http.host,
        port=settings.http.port,
        log_config=None,
        access_log=False,
        server_header=False,
    )
    return 0


def _run_worker() -> int:
    from ovlm.worker.main import run

    return run()


def _run_migrate() -> int:
    from alembic import command

    from ovlm.db.schema import alembic_config

    settings = Settings(process_role="migrate")
    configure_logging("migrate", settings.log.level)
    log.info("running migrations", extra={"db_role": settings.db_role})
    command.upgrade(alembic_config(settings.migrations_dir), "head")
    log.info("migrations complete")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args_in = list(sys.argv[1:] if argv is None else argv)
    if args_in[:1] == ["admin"]:  # `ovlm admin create ...` (bootstrap); see ovlm.auth.cli
        from ovlm.auth.cli import admin_main

        return admin_main(args_in[1:])
    if args_in[:1] == ["inventory"]:  # `ovlm inventory sync --cloud <name>` (E2-2); own sub-parser
        from ovlm.inventory.cli import main as inventory_main

        try:
            return inventory_main(args_in[1:])
        except Exception as exc:  # noqa: BLE001 - last-resort handler for the process
            logging.getLogger("ovlm.cli").error("fatal: %s", exc, exc_info=True)
            return 1
    parser = argparse.ArgumentParser(prog="ovlm", description="OpenStack VM Lifecycle Manager")
    parser.add_argument("--version", action="version", version=f"ovlm {__version__}")
    parser.add_argument("command", choices=["api", "worker", "migrate"])
    args = parser.parse_args(args_in)
    runners = {"api": _run_api, "worker": _run_worker, "migrate": _run_migrate}
    try:
        return runners[args.command]()
    except Exception as exc:  # noqa: BLE001 - last-resort handler for the process
        logging.getLogger("ovlm.cli").error("fatal: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
