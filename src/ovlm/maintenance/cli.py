"""``ovlm upgrade preflight`` and ``ovlm backup check`` (docs/backup-restore-upgrade.md). Read-only.

* ``ovlm upgrade preflight [--worker-stopped] [--planned-window-hours H]``: run with the **new** release (its
  migrations decide the direction) before ``ovlm migrate``. Exit 2 (refused) while a renewal is in its downtime
  window or a restore, when the database is ahead of this release or off its history (a downgrade), and, with
  ``--worker-stopped``, while a worker still beats or a step still holds a lease. Exit 0 otherwise; warnings
  (runs outside the window that will resume, a planned window soon) do not refuse.
* ``ovlm backup check [--kek-public FILE ...]``: before a backup and after a restore. Prints the manifest of the
  database (schema revision, KEK ids in use, TOTP check). Exit 2 when a sealed secret in use is wrapped to a key
  whose public key was not given (default: ``kek.public_key_file``), or when a stored TOTP secret does not decrypt
  with ``auth.totp_key_file``. It loads no private key; ``ovlm kek status`` in the worker proves the private key.

Both connect with the settings of ``--role`` (default ``api``: SELECT is enough). Lines are
``LEVEL<TAB>code<TAB>message``. Exit 1: the checks could not run (no database, bad settings).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from ovlm import __version__

if TYPE_CHECKING:
    from ovlm.config import Settings


def _settings(role: str) -> Settings:
    from ovlm.config import Settings

    return Settings(process_role="migrate" if role == "migrate" else "api")


def _print(lines: Sequence[str]) -> None:
    for line in lines:
        sys.stdout.write(line + "\n")


def _preflight(args: argparse.Namespace) -> int:
    from alembic.script import ScriptDirectory

    from ovlm.db.engine import make_engine
    from ovlm.db.schema import alembic_config, current_revision
    from ovlm.maintenance.checks import exit_code, migration_findings, runtime_findings

    settings = _settings(args.role)
    engine = make_engine(settings)
    try:
        script = ScriptDirectory.from_config(alembic_config(settings.migrations_dir))
        findings = migration_findings(current_revision(engine), script)
        with engine.connect() as conn:
            findings += runtime_findings(
                conn,
                worker_stopped=args.worker_stopped,
                live_worker_age=3 * settings.worker.heartbeat_interval,
                planned_window_horizon=timedelta(hours=args.planned_window_hours),
            )
    finally:
        engine.dispose()
    _print([f"release\t{__version__}"] + [f.line() for f in findings])
    code = exit_code(findings)
    _print(["preflight REFUSED" if code else "preflight OK"])
    return code


def _backup_check(args: argparse.Namespace) -> int:
    from ovlm.auth.totp import TotpUnavailableError, TotpVault
    from ovlm.db.engine import make_engine
    from ovlm.db.schema import current_revision
    from ovlm.maintenance.checks import backup_findings, exit_code
    from ovlm.secrets.envelope import load_public_key

    settings = _settings(args.role)
    files: list[Path] = list(args.kek_public or [])
    if not files and settings.kek.public_key_file is not None:
        files = [settings.kek.public_key_file]
    kek_ids = frozenset(load_public_key(p).kek_id for p in files)
    vault: TotpVault | None
    try:
        vault = TotpVault.from_file(settings.auth.totp_key_file)
    except (TotpUnavailableError, OSError):
        vault = None
    engine = make_engine(settings)
    try:
        revision = current_revision(engine)
        with engine.connect() as conn:
            findings = backup_findings(conn, kek_ids, vault)
    finally:
        engine.dispose()
    _print(
        [f"release\t{__version__}", f"schema_revision\t{revision or 'none'}"]
        + [f"kek_id_given\t{k}" for k in sorted(kek_ids)]
        + [f.line() for f in findings]
    )
    code = exit_code(findings)
    _print(["backup check REFUSED" if code else "backup check OK"])
    return code


def _role(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--role",
        choices=["api", "migrate"],
        default="api",
        help="settings and database role to connect with (default api: read-only is enough)",
    )


def upgrade_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="ovlm upgrade", description="Upgrade checks (read-only)")
    sub = parser.add_subparsers(dest="action", required=True)
    pre = sub.add_parser("preflight", help="refuse an upgrade mid-window or in the wrong direction")
    pre.add_argument(
        "--worker-stopped",
        action="store_true",
        help="the worker was stopped: also refuse while a worker beats or a step holds a lease",
    )
    pre.add_argument(
        "--planned-window-hours",
        type=float,
        default=2.0,
        help="warn about approved plans whose planned window starts within this many hours (default 2)",
    )
    _role(pre)
    args = parser.parse_args(list(argv))
    return _guard(_preflight, args)


def backup_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="ovlm backup", description="Backup checks (read-only)")
    sub = parser.add_subparsers(dest="action", required=True)
    chk = sub.add_parser(
        "check", help="manifest; refuse when the keys on hand cannot restore the database"
    )
    chk.add_argument(
        "--kek-public",
        type=Path,
        action="append",
        help="a KEK public key that will be kept with this backup (repeatable; default kek.public_key_file)",
    )
    _role(chk)
    args = parser.parse_args(list(argv))
    return _guard(_backup_check, args)


def _guard(fn: Callable[[argparse.Namespace], int], args: argparse.Namespace) -> int:
    try:
        return fn(args)
    except Exception as exc:  # noqa: BLE001 - a check that cannot run is exit 1, never a pass
        sys.stderr.write(f"error: {exc}\n")
        return 1
