"""``ovlm inventory sync --cloud <name>``: run one inventory sync from a ``clouds.yaml`` entry.

Meant for the read-only lab run against a real cloud (E2-4) and as the worker-side entry point until the
workflow engine calls ``run_inventory_sync`` itself (see ``sync.py``). Output is one JSON object on stdout:
counts and microversions only, never names, addresses or credentials. Logs go to stderr.

* ``--dry-run``: read the cloud (token request + GET only, through the read-only hook), print the counts, write
  nothing and need no database.
* default: also write to the database as the worker role (``Settings(process_role="worker")``).

The ``project_connection`` table is not built yet, so ``project_connection_id`` is derived from the cloud name and
the project id the token is scoped to (UUIDv5). When project connections exist, the worker passes the real id.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Literal, cast

from sqlalchemy import Engine

from ovlm.inventory.sync import SyncConfig, SyncKind, _fetch_full, run_inventory_sync
from ovlm.openstack.interface import ReadClient

_NAMESPACE = uuid.UUID("6f0e3f0a-7c5b-4a43-8f55-6c0b6a5d0c11")  # fixed: ids stay stable across runs

log = logging.getLogger("ovlm.inventory.cli")


def project_connection_id_for(cloud: str, project_id: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, f"{cloud}:{project_id}")


def sync_command(
    client: ReadClient,
    *,
    cloud: str,
    engine: Engine | None,
    kind: SyncKind | Literal["auto"] = "auto",
    config: SyncConfig | None = None,
) -> tuple[int, dict[str, object]]:
    """Run the sync (or, without ``engine``, a dry run). Returns ``(exit_code, result_json)``."""
    project_id = client.project_id()
    versions = client.negotiated_versions()
    pc_id = project_connection_id_for(cloud, project_id)
    out: dict[str, object] = {
        "cloud": cloud,
        "project_id": project_id,
        "project_connection_id": str(pc_id),
        "versions": versions.as_json(),
    }
    if engine is None:
        fetched = _fetch_full(client)
        out |= {
            "dry_run": True,
            "status": "read_ok",
            "counts": {k: len(v) for k, v in fetched.items()},
        }
        return 0, out
    result = run_inventory_sync(engine, client, pc_id, kind=kind, config=config)
    out |= {
        "dry_run": False,
        "sync_run_id": str(result.sync_run_id),
        "kind": result.kind,
        "status": result.status,
        "counts": result.counts,
        "error": result.error,
    }
    return (0 if result.status == "succeeded" else 1), out


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="ovlm inventory", description="Inventory commands")
    sub = parser.add_subparsers(dest="action", required=True)
    sync = sub.add_parser("sync", help="sync one OpenStack project into the inventory")
    sync.add_argument("--cloud", required=True, help="entry name in clouds.yaml")
    sync.add_argument(
        "--clouds-yaml", type=Path, help="path to clouds.yaml (default: the SDK search path)"
    )
    sync.add_argument("--kind", choices=["auto", "full", "servers_delta"], default="auto")
    sync.add_argument(
        "--dry-run", action="store_true", help="read only; write nothing, no database needed"
    )
    args = parser.parse_args(list(argv))

    from ovlm.config import Settings
    from ovlm.db.engine import make_engine
    from ovlm.observability.logging import configure_logging
    from ovlm.openstack.sdk_read import connect_read_only

    configure_logging("inventory-cli", "INFO", stream=sys.stderr)
    client = connect_read_only(args.cloud, args.clouds_yaml)
    engine = None if args.dry_run else make_engine(Settings(process_role="worker"))
    try:
        code, out = sync_command(
            client,
            cloud=args.cloud,
            engine=engine,
            kind=cast(SyncKind | Literal["auto"], args.kind),
        )
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps(out, indent=2, sort_keys=True))  # noqa: T201 - the command's result
    return code
