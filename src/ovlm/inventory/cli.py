"""``ovlm inventory sync --cloud <name> --dry-run``: read one project from a ``clouds.yaml`` entry, write nothing.

A lab and troubleshooting tool: it checks that a read application credential can list everything the inventory
needs (token request + GET only, through the read-only hook) and prints one JSON object on stdout: the token's
project id, the negotiated microversions and counts only, never names, addresses or credentials. Logs go to
stderr. It needs no database.

The inventory itself is synced by the **worker**, with the project connection's read credential from the encrypted
credential store, under the real ``project_connection_id``: ``POST /api/v1/projects/{id}/syncs`` (or the periodic
sync, ``inventory.sync_interval``). The former database-writing mode of this command was retired: it read
credentials from ``clouds.yaml`` and filed the data under a made-up connection id that no service could use.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from ovlm.inventory.sync import _fetch_full
from ovlm.openstack.interface import ReadClient

log = logging.getLogger("ovlm.inventory.cli")

RETIRED = (
    "error: `ovlm inventory sync` only reads (--dry-run). The inventory is synced by the worker with the project "
    "connection's stored read credential: POST /api/v1/projects/<project connection id>/syncs\n"
)


def sync_command(client: ReadClient, *, cloud: str) -> tuple[int, dict[str, object]]:
    """Read every resource kind; return ``(exit_code, result_json)`` with counts only."""
    out: dict[str, object] = {
        "cloud": cloud,
        "project_id": client.project_id(),
        "versions": client.negotiated_versions().as_json(),
    }
    fetched = _fetch_full(client)
    out |= {"dry_run": True, "status": "read_ok", "counts": {k: len(v) for k, v in fetched.items()}}
    return 0, out


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="ovlm inventory", description="Inventory commands")
    sub = parser.add_subparsers(dest="action", required=True)
    sync = sub.add_parser("sync", help="read one OpenStack project (dry run: writes nothing)")
    sync.add_argument("--cloud", required=True, help="entry name in clouds.yaml")
    sync.add_argument(
        "--clouds-yaml", type=Path, help="path to clouds.yaml (default: the SDK search path)"
    )
    sync.add_argument(
        "--dry-run",
        action="store_true",
        help="required: read only, write nothing, no database needed",
    )
    args = parser.parse_args(list(argv))
    if not args.dry_run:
        sys.stderr.write(RETIRED)
        return 2

    from ovlm.observability.logging import configure_logging
    from ovlm.openstack.sdk_read import connect_read_only

    configure_logging("inventory-cli", "INFO", stream=sys.stderr)
    client = connect_read_only(args.cloud, args.clouds_yaml)
    code, out = sync_command(client, cloud=args.cloud)
    print(json.dumps(out, indent=2, sort_keys=True))  # noqa: T201 - the command's result
    return code
