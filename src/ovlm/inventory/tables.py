"""SQLAlchemy Core tables of the inventory module (data-model.md section 3).

Core, not ORM, and a module-local ``MetaData``: the shared declarative ``Base`` does not exist yet, and other
modules must never import these tables (architecture.md section 3), only ``inventory.service``.
Typed status columns are named ``<resource>_status`` because ``status`` is the observation status
(``present``, ``gone``, ``unknown``). The migration ``inventory_0001`` creates the same columns; ``tests/integration/test_inventory_db.py`` compares them.
"""

from __future__ import annotations

from sqlalchemy import (
    ARRAY,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

metadata = MetaData()

#: Resource kinds in sync order. ``volume_attachment`` is derived from volumes + servers.
RESOURCES = (
    "server",
    "volume",
    "volume_attachment",
    "port",
    "floating_ip",
    "network",
    "image",
    "flavor",
)

OBSERVATION_STATUSES = ("present", "gone", "unknown")
SYNC_KINDS = ("full", "servers_delta")
SYNC_STATUSES = ("running", "succeeded", "failed")

_TS = DateTime(timezone=True)

sync_run = Table(
    "sync_run",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_connection_id", UUID(as_uuid=True), nullable=False),
    Column("kind", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("started_at", _TS, nullable=False),
    Column("finished_at", _TS),
    Column("counts", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("versions", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("error", JSONB),
    Column("workflow_run_id", UUID(as_uuid=True)),  # engine integration point (E5-1): no FK yet
)


def _typed_columns(resource: str) -> list[Column[object]]:
    t = Text
    arr = ARRAY(Text)
    cols: dict[str, list[Column[object]]] = {
        "server": [
            Column("server_status", t, nullable=False),
            Column("vm_state", t),
            Column("task_state", t),
            Column("power_state", Integer),
            Column("created", _TS),
            Column("launched_at", _TS),
            Column("nova_updated_at", _TS),
            Column("flavor_original_name", t),
            Column("flavor_vcpus", Integer),
            Column("flavor_ram", Integer),
            Column("flavor_disk", Integer),
            Column("image_id", t),
            Column("availability_zone", t),
            Column("locked", Boolean),
            Column("locked_reason", t),
            Column("tags", arr, nullable=False, server_default=text("'{}'")),
            Column("metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
            Column("host_id", t),
            Column("is_minimal_construct", Boolean, nullable=False, server_default=text("false")),
        ],
        "volume": [
            Column("volume_status", t, nullable=False),
            Column("size", Integer),
            Column("bootable", Boolean),
            Column("multiattach", Boolean),
            Column("availability_zone", t),
            Column("volume_type", t),
            Column("metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
        ],
        "volume_attachment": [
            Column("server_openstack_id", t, nullable=False),
            Column("volume_openstack_id", t, nullable=False),
            Column("device", t),
            Column("attachment_id", t),
            Column("delete_on_termination", Boolean),
        ],
        "port": [
            Column("network_id", t),
            Column("device_id", t),
            Column("device_owner", t),
            Column("fixed_ips", JSONB, nullable=False, server_default=text("'[]'::jsonb")),
            Column("mac", t),
            Column("security_group_ids", arr, nullable=False, server_default=text("'{}'")),
            Column("port_status", t),
        ],
        "floating_ip": [
            Column("floating_ip_address", t, nullable=False),
            Column("port_id", t),
            Column("fixed_ip_address", t),
            Column("router_id", t),
            Column("floating_network_id", t),
            Column("floating_ip_status", t),
            Column("tags", arr, nullable=False, server_default=text("'{}'")),
        ],
        "network": [
            Column("network_status", t),
            Column("is_external", Boolean, nullable=False, server_default=text("false")),
            Column("is_shared", Boolean, nullable=False, server_default=text("false")),
        ],
        "image": [
            Column("image_status", t),
            Column("visibility", t),
            Column("owner_id", t),
        ],
        "flavor": [
            Column("vcpus", Integer),
            Column("ram", Integer),
            Column("disk", Integer),
            Column("ephemeral", Integer),
            Column("is_public", Boolean),
        ],
    }
    return cols[resource]


def _observed(resource: str) -> tuple[Table, Table]:
    name = f"observed_{resource}"
    current = Table(
        name,
        metadata,
        Column("id", UUID(as_uuid=True), primary_key=True),
        Column("project_connection_id", UUID(as_uuid=True), nullable=False),
        Column("openstack_id", Text, nullable=False),
        Column("name", Text),
        *_typed_columns(resource),
        Column("payload", JSONB, nullable=False),
        Column("payload_hash", Text, nullable=False),
        Column("first_seen_sync_id", UUID(as_uuid=True), ForeignKey("sync_run.id"), nullable=False),
        Column("last_seen_sync_id", UUID(as_uuid=True), ForeignKey("sync_run.id"), nullable=False),
        Column("missed_syncs", Integer, nullable=False, server_default=text("0")),
        Column("status", Text, nullable=False, server_default=text("'present'")),
        Column("gone_at", _TS),
        Column("synced_at", _TS, nullable=False),
        Column("created_at", _TS, nullable=False, server_default=text("now()")),
        Column("updated_at", _TS, nullable=False, server_default=text("now()")),
        UniqueConstraint("project_connection_id", "openstack_id"),
    )
    revision = Table(
        f"{name}_revision",
        metadata,
        Column("id", UUID(as_uuid=True), primary_key=True),
        Column(f"{name}_id", UUID(as_uuid=True), ForeignKey(f"{name}.id"), nullable=False),
        Column("sync_run_id", UUID(as_uuid=True), ForeignKey("sync_run.id"), nullable=False),
        Column("payload", JSONB, nullable=False),
        Column("payload_hash", Text, nullable=False),
        Column("observed_at", _TS, nullable=False),
    )
    return current, revision


OBSERVED: dict[str, Table] = {}
REVISIONS: dict[str, Table] = {}
for _res in RESOURCES:
    OBSERVED[_res], REVISIONS[_res] = _observed(_res)
