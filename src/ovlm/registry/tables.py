"""SQLAlchemy Core tables of the registry module. Created by migration ``registry_0001``."""

from __future__ import annotations

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    Table,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID

metadata = MetaData()
_TS = DateTime(timezone=True)

ROLES = ("current", "retained", "candidate", "retired")

service_group = Table(
    "service_group",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("name", Text, nullable=False, unique=True),
    Column("description", Text),
    Column("version", Integer, nullable=False, server_default=text("1")),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
    Column("updated_at", _TS, nullable=False, server_default=text("now()")),
)

service = Table(
    "service",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("name", Text, nullable=False),
    Column("slug", Text, nullable=False, unique=True),
    Column("service_group_id", UUID(as_uuid=True), ForeignKey("service_group.id")),
    Column("project_connection_id", UUID(as_uuid=True), nullable=False),
    Column("owner_contact", Text),
    Column("current_profile_id", UUID(as_uuid=True)),  # profiles module: no FK yet
    Column("version", Integer, nullable=False, server_default=text("1")),
    Column("created_by", UUID(as_uuid=True)),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
    Column("updated_at", _TS, nullable=False, server_default=text("now()")),
)

managed_vm = Table(
    "managed_vm",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("service_id", UUID(as_uuid=True), ForeignKey("service.id"), nullable=False),
    # references inventory's observed_server(id); declared as a plain column: other modules never import it
    Column("observed_server_id", UUID(as_uuid=True), nullable=False),
    Column("openstack_server_id", Text, nullable=False, unique=True),
    Column("role", Text, nullable=False),
    Column("registered_by", UUID(as_uuid=True)),
    Column("registered_at", _TS, nullable=False),
    Column("ssh_host_key_fingerprint", Text),
    Column("host_key_confirmed_by", UUID(as_uuid=True)),
    Column("host_key_confirmed_at", _TS),
    Column("launched_at_effective", _TS),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
    Column("updated_at", _TS, nullable=False, server_default=text("now()")),
    Index("managed_vm_service", "service_id"),
)
