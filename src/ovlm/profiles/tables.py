"""SQLAlchemy Core tables of the profiles module. Created by migration ``profiles_0001``."""

from __future__ import annotations

from sqlalchemy import (
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
_TS = DateTime(timezone=True)

profile = Table(
    "profile",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column(
        "service_id", UUID(as_uuid=True), nullable=False, unique=True
    ),  # FK to registry's service in SQL
    Column("name", Text, nullable=False),
    Column("latest_version", Integer, nullable=False, server_default=text("0")),
    Column("version", Integer, nullable=False, server_default=text("1")),
    Column("created_by", UUID(as_uuid=True)),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
    Column("updated_at", _TS, nullable=False, server_default=text("now()")),
)

profile_version = Table(
    "profile_version",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("profile_id", UUID(as_uuid=True), ForeignKey("profile.id"), nullable=False),
    Column("number", Integer, nullable=False),
    Column("spec", JSONB, nullable=False),
    Column("spec_hash", Text, nullable=False),
    Column("automation_sha", Text),
    Column("created_by", UUID(as_uuid=True)),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
    Column("lint_result", JSONB),  # written by the worker only
    UniqueConstraint("profile_id", "number"),
)
