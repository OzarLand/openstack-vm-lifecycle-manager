"""SQLAlchemy Core tables of the policies module. Created by migration ``policies_0001``."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
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

policy = Table(
    "policy",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("name", Text, nullable=False, unique=True),
    Column("max_age_seconds", BigInteger, nullable=False),
    Column("renewal_interval_seconds", BigInteger, nullable=False),
    Column("windows", JSONB, nullable=False),
    Column("approvals", JSONB, nullable=False),
    Column("require_distinct_approvers", Boolean, nullable=False, server_default=text("true")),
    Column("snapshot_retain_after_restore", Text, nullable=False),
    Column("auto_restore_in_window", Boolean, nullable=False, server_default=text("true")),
    Column("max_window_duration_seconds", BigInteger, nullable=False),
    Column("retention_period_seconds", BigInteger),
    Column("version", Integer, nullable=False, server_default=text("1")),
    Column("last_edited_by", UUID(as_uuid=True)),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
    Column("updated_at", _TS, nullable=False, server_default=text("now()")),
)

policy_binding = Table(
    "policy_binding",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("policy_id", UUID(as_uuid=True), nullable=False),
    Column("scope_type", Text, nullable=False),
    Column("scope_id", UUID(as_uuid=True), nullable=False),
    Column("created_by", UUID(as_uuid=True)),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
    UniqueConstraint("scope_type", "scope_id"),
)

policy_exception = Table(
    "policy_exception",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("service_id", UUID(as_uuid=True), nullable=False),
    Column("reason", Text, nullable=False),
    Column("owner", Text, nullable=False),
    Column("starts_at", _TS, nullable=False),
    Column("expires_at", _TS, nullable=False),
    Column("requested_by", UUID(as_uuid=True), nullable=False),
    Column("approved_by", UUID(as_uuid=True)),
    Column("approved_at", _TS),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
)
