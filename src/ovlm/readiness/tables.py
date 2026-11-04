"""SQLAlchemy Core tables of the readiness module. Created by migration ``readiness_0001`` (same columns; the
integration tests compare them)."""

from __future__ import annotations

from sqlalchemy import (
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
_TS = DateTime(timezone=True)

readiness_assessment = Table(
    "readiness_assessment",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("managed_vm_id", UUID(as_uuid=True), nullable=False),
    Column("profile_version_id", UUID(as_uuid=True)),
    Column("observed_server_revision_id", UUID(as_uuid=True)),
    Column("input_snapshot", JSONB, nullable=False),
    Column("level", Text, nullable=False),
    Column("summary", JSONB, nullable=False),
    Column("requested_by", UUID(as_uuid=True)),
    Column("workflow_run_id", UUID(as_uuid=True), nullable=False, unique=True),
    Column("live_code_run", Boolean, nullable=False, server_default=text("false")),
    Column("live_code_sha", Text),
    Column("live_code_confirmation", JSONB),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
)

check_result = Table(
    "check_result",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column(
        "assessment_id", UUID(as_uuid=True), ForeignKey("readiness_assessment.id"), nullable=False
    ),
    Column("check_key", Text, nullable=False),
    Column("check_version", Integer, nullable=False),
    Column("category", Text, nullable=False),
    Column("result", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("evidence", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("recommendation", Text),
    Column("seq", Integer, nullable=False),
    UniqueConstraint("assessment_id", "check_key"),
)

attestation = Table(
    "attestation",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("managed_vm_id", UUID(as_uuid=True), nullable=False),
    Column("check_key", Text, nullable=False),
    Column("statement", Text, nullable=False),
    Column("attested_by", UUID(as_uuid=True), nullable=False),
    Column("attested_at", _TS, nullable=False, server_default=text("now()")),
    Column("expires_at", _TS),
    Column("profile_version_id", UUID(as_uuid=True), nullable=False),
)
