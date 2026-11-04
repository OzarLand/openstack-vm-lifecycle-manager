"""SQLAlchemy Core tables of the renewal module (migration ``renewal_0001``). Imported by api and worker."""

from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Integer, MetaData, Table, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

metadata = MetaData()
_TS = DateTime(timezone=True)

renewal_plan = Table(
    "renewal_plan",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("managed_vm_id", UUID(as_uuid=True), nullable=False),
    Column("service_id", UUID(as_uuid=True), nullable=False),
    Column("profile_version_id", UUID(as_uuid=True), nullable=False),
    Column("assessment_id", UUID(as_uuid=True)),
    Column("policy_id", UUID(as_uuid=True), nullable=False),
    Column("policy_version", Integer, nullable=False),
    Column("resolved", JSONB, nullable=False),
    Column("automation_diff", JSONB),
    Column("plan_hash", Text, nullable=False),
    Column("planned_window_start", _TS),
    Column("capacity_check", JSONB),
    Column("state", Text, nullable=False, server_default=text("'draft'")),
    Column("created_by", UUID(as_uuid=True)),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
    Column("updated_at", _TS, nullable=False, server_default=text("now()")),
    Column("version", Integer, nullable=False, server_default=text("1")),
)

approval = Table(
    "approval",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("subject_type", Text, nullable=False),
    Column("subject_id", UUID(as_uuid=True), nullable=False),
    Column("plan_id", UUID(as_uuid=True), nullable=False),
    Column("run_id", UUID(as_uuid=True)),
    Column("scope", Text, nullable=False),
    Column("bound_hash", Text, nullable=False),
    Column("hash_inputs", JSONB, nullable=False),
    Column("requester_set", ARRAY(UUID(as_uuid=True)), nullable=False),
    Column("requested_by", UUID(as_uuid=True), nullable=False),
    Column("requested_at", _TS, nullable=False, server_default=text("now()")),
    Column("decided_by", UUID(as_uuid=True)),
    Column("decision", Text),
    Column("typed_confirmation", Text),
    Column("auth_method", Text),
    Column("stepup_id", UUID(as_uuid=True)),
    Column("self_approved", Boolean, nullable=False, server_default=text("false")),
    Column("operator_confirmed", Boolean, nullable=False, server_default=text("false")),
    Column("account_provenance", JSONB),
    Column("comment", Text),
    Column("decided_at", _TS),
    Column("expires_at", _TS),
    Column("void_reason", Text),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
    Column("version", Integer, nullable=False, server_default=text("1")),
)

owned_resource = Table(
    "owned_resource",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("run_id", UUID(as_uuid=True), nullable=False),
    Column("resource_type", Text, nullable=False),
    Column("role", Text, nullable=False),
    Column("intended_name", Text, nullable=False),
    Column("openstack_id", Text),
    Column("state", Text, nullable=False),
    Column("detail", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("intent_committed_at", _TS, nullable=False, server_default=text("now()")),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
    Column("updated_at", _TS, nullable=False, server_default=text("now()")),
)

api_idempotency = Table(
    "api_idempotency",
    metadata,
    Column("principal_id", UUID(as_uuid=True), primary_key=True),
    Column("key", Text, primary_key=True),
    Column("method", Text, nullable=False),
    Column("path", Text, nullable=False),
    Column("body_hash", Text, nullable=False),
    Column("status", Integer, nullable=False),
    Column("response", JSONB, nullable=False),
    Column("created_at", _TS, nullable=False, server_default=text("now()")),
)
