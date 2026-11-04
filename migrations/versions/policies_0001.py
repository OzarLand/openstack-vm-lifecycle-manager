"""Policies, bindings and time-boxed exceptions (data-model.md section 6).

Revision ID: policies_0001
Revises: 0003_merge

Durations are stored as whole seconds. ``policy_binding`` is UNIQUE per (scope_type, scope_id): the most specific
binding wins at resolution time, so one scope never has two policies. ``scope_id`` is polymorphic (a service group
or a service) and is checked by the application. An exception ends by time alone (``expires_at``), nothing deletes
it; the api may only set ``approved_by`` and ``approved_at`` after the insert, and the approver differs from the
requester (CHECK).
"""

from alembic import op

revision = "policies_0001"
down_revision = "0003_merge"
branch_labels = ("policies",)
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE policy (
          id                            uuid PRIMARY KEY,
          name                          text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 200),
          max_age_seconds               bigint NOT NULL CHECK (max_age_seconds > 0),
          renewal_interval_seconds      bigint NOT NULL CHECK (renewal_interval_seconds > 0),
          windows                       jsonb NOT NULL,
          approvals                     jsonb NOT NULL,
          require_distinct_approvers    boolean NOT NULL DEFAULT true,
          snapshot_retain_after_restore text NOT NULL DEFAULT 'until_next_renewal',
          auto_restore_in_window        boolean NOT NULL DEFAULT true,
          max_window_duration_seconds   bigint NOT NULL CHECK (max_window_duration_seconds > 0),
          retention_period_seconds      bigint CHECK (retention_period_seconds > 0),
          version                       integer NOT NULL DEFAULT 1,
          last_edited_by                uuid,
          created_at                    timestamptz NOT NULL DEFAULT now(),
          updated_at                    timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE policy_binding (
          id         uuid PRIMARY KEY,
          policy_id  uuid NOT NULL REFERENCES policy (id),
          scope_type text NOT NULL CHECK (scope_type IN ('service_group', 'service')),
          scope_id   uuid NOT NULL,
          created_by uuid,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (scope_type, scope_id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE policy_exception (
          id           uuid PRIMARY KEY,
          service_id   uuid NOT NULL REFERENCES service (id),
          reason       text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
          owner        text NOT NULL CHECK (length(owner) BETWEEN 1 AND 200),
          starts_at    timestamptz NOT NULL,
          expires_at   timestamptz NOT NULL,
          requested_by uuid NOT NULL,
          approved_by  uuid,
          approved_at  timestamptz,
          created_at   timestamptz NOT NULL DEFAULT now(),
          CHECK (expires_at > starts_at),
          CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
          CHECK (approved_by IS NULL OR approved_by <> requested_by)
        )
        """
    )
    op.execute("CREATE INDEX policy_binding_policy ON policy_binding (policy_id)")
    op.execute("CREATE INDEX policy_exception_service ON policy_exception (service_id, expires_at)")

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON policy, policy_binding TO ovlm_api")
    op.execute("GRANT SELECT, INSERT ON policy_exception TO ovlm_api")
    op.execute("GRANT UPDATE (approved_by, approved_at) ON policy_exception TO ovlm_api")
    op.execute("GRANT SELECT ON policy, policy_binding, policy_exception TO ovlm_worker")


def downgrade() -> None:
    op.execute("DROP TABLE policy_exception")
    op.execute("DROP TABLE policy_binding")
    op.execute("DROP TABLE policy")
