"""Authorization (E3-2): installation settings with history, and role-binding history lookups.

``installation_setting`` (data-model.md section 8) is insert-only: each change is a new row, the current value is the
newest row per key, and earlier rows are the history the worker's approval re-validation reads ("was the setting on
at ``decided_at``", renewal-workflow.md section 3.1). UPDATE and DELETE are refused by grants and by a trigger.

The index on ``role_binding`` serves the "held role R in scope S at time T" query of the same re-validation.

Revision ID: auth_0002
Revises: 0003_merge
"""

from alembic import op

revision = "auth_0002"
down_revision = "0003_merge"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE installation_setting (
          id          bigserial PRIMARY KEY,
          key         text NOT NULL CHECK (key IN ('allow_operator_approver')),
          value       jsonb NOT NULL,
          changed_by  uuid NOT NULL REFERENCES app_user(id),
          changed_at  timestamptz NOT NULL DEFAULT now(),
          stepup_id   uuid UNIQUE REFERENCES stepup(id),
          reason      text NOT NULL DEFAULT ''
        );
        CREATE INDEX installation_setting_key_time ON installation_setting (key, changed_at DESC, id DESC);

        CREATE FUNCTION installation_setting_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'installation_setting is append-only (history kept)';
        END $$;
        CREATE TRIGGER installation_setting_no_change BEFORE UPDATE OR DELETE ON installation_setting
          FOR EACH ROW EXECUTE FUNCTION installation_setting_immutable();

        CREATE INDEX role_binding_user_time ON role_binding (user_id, role, created_at);

        GRANT SELECT, INSERT ON installation_setting TO ovlm_api;
        GRANT USAGE ON SEQUENCE installation_setting_id_seq TO ovlm_api;
        GRANT SELECT ON installation_setting TO ovlm_worker;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX role_binding_user_time;
        DROP TABLE installation_setting;
        DROP FUNCTION installation_setting_immutable();
        """
    )
