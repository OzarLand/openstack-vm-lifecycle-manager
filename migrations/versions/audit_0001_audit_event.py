"""Append-only ``audit_event`` (security-model.md section 8, data-model.md section 10).

Revision ID: audit_0001
Revises: 0001_baseline

Three layers: owner-only DDL, runtime roles granted INSERT + SELECT only, and triggers that raise on UPDATE,
DELETE and TRUNCATE (they catch a mis-grant and the table owner alike; only a deliberate migration that drops
the trigger can change history).
"""

from alembic import op

revision = "audit_0001"
down_revision = "0001_baseline"
branch_labels = ("audit",)
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE audit_event (
          id             bigserial PRIMARY KEY,
          ts             timestamptz NOT NULL DEFAULT now(),
          actor_id       uuid,
          principal_type text NOT NULL CHECK (principal_type IN ('human','token','system','worker')),
          auth_method    text NOT NULL,
          source_ip      text,
          project_scope  text,
          action         text NOT NULL CHECK (action <> ''),
          target_type    text NOT NULL CHECK (target_type <> ''),
          target_id      text,
          before         jsonb,
          after          jsonb,
          result         text NOT NULL CHECK (result IN ('success','failure','denied')),
          run_id         uuid,
          step_id        uuid,
          request_id     text,
          authority_ref  text
        );
        CREATE INDEX audit_event_ts_idx ON audit_event (ts);
        CREATE INDEX audit_event_actor_idx ON audit_event (actor_id, ts);
        CREATE INDEX audit_event_target_idx ON audit_event (target_type, target_id);
        CREATE INDEX audit_event_run_idx ON audit_event (run_id) WHERE run_id IS NOT NULL;

        CREATE FUNCTION audit_event_refuse_change() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'audit_event is append-only: % refused', TG_OP
            USING ERRCODE = 'insufficient_privilege';
        END
        $$;

        CREATE TRIGGER audit_event_no_update_delete
          BEFORE UPDATE OR DELETE ON audit_event
          FOR EACH ROW EXECUTE FUNCTION audit_event_refuse_change();
        CREATE TRIGGER audit_event_no_truncate
          BEFORE TRUNCATE ON audit_event
          FOR EACH STATEMENT EXECUTE FUNCTION audit_event_refuse_change();

        GRANT INSERT, SELECT ON audit_event TO ovlm_api, ovlm_worker;
        GRANT USAGE ON SEQUENCE audit_event_id_seq TO ovlm_api, ovlm_worker;
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE audit_event")
    op.execute("DROP FUNCTION audit_event_refuse_change()")
