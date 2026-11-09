"""``automation_reprepare`` is append-only: a one-shot authorization cannot be re-armed (review PMR-6 b).

Revision ID: renewal_0005
Revises: renewal_0004

The worker holds ``UPDATE (consumed_at, outcome)`` on the table; with grants alone it could set ``consumed_at`` back
to ``NULL`` and re-arm a consumed authorization. A trigger now allows only the consume transitions:

* ``consumed_at`` from ``NULL`` to a value (the guest port takes the authorization before it clones);
* ``outcome`` from ``NULL`` to a value, once ``consumed_at`` is set (what the consumed authorization led to);
* both at once (an authorization voided because its step closed without it, PMR-2: ``expired``).

Every other UPDATE (another column, a value changed again or cleared, a no-op), every DELETE and a TRUNCATE are
refused. Grants are unchanged (worker ``SELECT, INSERT, UPDATE (consumed_at, outcome)``, api ``SELECT``, no
DELETE), as for ``run_downtime`` and ``step_acceptance``.

Linear after ``renewal_0004`` so the schema keeps a single head.
"""

from alembic import op

revision = "renewal_0005"
down_revision = "renewal_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION automation_reprepare_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'UPDATE'
             AND NEW.id = OLD.id AND NEW.run_id = OLD.run_id AND NEW.signal_id = OLD.signal_id
             AND NEW.step_id = OLD.step_id AND NEW.step_key = OLD.step_key AND NEW.sha = OLD.sha
             AND NEW.approver_id = OLD.approver_id AND NEW.authorized_at = OLD.authorized_at
             AND NEW.consumed_at IS NOT NULL
             AND (OLD.consumed_at IS NULL OR NEW.consumed_at = OLD.consumed_at)
             AND (OLD.outcome IS NULL OR NEW.outcome IS NOT DISTINCT FROM OLD.outcome)
             AND (OLD.consumed_at IS NULL OR (OLD.outcome IS NULL AND NEW.outcome IS NOT NULL)) THEN
            RETURN NEW;
          END IF;
          RAISE EXCEPTION 'automation_reprepare is append-only (an authorization is consumed once, its outcome set '
                          'once): % refused', TG_OP;
        END
        $$;
        CREATE TRIGGER automation_reprepare_consume_only
          BEFORE UPDATE OR DELETE ON automation_reprepare
          FOR EACH ROW EXECUTE FUNCTION automation_reprepare_guard();
        CREATE TRIGGER automation_reprepare_no_truncate
          BEFORE TRUNCATE ON automation_reprepare
          FOR EACH STATEMENT EXECUTE FUNCTION automation_reprepare_guard();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER automation_reprepare_no_truncate ON automation_reprepare")
    op.execute("DROP TRIGGER automation_reprepare_consume_only ON automation_reprepare")
    op.execute("DROP FUNCTION automation_reprepare_guard()")
