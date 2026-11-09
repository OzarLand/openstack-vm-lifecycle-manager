"""A step-up spent on a run action names the ``run_signal`` it authorised (review PMR-8, REN-10).

Revision ID: auth_0003
Revises: renewal_0005

The worker re-validates the step-up of every confirmed run action (``_check_confirmation``): user, action
``run.<kind>``, target = the run, password+TOTP, consumed within its validity. It did not check that **this** signal
consumed it, so a second ``run_signal`` carrying an already spent ``stepup_id`` passed (a replay only a compromised
api can write). The api now spends the step-up and inserts the signal in one transaction and records the signal's id
on the step-up; the worker requires ``consumed_by_signal`` = the signal it is applying.

* ``stepup.consumed_by_signal uuid``: ``UNIQUE`` (one step-up per signal and one signal per step-up), set only by the
  consume itself (``consumed_at`` from NULL in the same UPDATE) and never changed afterwards (trigger
  ``stepup_signal_binding``, every role). CHECK: a bound step-up is consumed.
* Not a foreign key to ``run_signal``: the auth tables do not reference workflow tables (the step-up is spent just
  before the signal row is inserted, in the same transaction).

Linear after ``renewal_0005`` so the schema keeps a single head. A step-up spent before this revision has no
binding: a signal still pending across the upgrade is refused by the worker (``step-up evidence invalid``) and the
operator sends it again.
"""

from alembic import op

revision = "auth_0003"
down_revision = "renewal_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE stepup ADD COLUMN consumed_by_signal uuid UNIQUE;
        ALTER TABLE stepup ADD CONSTRAINT stepup_signal_consumed
          CHECK (consumed_by_signal IS NULL OR consumed_at IS NOT NULL);

        CREATE FUNCTION stepup_signal_binding_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.consumed_by_signal IS DISTINCT FROM OLD.consumed_by_signal
             AND NOT (OLD.consumed_by_signal IS NULL AND OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL) THEN
            RAISE EXCEPTION 'stepup.consumed_by_signal is set by the consume only, once'
              USING ERRCODE = '42501';
          END IF;
          IF OLD.consumed_by_signal IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
            RAISE EXCEPTION 'a step-up bound to a signal stays consumed' USING ERRCODE = '42501';
          END IF;
          RETURN NEW;
        END
        $$;
        CREATE TRIGGER stepup_signal_binding BEFORE UPDATE ON stepup
          FOR EACH ROW EXECUTE FUNCTION stepup_signal_binding_guard();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER stepup_signal_binding ON stepup")
    op.execute("DROP FUNCTION stepup_signal_binding_guard()")
    op.execute("ALTER TABLE stepup DROP CONSTRAINT stepup_signal_consumed")
    op.execute("ALTER TABLE stepup DROP COLUMN consumed_by_signal")
