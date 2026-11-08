"""``reprepare-automation``: one approver-authorized re-clone inside the window (renewal-workflow.md, AC section 2).

Revision ID: renewal_0002
Revises: profiles_0002

* ``run_signal.kind`` accepts ``reprepare_automation``.
* ``automation_reprepare``: the one-shot authorization the worker records when it accepts the signal (approver,
  pinned SHA, parked step) and consumes before it clones (``consumed_at``, then ``outcome``). At most one pending
  authorization per run; one row per signal. The worker inserts and consumes; nothing deletes (no DELETE grant); the
  api reads it.

Linear after ``profiles_0002`` so the schema keeps a single head (``check_schema_at_head``).
"""

from alembic import op

revision = "renewal_0002"
down_revision = "profiles_0002"
branch_labels = None
depends_on = None

SIGNAL_KINDS_OLD = (
    "admit",
    "abort",
    "rollback",
    "revert",
    "retry_step",
    "mark_resolved",
    "probe",
    "discard",
    "approve",
)
SIGNAL_KINDS = (*SIGNAL_KINDS_OLD, "reprepare_automation")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    op.execute("ALTER TABLE run_signal DROP CONSTRAINT run_signal_kind_check")
    op.execute(
        f"ALTER TABLE run_signal ADD CONSTRAINT run_signal_kind_check CHECK (kind IN ({_in(SIGNAL_KINDS)}))"
    )
    op.execute(
        """
        CREATE TABLE automation_reprepare (
          id             uuid PRIMARY KEY,
          run_id         uuid NOT NULL REFERENCES workflow_run (id),
          signal_id      uuid NOT NULL UNIQUE REFERENCES run_signal (id),
          step_id        uuid NOT NULL REFERENCES workflow_step (id),
          step_key       text NOT NULL,
          sha            text NOT NULL CHECK (sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
          approver_id    uuid NOT NULL REFERENCES app_user (id),
          authorized_at  timestamptz NOT NULL DEFAULT now(),
          consumed_at    timestamptz,
          outcome        text
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX automation_reprepare_one_pending ON automation_reprepare (run_id) "
        "WHERE consumed_at IS NULL"
    )
    op.execute("GRANT SELECT, INSERT ON automation_reprepare TO ovlm_worker")
    op.execute("GRANT UPDATE (consumed_at, outcome) ON automation_reprepare TO ovlm_worker")
    op.execute("GRANT SELECT ON automation_reprepare TO ovlm_api")


def downgrade() -> None:
    op.execute("DROP TABLE automation_reprepare")
    op.execute("DELETE FROM run_signal WHERE kind = 'reprepare_automation'")
    op.execute("ALTER TABLE run_signal DROP CONSTRAINT run_signal_kind_check")
    op.execute(
        f"ALTER TABLE run_signal ADD CONSTRAINT run_signal_kind_check CHECK (kind IN ({_in(SIGNAL_KINDS_OLD)}))"
    )
