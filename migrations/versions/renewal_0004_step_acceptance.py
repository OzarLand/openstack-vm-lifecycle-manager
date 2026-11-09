"""``accept-step``: an approver accepts a parked restore step without running its playbook (ADR-0008, roadmap P0-2).

Revision ID: renewal_0004
Revises: renewal_0003

* ``run_signal.kind`` accepts ``accept_step``.
* ``workflow_step.resolution``: ``accepted`` when a step was closed ``succeeded`` by an approver's accept-step, its
  playbook never run; ``NULL`` for every step that ran (the normal case). The worker writes it in the signal's
  transaction.
* ``step_acceptance``: one row per accept-step decision of the worker, ``accepted`` or ``refused`` (with its refusal
  code): run, step, attempt, approver, signal, pinned SHA, the parked reason and a SHA-256 of the refused phase result,
  the OVLM probe (JSON, id and time), the approver's attestation (data, rendered escaped), the outcome. At most one
  ``accepted`` row per (run, step key) (partial unique index): once per step. Append-only: the worker inserts, a
  trigger refuses UPDATE, DELETE and TRUNCATE, no UPDATE or DELETE grant; the api reads.

Linear after ``renewal_0003`` so the schema keeps a single head.
"""

from alembic import op

revision = "renewal_0004"
down_revision = "renewal_0003"
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
    "reprepare_automation",
)
SIGNAL_KINDS = (*SIGNAL_KINDS_OLD, "accept_step")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    op.execute("ALTER TABLE run_signal DROP CONSTRAINT run_signal_kind_check")
    op.execute(
        f"ALTER TABLE run_signal ADD CONSTRAINT run_signal_kind_check CHECK (kind IN ({_in(SIGNAL_KINDS)}))"
    )
    op.execute(
        "ALTER TABLE workflow_step ADD COLUMN resolution text "
        "CHECK (resolution IS NULL OR (resolution = 'accepted' AND state = 'succeeded'))"
    )
    op.execute(
        """
        CREATE TABLE step_acceptance (
          id                     uuid PRIMARY KEY,
          run_id                 uuid NOT NULL REFERENCES workflow_run (id),
          signal_id              uuid NOT NULL UNIQUE REFERENCES run_signal (id),
          step_id                uuid REFERENCES workflow_step (id),
          step_key               text,
          attempt                integer,
          approver_id            uuid NOT NULL REFERENCES app_user (id),
          pinned_sha             text,
          parked_reason          text,
          refused_result_sha256  text CHECK (refused_result_sha256 IS NULL OR refused_result_sha256 ~ '^[0-9a-f]{64}$'),
          probe_id               text,
          probe                  jsonb,
          probed_at              timestamptz,
          attestation            text NOT NULL CHECK (char_length(attestation) <= 2000),
          outcome                text NOT NULL CHECK (outcome IN ('accepted', 'refused')),
          refusal_code           text,
          refusal                text,
          created_at             timestamptz NOT NULL DEFAULT now(),
          CHECK ((outcome = 'accepted') = (refusal_code IS NULL)),
          CHECK (outcome = 'refused' OR (step_id IS NOT NULL AND step_key IS NOT NULL AND attempt IS NOT NULL
                                         AND probe IS NOT NULL AND probed_at IS NOT NULL
                                         AND char_length(attestation) >= 20))
        );
        CREATE UNIQUE INDEX step_acceptance_once ON step_acceptance (run_id, step_key) WHERE outcome = 'accepted';
        CREATE INDEX step_acceptance_run_idx ON step_acceptance (run_id, created_at);

        CREATE FUNCTION step_acceptance_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'step_acceptance is append-only: % refused', TG_OP;
        END
        $$;
        CREATE TRIGGER step_acceptance_no_update_delete
          BEFORE UPDATE OR DELETE ON step_acceptance
          FOR EACH ROW EXECUTE FUNCTION step_acceptance_append_only();
        CREATE TRIGGER step_acceptance_no_truncate
          BEFORE TRUNCATE ON step_acceptance
          FOR EACH STATEMENT EXECUTE FUNCTION step_acceptance_append_only();
        """
    )
    op.execute("GRANT SELECT, INSERT ON step_acceptance TO ovlm_worker")
    op.execute("GRANT SELECT ON step_acceptance TO ovlm_api")


def downgrade() -> None:
    op.execute("DROP TABLE step_acceptance")
    op.execute("DROP FUNCTION step_acceptance_append_only()")
    op.execute("ALTER TABLE workflow_step DROP COLUMN resolution")
    op.execute("DELETE FROM run_signal WHERE kind = 'accept_step'")
    op.execute("ALTER TABLE run_signal DROP CONSTRAINT run_signal_kind_check")
    op.execute(
        f"ALTER TABLE run_signal ADD CONSTRAINT run_signal_kind_check CHECK (kind IN ({_in(SIGNAL_KINDS_OLD)}))"
    )
