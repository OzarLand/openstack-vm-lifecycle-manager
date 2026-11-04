"""``automation_run``: one row per automation phase attempt, with the restricted artefact columns (E5-3).

Revision ID: automation_0001
Revises: 0003_merge

data-model.md section 3 / automation-contract.md sections 3.7 and 7. ``log``, ``events`` and ``diff`` are the
*restricted* columns: they can hold workload secrets that OVLM cannot redact (SEC-R-3), so they are readable
through the API by operator/admin in scope only, purged after ``automation.artifact_retention`` (a separate
clock from audit retention), and excluded from every export. ``diff`` stays NULL unless the profile opted in with
``store_diffs``. The worker inserts and may only purge (NULL) the restricted columns afterwards; nobody deletes.
"""

from alembic import op

revision = "automation_0001"
down_revision = "0003_merge"
branch_labels = ("automation",)
depends_on = None

_PHASES = (
    "'preflight','configure','quiesce','data_attach','start_service','healthcheck','rollback_hooks'"
)


def upgrade() -> None:
    op.execute(
        f"""
        CREATE TABLE automation_run (
          id                     uuid PRIMARY KEY,
          step_id                uuid NOT NULL REFERENCES workflow_step(id),
          attempt                integer NOT NULL,
          phase                  text NOT NULL CHECK (phase IN ({_PHASES})),
          target_role            text NOT NULL CHECK (target_role IN ('old','new')),
          project_scope          text NOT NULL CHECK (project_scope <> ''),
          repo                   text NOT NULL,
          sha                    text NOT NULL CHECK (sha ~ '^[0-9a-f]{{40,64}}$'),
          requirements_hash      text NOT NULL,
          ansible_core_version   text NOT NULL,
          extravars_sha256       text NOT NULL,
          extravars_keys         text[] NOT NULL,
          first_use              boolean,
          exit_code              integer,
          classification         text NOT NULL
                                 CHECK (classification IN ('ok','retryable','needs_human','fatal')),
          reported_classification text,
          reason                 text NOT NULL DEFAULT '',
          result                 jsonb,
          result_error           text,
          task_summary           jsonb NOT NULL DEFAULT '[]'::jsonb,
          duration_seconds       double precision,
          host_key_mode          text NOT NULL CHECK (host_key_mode IN ('pinned','tofu')),
          lint_digest            text,
          -- restricted columns (SEC-R-3): operator/admin in scope only, own retention, never exported
          log                    text,
          events                 jsonb,
          diff                   text,
          artifact_expires_at    timestamptz NOT NULL,
          artifacts_purged_at    timestamptz,
          created_at             timestamptz NOT NULL DEFAULT now(),
          -- a diff is only ever stored when the profile opted in: the opt-in is recorded with it
          store_diffs            boolean NOT NULL DEFAULT false,
          CHECK (diff IS NULL OR store_diffs)
        );
        CREATE INDEX automation_run_step_idx ON automation_run (step_id, attempt);
        CREATE INDEX automation_run_expiry_idx ON automation_run (artifact_expires_at)
          WHERE artifacts_purged_at IS NULL;

        GRANT SELECT ON automation_run TO ovlm_api;
        GRANT SELECT, INSERT ON automation_run TO ovlm_worker;
        -- retention purge: only the restricted columns and the purge stamp may change, nobody deletes
        GRANT UPDATE (log, events, diff, artifacts_purged_at) ON automation_run TO ovlm_worker;
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE automation_run")
