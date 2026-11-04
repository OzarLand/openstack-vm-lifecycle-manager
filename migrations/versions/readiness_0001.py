"""Readiness: readiness_assessment, check_result, attestation (data-model.md sections 7, 12; FR-RDY-4).

Revision ID: readiness_0001
Revises: 0004_merge_profiles_policies

Assessments and their check results are append-only (FR-RDY-4): a trigger rejects UPDATE and DELETE for every role,
the table owner included. The worker writes an assessment and its results in one transaction when its ``readiness``
run finishes; ``workflow_run_id`` is UNIQUE, so a retried step cannot write a second assessment for the same run. The
api only reads them: it requests an assessment by inserting a ``workflow_run`` in ``requested`` (already granted).

``managed_vm_id`` carries no foreign key on purpose: unregistering a VM deletes its row, and its assessments are
history that must survive. ``attestation`` (FR-RDY-5) is created now so the check hook reads a real table; nothing
writes it yet (V1), and it is append-only too.
"""

from alembic import op

revision = "readiness_0001"
down_revision = "0004_merge_profiles_policies"
branch_labels = ("readiness",)
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE readiness_assessment (
          id                           uuid PRIMARY KEY,
          managed_vm_id                uuid NOT NULL,
          profile_version_id           uuid REFERENCES profile_version (id),
          observed_server_revision_id  uuid,
          input_snapshot               jsonb NOT NULL,
          level                        text NOT NULL CHECK (level IN ('not-ready', 'partially-ready', 'ready')),
          summary                      jsonb NOT NULL,
          requested_by                 uuid,
          workflow_run_id              uuid NOT NULL UNIQUE,
          live_code_run                boolean NOT NULL DEFAULT false,
          live_code_sha                text,
          live_code_confirmation       jsonb,
          created_at                   timestamptz NOT NULL DEFAULT now(),
          CHECK (live_code_run OR (live_code_sha IS NULL AND live_code_confirmation IS NULL))
        )
        """
    )
    op.execute(
        "CREATE INDEX readiness_assessment_vm ON readiness_assessment (managed_vm_id, created_at DESC, id DESC)"
    )
    op.execute(
        """
        CREATE TABLE check_result (
          id             uuid PRIMARY KEY,
          assessment_id  uuid NOT NULL REFERENCES readiness_assessment (id),
          check_key      text NOT NULL,
          check_version  integer NOT NULL CHECK (check_version >= 1),
          category       text NOT NULL CHECK (category IN (
                           'configuration-reproducibility', 'persistent-data-separation', 'dependencies',
                           'validation-capability', 'external-services')),
          result         text NOT NULL CHECK (result IN ('pass', 'fail', 'unknown', 'not-applicable')),
          severity       text NOT NULL CHECK (severity IN ('blocker', 'warning', 'info')),
          evidence       jsonb NOT NULL DEFAULT '{}'::jsonb,
          recommendation text,
          seq            integer NOT NULL,
          UNIQUE (assessment_id, check_key)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE attestation (
          id                  uuid PRIMARY KEY,
          managed_vm_id       uuid NOT NULL,
          check_key           text NOT NULL,
          statement           text NOT NULL,
          attested_by         uuid NOT NULL,
          attested_at         timestamptz NOT NULL DEFAULT now(),
          expires_at          timestamptz,
          profile_version_id  uuid NOT NULL REFERENCES profile_version (id)
        )
        """
    )
    op.execute(
        "CREATE INDEX attestation_vm ON attestation (managed_vm_id, check_key, attested_at DESC)"
    )
    op.execute(
        """
        CREATE FUNCTION readiness_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION '% rows are append-only (FR-RDY-4)', TG_TABLE_NAME;
        END $$
        """
    )
    for table in ("readiness_assessment", "check_result", "attestation"):
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION readiness_append_only()"
        )
    op.execute("GRANT SELECT ON readiness_assessment, check_result, attestation TO ovlm_api")
    op.execute("GRANT SELECT, INSERT ON readiness_assessment, check_result TO ovlm_worker")
    op.execute("GRANT SELECT ON attestation TO ovlm_worker")


def downgrade() -> None:
    # Supported downgrade path is "restore backup" (architecture.md section 9).
    op.execute("DROP TABLE attestation")
    op.execute("DROP TABLE check_result")
    op.execute("DROP TABLE readiness_assessment")
    op.execute("DROP FUNCTION readiness_append_only()")
