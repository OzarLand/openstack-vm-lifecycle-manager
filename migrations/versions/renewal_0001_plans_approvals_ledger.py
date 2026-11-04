"""Renewal (E5-4, E5-5): plans, approvals, ownership ledger, API idempotency keys (data-model.md sections 7, 9, 12).

Revision ID: renewal_0001
Revises: 0005_merge

* ``renewal_plan``: what G1 approves (resolved ids, policy version) and its ``plan_hash``.
* ``approval``: gates G1 (plan), G2 (cutover), G3 (retirement). Never trusted as a flag by the worker: it re-derives
  the evidence (renewal-workflow.md 3.1). Constraints of data-model.md section 7.
* ``owned_resource``: the ledger of what a run creates (ADR-0005; SRE-R-11 partial uniqueness).
* ``api_idempotency``: ``Idempotency-Key`` replay store of the renewal endpoints (api-design.md section 1).

Also: ``run_signal.kind`` accepts ``approve`` (an approval decision wakes the gate step); ``ovlm_worker`` may INSERT
``managed_vm`` (green becomes ``current`` in the W10 success transaction, data-model.md section 4).

Grants (data-model.md section 12): the api reads/writes plans and approvals (not ``renewal_plan.automation_diff``);
the worker only reads them, may set ``renewal_plan.state``, and owns the ledger.
"""

from alembic import op

revision = "renewal_0001"
down_revision = "0005_merge"
branch_labels = ("renewal",)
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
)
SIGNAL_KINDS = (*SIGNAL_KINDS_OLD, "approve")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE renewal_plan (
          id                    uuid PRIMARY KEY,
          managed_vm_id         uuid NOT NULL REFERENCES managed_vm (id),
          service_id            uuid NOT NULL REFERENCES service (id),
          profile_version_id    uuid NOT NULL REFERENCES profile_version (id),
          assessment_id         uuid,
          policy_id             uuid NOT NULL REFERENCES policy (id),
          policy_version        integer NOT NULL,
          resolved              jsonb NOT NULL,
          automation_diff       jsonb,
          plan_hash             text NOT NULL CHECK (plan_hash ~ '^[0-9a-f]{64}$'),
          planned_window_start  timestamptz,
          capacity_check        jsonb,
          state                 text NOT NULL DEFAULT 'draft' CHECK (state IN
                                  ('draft', 'awaiting_approval', 'approved', 'started', 'cancelled', 'expired')),
          created_by            uuid,
          created_at            timestamptz NOT NULL DEFAULT now(),
          updated_at            timestamptz NOT NULL DEFAULT now(),
          version               integer NOT NULL DEFAULT 1
        )
        """
    )
    op.execute("CREATE INDEX renewal_plan_created ON renewal_plan (created_at, id)")
    op.execute("CREATE INDEX renewal_plan_vm ON renewal_plan (managed_vm_id)")

    op.execute(
        """
        CREATE TABLE approval (
          id                  uuid PRIMARY KEY,
          subject_type        text NOT NULL CHECK (subject_type IN ('plan', 'cutover', 'retirement', 'manual_recovery')),
          subject_id          uuid NOT NULL,
          plan_id             uuid NOT NULL REFERENCES renewal_plan (id),
          run_id              uuid REFERENCES workflow_run (id),
          scope               text NOT NULL,
          bound_hash          text NOT NULL,
          hash_inputs         jsonb NOT NULL DEFAULT '{}'::jsonb,
          requester_set       uuid[] NOT NULL DEFAULT '{}',
          requested_by        uuid NOT NULL,
          requested_at        timestamptz NOT NULL DEFAULT now(),
          decided_by          uuid,
          decision            text CHECK (decision IN ('approved', 'rejected')),
          typed_confirmation  text,
          auth_method         text,
          stepup_id           uuid UNIQUE,
          self_approved       boolean NOT NULL DEFAULT false,
          operator_confirmed  boolean NOT NULL DEFAULT false,
          account_provenance  jsonb,
          comment             text,
          decided_at          timestamptz,
          expires_at          timestamptz,
          void_reason         text,
          created_at          timestamptz NOT NULL DEFAULT now(),
          version             integer NOT NULL DEFAULT 1,
          CHECK (self_approved OR decided_by IS NULL OR operator_confirmed
                 OR NOT decided_by = ANY (requester_set)),
          CHECK (NOT (subject_type = 'retirement' AND self_approved)),
          CHECK (NOT (subject_type <> 'cutover' AND operator_confirmed)),
          CHECK ((decision IS NULL) = (decided_at IS NULL))
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX approval_one_open_per_subject ON approval (subject_type, subject_id) "
        "WHERE decision IS NULL AND void_reason IS NULL"
    )
    op.execute("CREATE INDEX approval_subject ON approval (subject_type, subject_id, decided_at)")

    op.execute(
        """
        CREATE TABLE owned_resource (
          id                   uuid PRIMARY KEY,
          run_id               uuid NOT NULL REFERENCES workflow_run (id),
          resource_type        text NOT NULL CHECK (resource_type IN ('server', 'snapshot')),
          role                 text NOT NULL CHECK (role IN ('green', 'snapshot')),
          intended_name        text NOT NULL,
          openstack_id         text,
          state                text NOT NULL CHECK (state IN ('intended', 'present', 'deleted', 'orphan')),
          detail               jsonb NOT NULL DEFAULT '{}'::jsonb,
          intent_committed_at  timestamptz NOT NULL DEFAULT now(),
          created_at           timestamptz NOT NULL DEFAULT now(),
          updated_at           timestamptz NOT NULL DEFAULT now(),
          UNIQUE (resource_type, openstack_id)
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX owned_resource_one_live_per_role ON owned_resource (run_id, role) "
        "WHERE state IN ('intended', 'present')"
    )

    op.execute(
        """
        CREATE TABLE api_idempotency (
          principal_id  uuid NOT NULL,
          key           text NOT NULL CHECK (length(key) BETWEEN 8 AND 200),
          method        text NOT NULL,
          path          text NOT NULL,
          body_hash     text NOT NULL,
          status        integer NOT NULL,
          response      jsonb NOT NULL,
          created_at    timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (principal_id, key)
        )
        """
    )

    op.execute("ALTER TABLE run_signal DROP CONSTRAINT run_signal_kind_check")
    op.execute(
        f"ALTER TABLE run_signal ADD CONSTRAINT run_signal_kind_check CHECK (kind IN ({_in(SIGNAL_KINDS)}))"
    )

    op.execute("GRANT SELECT, INSERT ON renewal_plan TO ovlm_api")
    op.execute("GRANT UPDATE (state, updated_at, version) ON renewal_plan TO ovlm_api")
    op.execute("GRANT SELECT, INSERT ON approval TO ovlm_api")
    op.execute(
        "GRANT UPDATE (decided_by, decision, typed_confirmation, auth_method, stepup_id, self_approved, "
        "account_provenance, comment, decided_at, expires_at, void_reason, version) ON approval TO ovlm_api"
    )
    op.execute("GRANT SELECT ON owned_resource TO ovlm_api")
    op.execute("GRANT SELECT, INSERT, DELETE ON api_idempotency TO ovlm_api")

    op.execute("GRANT SELECT ON renewal_plan, approval TO ovlm_worker")
    op.execute("GRANT UPDATE (state, updated_at) ON renewal_plan TO ovlm_worker")
    op.execute("GRANT UPDATE (automation_diff) ON renewal_plan TO ovlm_worker")
    op.execute("GRANT SELECT, INSERT, UPDATE ON owned_resource TO ovlm_worker")
    op.execute("GRANT INSERT ON managed_vm TO ovlm_worker")


def downgrade() -> None:
    op.execute("REVOKE INSERT ON managed_vm FROM ovlm_worker")
    op.execute("DELETE FROM run_signal WHERE kind = 'approve'")
    op.execute("ALTER TABLE run_signal DROP CONSTRAINT run_signal_kind_check")
    op.execute(
        f"ALTER TABLE run_signal ADD CONSTRAINT run_signal_kind_check CHECK (kind IN ({_in(SIGNAL_KINDS_OLD)}))"
    )
    for table in ("api_idempotency", "owned_resource", "approval", "renewal_plan"):
        op.execute(f"DROP TABLE {table}")
