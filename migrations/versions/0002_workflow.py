"""Workflow engine tables (ADR-0003, data-model.md sections 8 and 9).

Revision ID: 0002_workflow
Revises: 0001_baseline

Tables: ``workflow_run``, ``workflow_step``, ``workflow_step_attempt``, ``run_signal``, ``resource_lock``,
``worker_heartbeat`` and the sequence ``fencing_seq``.

Not here (owned by other modules): ``approval``, ``renewal_plan``, ``service``, ``automation_run``,
``owned_resource``, ``audit_event``, ``installation_setting``. Foreign keys from ``workflow_run`` to
``renewal_plan`` / ``service`` are added by the merge revision once those tables exist (columns are plain uuid here).

Grants follow data-model.md section 12:

* ``ovlm_api``: SELECT on all workflow tables; INSERT on ``workflow_run`` (only ``state='requested'``, enforced by a
  trigger) and on ``run_signal`` (only unconsumed rows, trigger). No UPDATE/DELETE anywhere (SEC-R-1).
* ``ovlm_worker``: read/write on all of them, USAGE on ``fencing_seq``; UPDATE on ``run_signal`` limited to
  ``consumed_at``/``outcome``.

Expand/contract applies to these tables: in-flight runs survive upgrades (architecture.md section 9).
"""

from alembic import op

revision = "0002_workflow"
down_revision = "0001_baseline"
branch_labels = ("workflow",)
depends_on = None

RUN_STATES = (
    "requested",
    "running",
    "needs_human",
    "rejected",
    "cancelled",
    "failed",
    "completed",
    "rolled_back",
)
TERMINAL_RUN_STATES = ("rejected", "cancelled", "failed", "completed", "rolled_back")
STEP_STATES = (
    "ready",
    "running",
    "waiting",
    "succeeded",
    "failed",
    "needs_human",
    "skipped",
    "cancelled",
)
SIGNAL_KINDS = (
    "admit",
    "abort",
    "rollback",
    "revert",
    "retry_step",
    "mark_resolved",
    "probe",
    "discard",
)


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    op.execute("CREATE SEQUENCE fencing_seq AS bigint START 1 NO CYCLE")

    op.execute(
        f"""
        CREATE TABLE workflow_run (
          id                   uuid PRIMARY KEY,
          kind                 text NOT NULL,
          strategy             text NOT NULL,
          strategy_version     text NOT NULL,
          state                text NOT NULL DEFAULT 'requested' CHECK (state IN ({_in(RUN_STATES)})),
          renewal_plan_id      uuid,
          service_id           uuid,
          subject              jsonb NOT NULL DEFAULT '{{}}'::jsonb,
          abort_requested      boolean NOT NULL DEFAULT false,
          abort_requested_by   uuid,
          phase                text,
          auto_restore_used    boolean NOT NULL DEFAULT false,
          needs_human_reason   text,
          end_reason           text,
          downtime_started_at  timestamptz,
          downtime_ended_at    timestamptz,
          current_truth        jsonb,
          current_truth_at     timestamptz,
          started_by           uuid,
          started_at           timestamptz,
          admitted_at          timestamptz,
          finished_at          timestamptz,
          created_at           timestamptz NOT NULL DEFAULT now(),
          updated_at           timestamptz NOT NULL DEFAULT now(),
          version              integer NOT NULL DEFAULT 1,
          CHECK ((state IN ({_in(TERMINAL_RUN_STATES)})) = (finished_at IS NOT NULL)),
          CHECK (state <> 'needs_human' OR needs_human_reason IS NOT NULL)
        )
        """
    )
    # One non-terminal renewal run per service (data-model.md section 8). 'requested' counts (SRE-R-25).
    op.execute(
        f"""
        CREATE UNIQUE INDEX workflow_run_one_active_renewal_per_service ON workflow_run (service_id)
        WHERE kind = 'renewal' AND state NOT IN ({_in(TERMINAL_RUN_STATES)})
        """
    )
    op.execute("CREATE INDEX workflow_run_state_idx ON workflow_run (state, created_at)")

    op.execute(
        f"""
        CREATE TABLE workflow_step (
          id                uuid PRIMARY KEY,
          run_id            uuid NOT NULL REFERENCES workflow_run(id),
          seq               integer NOT NULL,
          step_key          text NOT NULL,
          state             text NOT NULL CHECK (state IN ({_in(STEP_STATES)})),
          attempt           integer NOT NULL DEFAULT 0,
          fencing_token     bigint,
          lease_owner       text,
          lease_expires_at  timestamptz,
          heartbeat_at      timestamptz,
          not_before        timestamptz,
          deadline_at       timestamptz,
          intent            jsonb,
          evidence          jsonb,
          error_class       text CHECK (error_class IN ('retryable', 'needs_human', 'fatal')),
          error             jsonb,
          destructive       boolean NOT NULL DEFAULT false,
          params            jsonb NOT NULL DEFAULT '{{}}'::jsonb,
          -- step timeout (seconds); deadline_at = now() + timeout_seconds when the step becomes ready
          timeout_seconds   double precision,
          -- attempts <= retry_floor do not count against the retry budget (reset by an operator retry-step)
          retry_floor       integer NOT NULL DEFAULT 0,
          created_at        timestamptz NOT NULL DEFAULT now(),
          updated_at        timestamptz NOT NULL DEFAULT now(),
          finished_at       timestamptz,
          UNIQUE (run_id, seq),
          CHECK (state <> 'running' OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL
                                        AND fencing_token IS NOT NULL))
        )
        """
    )
    # ADR-0003: one running step per run.
    op.execute(
        "CREATE UNIQUE INDEX workflow_step_one_running_per_run ON workflow_step (run_id) "
        "WHERE state = 'running'"
    )
    # Stricter than data-model.md (reported): renewal steps are strictly sequential, so at most one *open* step
    # per run. Makes a double-append (e.g. a transition applied twice) impossible at the DB level.
    op.execute(
        "CREATE UNIQUE INDEX workflow_step_one_open_per_run ON workflow_step (run_id) "
        "WHERE state IN ('ready', 'running', 'waiting', 'needs_human')"
    )
    op.execute("CREATE INDEX workflow_step_ready_idx ON workflow_step (state, not_before)")
    op.execute("CREATE INDEX workflow_step_lease_idx ON workflow_step (state, lease_expires_at)")

    op.execute(
        """
        CREATE TABLE workflow_step_attempt (
          id             uuid PRIMARY KEY,
          step_id        uuid NOT NULL REFERENCES workflow_step(id),
          attempt        integer NOT NULL,
          fencing_token  bigint NOT NULL,
          worker_id      text NOT NULL,
          takeover       boolean NOT NULL DEFAULT false,
          started_at     timestamptz NOT NULL DEFAULT now(),
          ended_at       timestamptz,
          outcome        text,
          error_class    text,
          evidence       jsonb,
          UNIQUE (step_id, attempt)
        )
        """
    )

    op.execute(
        f"""
        CREATE TABLE run_signal (
          id           uuid PRIMARY KEY,
          run_id       uuid NOT NULL REFERENCES workflow_run(id),
          kind         text NOT NULL CHECK (kind IN ({_in(SIGNAL_KINDS)})),
          actor_id     uuid,
          approval_id  uuid,
          payload      jsonb NOT NULL DEFAULT '{{}}'::jsonb,
          created_at   timestamptz NOT NULL DEFAULT now(),
          consumed_at  timestamptz,
          outcome      text,
          CHECK ((consumed_at IS NULL) = (outcome IS NULL))
        )
        """
    )
    op.execute(
        "CREATE INDEX run_signal_pending_idx ON run_signal (created_at) WHERE consumed_at IS NULL"
    )

    op.execute(
        """
        CREATE TABLE resource_lock (
          resource_type  text NOT NULL CHECK (resource_type IN
                           ('service', 'server', 'volume', 'floating_ip', 'port')),
          resource_key   text NOT NULL,
          holder_run_id  uuid NOT NULL REFERENCES workflow_run(id),
          acquired_at    timestamptz NOT NULL DEFAULT now(),
          reason         text,
          PRIMARY KEY (resource_type, resource_key)
        )
        """
    )
    op.execute("CREATE INDEX resource_lock_holder_idx ON resource_lock (holder_run_id)")

    op.execute(
        """
        CREATE TABLE worker_heartbeat (
          worker_id     text PRIMARY KEY,
          hostname      text NOT NULL,
          started_at    timestamptz NOT NULL DEFAULT now(),
          last_seen_at  timestamptz NOT NULL DEFAULT now(),
          version       text NOT NULL,
          draining      boolean NOT NULL DEFAULT false
        )
        """
    )

    # SEC-R-1: the api inserts runs only in 'requested', with no execution columns set; signals unconsumed.
    op.execute(
        """
        CREATE FUNCTION workflow_api_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF current_user = 'ovlm_api' THEN
            IF TG_TABLE_NAME = 'workflow_run' AND (
                 NEW.state <> 'requested' OR NEW.abort_requested OR NEW.phase IS NOT NULL
                 OR NEW.admitted_at IS NOT NULL OR NEW.finished_at IS NOT NULL
                 OR NEW.needs_human_reason IS NOT NULL OR NEW.auto_restore_used) THEN
              RAISE EXCEPTION 'ovlm_api may only insert workflow_run rows in state requested'
                USING ERRCODE = 'insufficient_privilege';
            END IF;
            IF TG_TABLE_NAME = 'run_signal' AND (NEW.consumed_at IS NOT NULL OR NEW.outcome IS NOT NULL) THEN
              RAISE EXCEPTION 'ovlm_api may only insert unconsumed run_signal rows'
                USING ERRCODE = 'insufficient_privilege';
            END IF;
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    for table in ("workflow_run", "run_signal"):
        op.execute(
            f"CREATE TRIGGER {table}_api_insert_guard BEFORE INSERT ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION workflow_api_insert_guard()"
        )

    tables = (
        "workflow_run",
        "workflow_step",
        "workflow_step_attempt",
        "run_signal",
        "resource_lock",
        "worker_heartbeat",
    )
    for table in tables:
        op.execute(f"GRANT SELECT ON {table} TO ovlm_api")
    op.execute("GRANT INSERT ON workflow_run, run_signal TO ovlm_api")

    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON workflow_run, workflow_step, workflow_step_attempt, "
        "worker_heartbeat TO ovlm_worker"
    )
    op.execute("GRANT SELECT, INSERT, DELETE ON resource_lock TO ovlm_worker")
    op.execute("GRANT DELETE ON worker_heartbeat TO ovlm_worker")
    # The worker may insert signals (scheduler re-probe) but only update the consumption columns.
    op.execute("GRANT SELECT, INSERT ON run_signal TO ovlm_worker")
    op.execute("GRANT UPDATE (consumed_at, outcome) ON run_signal TO ovlm_worker")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE fencing_seq TO ovlm_worker")


def downgrade() -> None:
    # Supported path is "restore backup" (architecture.md section 9); kept for local development only.
    for table in (
        "worker_heartbeat",
        "resource_lock",
        "run_signal",
        "workflow_step_attempt",
        "workflow_step",
        "workflow_run",
    ):
        op.execute(f"DROP TABLE {table}")
    op.execute("DROP FUNCTION workflow_api_insert_guard()")
    op.execute("DROP SEQUENCE fencing_seq")
