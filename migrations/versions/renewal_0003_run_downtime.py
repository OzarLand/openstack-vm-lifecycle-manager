"""``run_downtime``: every downtime interval of a renewal run, not only the first (roadmap P0-3, lab finding AC).

Revision ID: renewal_0003
Revises: renewal_0002

One row per interval: ``kind`` ``window`` (opened by the W1 claim) or ``restore`` (opened by S2 when a revert or a
restore starts with the service up on green, i.e. no interval is open), ``started_at`` / ``started_by_step``,
``ended_at`` / ``ended_by_step`` (W10 or S9 success; ``NULL`` while the outage is ongoing).

* At most one open interval per run (partial unique index).
* Append-only in spirit: the worker inserts and may only **close** an open interval once (``ended_at``,
  ``ended_by_step`` from ``NULL`` to a value); a trigger refuses any other UPDATE, a DELETE and a TRUNCATE. No DELETE
  grant. The api reads.
* ``workflow_run.downtime_started_at`` / ``downtime_ended_at`` stay: they are the run's first interval (the window
  budget, the REN-1 outage seal and the retention timer read them). Backfill: one ``window`` row per run that has
  ``downtime_started_at``, with the same times; ``ended_by_step`` from the step that ended it (W10 or S9). Restore
  intervals of runs before this migration were never measured and are not invented.

Linear after ``renewal_0002`` so the schema keeps a single head.
"""

from alembic import op

revision = "renewal_0003"
down_revision = "renewal_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE run_downtime (
          id               uuid PRIMARY KEY,
          run_id           uuid NOT NULL REFERENCES workflow_run (id),
          kind             text NOT NULL CHECK (kind IN ('window', 'restore')),
          started_at       timestamptz NOT NULL,
          started_by_step  text NOT NULL,
          ended_at         timestamptz,
          ended_by_step    text,
          CHECK ((ended_at IS NULL) = (ended_by_step IS NULL)),
          CHECK (ended_at IS NULL OR ended_at >= started_at)
        );
        CREATE UNIQUE INDEX run_downtime_one_open ON run_downtime (run_id) WHERE ended_at IS NULL;
        CREATE INDEX run_downtime_run_idx ON run_downtime (run_id, started_at);

        CREATE FUNCTION run_downtime_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'UPDATE' AND OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL
             AND NEW.id = OLD.id AND NEW.run_id = OLD.run_id AND NEW.kind = OLD.kind
             AND NEW.started_at = OLD.started_at AND NEW.started_by_step = OLD.started_by_step THEN
            RETURN NEW;
          END IF;
          RAISE EXCEPTION 'run_downtime is append-only (an open interval may only be closed once): % refused', TG_OP;
        END
        $$;
        CREATE TRIGGER run_downtime_close_only
          BEFORE UPDATE OR DELETE ON run_downtime
          FOR EACH ROW EXECUTE FUNCTION run_downtime_guard();
        CREATE TRIGGER run_downtime_no_truncate
          BEFORE TRUNCATE ON run_downtime
          FOR EACH STATEMENT EXECUTE FUNCTION run_downtime_guard();
        """
    )
    # Backfill the first interval from the run columns (ids: random v4, the table only needs uniqueness).
    op.execute(
        """
        INSERT INTO run_downtime (id, run_id, kind, started_at, started_by_step, ended_at, ended_by_step)
        SELECT gen_random_uuid(), r.id, 'window', r.downtime_started_at, 'quiesce_old', r.downtime_ended_at,
               CASE WHEN r.downtime_ended_at IS NULL THEN NULL
                    WHEN EXISTS (SELECT 1 FROM workflow_step s WHERE s.run_id = r.id
                                 AND s.step_key = 'verify_external' AND s.state = 'succeeded')
                    THEN 'verify_external' ELSE 'verify_external_old' END
        FROM workflow_run r
        WHERE r.downtime_started_at IS NOT NULL
          AND (r.downtime_ended_at IS NULL OR r.downtime_ended_at >= r.downtime_started_at)
        """
    )
    op.execute("GRANT SELECT, INSERT ON run_downtime TO ovlm_worker")
    op.execute("GRANT UPDATE (ended_at, ended_by_step) ON run_downtime TO ovlm_worker")
    op.execute("GRANT SELECT ON run_downtime TO ovlm_api")


def downgrade() -> None:
    op.execute("DROP TABLE run_downtime")
    op.execute("DROP FUNCTION run_downtime_guard()")
