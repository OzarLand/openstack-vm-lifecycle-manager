"""Profiles and immutable profile versions (data-model.md section 5, SEC-R-36).

Revision ID: profiles_0001
Revises: 0003_merge

``ovlm_api`` may only INSERT profile versions: it has no UPDATE and no DELETE on ``profile_version``. The worker
may update the ``lint_result`` column and nothing else. A trigger repeats the rule for every other role, the table
owner included, so a changed ``spec`` cannot slip in through a mistaken grant. ``profile.service_id`` is UNIQUE:
one profile per service in the MVP. ``service.current_profile_id`` keeps no foreign key here (registry's table).
"""

from alembic import op

revision = "profiles_0001"
down_revision = "0003_merge"
branch_labels = ("profiles",)
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE profile (
          id             uuid PRIMARY KEY,
          service_id     uuid NOT NULL UNIQUE REFERENCES service (id),
          name           text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
          latest_version integer NOT NULL DEFAULT 0 CHECK (latest_version >= 0),
          version        integer NOT NULL DEFAULT 1,
          created_by     uuid,
          created_at     timestamptz NOT NULL DEFAULT now(),
          updated_at     timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE profile_version (
          id             uuid PRIMARY KEY,
          profile_id     uuid NOT NULL REFERENCES profile (id),
          number         integer NOT NULL CHECK (number >= 1),
          spec           jsonb NOT NULL,
          spec_hash      text NOT NULL CHECK (spec_hash ~ '^[0-9a-f]{64}$'),
          automation_sha text,
          created_by     uuid,
          created_at     timestamptz NOT NULL DEFAULT now(),
          lint_result    jsonb,
          UNIQUE (profile_id, number)
        )
        """
    )
    op.execute("CREATE INDEX profile_created ON profile (created_at, id)")
    op.execute(
        """
        CREATE FUNCTION profile_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'profile_version rows are immutable (SEC-R-36)';
          END IF;
          IF (NEW.id, NEW.profile_id, NEW.number, NEW.spec, NEW.spec_hash, NEW.automation_sha,
              NEW.created_by, NEW.created_at)
             IS DISTINCT FROM
             (OLD.id, OLD.profile_id, OLD.number, OLD.spec, OLD.spec_hash, OLD.automation_sha,
              OLD.created_by, OLD.created_at) THEN
            RAISE EXCEPTION 'profile_version is immutable except lint_result (SEC-R-36)';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER profile_version_immutable BEFORE UPDATE OR DELETE ON profile_version "
        "FOR EACH ROW EXECUTE FUNCTION profile_version_immutable()"
    )

    op.execute("GRANT SELECT, INSERT ON profile TO ovlm_api")
    op.execute("GRANT UPDATE (name, latest_version, version, updated_at) ON profile TO ovlm_api")
    op.execute("GRANT SELECT ON profile TO ovlm_worker")
    op.execute("GRANT SELECT, INSERT ON profile_version TO ovlm_api")  # no UPDATE, no DELETE
    op.execute("GRANT SELECT ON profile_version TO ovlm_worker")
    op.execute("GRANT UPDATE (lint_result) ON profile_version TO ovlm_worker")


def downgrade() -> None:
    op.execute("DROP TABLE profile_version")
    op.execute("DROP FUNCTION profile_version_immutable()")
    op.execute("DROP TABLE profile")
