"""Lint waivers (automation-contract.md 9, data-model.md ``lint_waiver``, SEC-R-36; security follow-up SF-13).

Revision ID: profiles_0002
Revises: connections_0003

An approver's audited exception to one blocking lint rule, for **one profile version**, on the repository paths a glob
matches, with a reason. Granted through ``POST /api/v1/profiles/{id}/versions/{n}/lint-waivers`` (human session, TOTP
step-up bound to the version; never the version's author nor a requester of a plan on it), listed, and revoked.
The worker's B6 lint loads the active waivers of the run's profile version, and the plan hash binds them, so a
waiver granted or revoked after an approval voids it.

* Append-only: no DELETE grant; a trigger keeps every column immutable except the four revocation columns, which can
  be set once (a revoked waiver stays revoked).
* ``rule`` is limited to the rules a waiver may cover. The data-safety rules (``formatting``, ``quiesce_state``,
  ``ssh_override``, ``hosts_pattern``) and ``parse_error`` can never be waived, whoever writes the row.
* ``stepup_id`` is unique: one step-up, one waiver.

Linear after ``connections_0003`` so the schema keeps a single head (``check_schema_at_head``).
"""

from alembic import op

revision = "profiles_0002"
down_revision = "connections_0003"
branch_labels = ("lint_waiver",)
depends_on = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE lint_waiver (
          id                 uuid PRIMARY KEY,
          profile_version_id uuid NOT NULL REFERENCES profile_version (id),
          rule               text NOT NULL CHECK (rule IN
                               ('no_log_secret', 'check_mode_forced', 'delegate_to', 'ignore_errors')),
          path_glob          text NOT NULL CHECK (path_glob ~ '^[A-Za-z0-9_.*?/\[\]-]{1,200}$'
                               AND path_glob !~ '^/' AND path_glob !~ '(^|/)\.\.(/|$)'),
          reason             text NOT NULL CHECK (length(btrim(reason)) BETWEEN 10 AND 1000),
          granted_by         uuid NOT NULL REFERENCES app_user (id),
          granted_at         timestamptz NOT NULL DEFAULT now(),
          stepup_id          uuid NOT NULL UNIQUE REFERENCES stepup (id),
          revoked_by         uuid REFERENCES app_user (id),
          revoked_at         timestamptz,
          revoke_stepup_id   uuid UNIQUE REFERENCES stepup (id),
          revoke_reason      text CHECK (revoke_reason IS NULL OR length(btrim(revoke_reason)) BETWEEN 10 AND 1000),
          CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
          CHECK ((revoked_at IS NULL) = (revoke_stepup_id IS NULL)),
          CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
        )
        """
    )
    op.execute(
        "CREATE INDEX lint_waiver_version ON lint_waiver (profile_version_id, granted_at, id)"
    )
    op.execute(
        """
        CREATE FUNCTION lint_waiver_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'lint_waiver rows are append-only (SEC-R-36)';
          END IF;
          IF TG_OP = 'INSERT' THEN
            IF NEW.revoked_at IS NOT NULL THEN
              RAISE EXCEPTION 'a lint waiver is inserted active';
            END IF;
            RETURN NEW;
          END IF;
          IF (NEW.id, NEW.profile_version_id, NEW.rule, NEW.path_glob, NEW.reason, NEW.granted_by, NEW.granted_at,
              NEW.stepup_id)
             IS DISTINCT FROM
             (OLD.id, OLD.profile_version_id, OLD.rule, OLD.path_glob, OLD.reason, OLD.granted_by, OLD.granted_at,
              OLD.stepup_id) THEN
            RAISE EXCEPTION 'a lint waiver is immutable; revoke it and grant a new one';
          END IF;
          IF OLD.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'a revoked lint waiver stays revoked';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER lint_waiver_append_only BEFORE INSERT OR UPDATE OR DELETE ON lint_waiver "
        "FOR EACH ROW EXECUTE FUNCTION lint_waiver_append_only()"
    )
    op.execute("GRANT SELECT, INSERT ON lint_waiver TO ovlm_api")
    op.execute(
        "GRANT UPDATE (revoked_by, revoked_at, revoke_stepup_id, revoke_reason) ON lint_waiver TO ovlm_api"
    )
    op.execute("GRANT SELECT ON lint_waiver TO ovlm_worker")


def downgrade() -> None:
    op.execute("DROP TABLE lint_waiver")
    op.execute("DROP FUNCTION lint_waiver_append_only()")
