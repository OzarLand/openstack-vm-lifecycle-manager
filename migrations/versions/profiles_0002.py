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
* **Api guard** (review SFR-1, ``lint_waiver_api_guard``, for every non-superuser member of ``ovlm_api``): an insert
  needs the granter's own **consumed** password+TOTP step-up for ``lint_waiver.grant`` on that profile version, and
  a granter other than the version's author; a revocation needs the revoker's own consumed password+TOTP step-up for
  ``lint_waiver.revoke`` on the waiver id. The api consumes the step-up before the write, in the same transaction,
  so the trigger sees it. A compromised api can no longer write a waiver in someone else's name, nor reuse an
  unrelated step-up. What needs history (the approver role at ``granted_at``, the requester set) is re-checked by
  the worker before B6 applies a waiver and at every approval re-validation.
* ``path_glob`` keeps at least one literal path segment (review SFR-2): ``*``, ``**``, ``*/*``, ``**/*``, ``*/**`` or
  ``[a-z]*`` would waive the rule for the whole repository (``fnmatch``'s ``*`` matches ``/``). The api checks the same
  regex (``ovlm.profiles.waivers.LITERAL_SEGMENT``).

Linear after ``connections_0003`` so the schema keeps a single head (``check_schema_at_head``).
"""

from alembic import op

revision = "profiles_0002"
down_revision = "connections_0003"
branch_labels = ("lint_waiver",)
depends_on = None


#: Every non-superuser member of ``ovlm_api`` (as ``managed_vm_api_insert_guard`` since ``registry_0003``): a
#: deployment giving the api another login role must not switch the guard off. Superusers are left out
#: (``pg_has_role`` is always true for them, and they can disable any trigger anyway).
_API_MEMBER = (
    "(pg_has_role(current_user, 'ovlm_api', 'MEMBER') "
    "AND NOT (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = current_user))"
)


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE lint_waiver (
          id                 uuid PRIMARY KEY,
          profile_version_id uuid NOT NULL REFERENCES profile_version (id),
          rule               text NOT NULL CHECK (rule IN
                               ('no_log_secret', 'check_mode_forced', 'delegate_to', 'ignore_errors')),
          path_glob          text NOT NULL CHECK (path_glob ~ '^[A-Za-z0-9_.*?/\[\]-]{1,200}$'
                               AND path_glob !~ '^/' AND path_glob !~ '(^|/)\.\.(/|$)'
                               AND path_glob ~ '(^|/)[A-Za-z0-9_.-]*[A-Za-z0-9_-][A-Za-z0-9_.-]*(/|$)'),
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
    op.execute(
        f"""
        CREATE FUNCTION lint_waiver_api_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
        BEGIN
          IF NOT {_API_MEMBER} THEN
            RETURN NEW;
          END IF;
          IF TG_OP = 'INSERT' THEN
            IF NOT EXISTS (
                SELECT 1 FROM public.stepup s
                WHERE s.id = NEW.stepup_id AND s.user_id = NEW.granted_by AND s.action = 'lint_waiver.grant'
                  AND s.target_id = NEW.profile_version_id::text AND s.auth_method = 'password+totp'
                  AND s.consumed_at IS NOT NULL) THEN
              RAISE EXCEPTION 'lint waiver %: the step-up is not the granter''s consumed password+TOTP step-up '
                'for lint_waiver.grant on this profile version', NEW.id
                USING ERRCODE = 'insufficient_privilege';
            END IF;
            IF EXISTS (SELECT 1 FROM public.profile_version pv
                       WHERE pv.id = NEW.profile_version_id AND pv.created_by = NEW.granted_by) THEN
              RAISE EXCEPTION 'lint waiver %: the author of a profile version cannot waive its lint findings', NEW.id
                USING ERRCODE = 'insufficient_privilege';
            END IF;
          ELSIF NOT EXISTS (
              SELECT 1 FROM public.stepup s
              WHERE s.id = NEW.revoke_stepup_id AND s.user_id = NEW.revoked_by AND s.action = 'lint_waiver.revoke'
                AND s.target_id = NEW.id::text AND s.auth_method = 'password+totp'
                AND s.consumed_at IS NOT NULL) THEN
            RAISE EXCEPTION 'lint waiver %: the step-up is not the revoker''s consumed password+TOTP step-up '
              'for lint_waiver.revoke on this waiver', NEW.id
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER lint_waiver_api_guard BEFORE INSERT OR UPDATE ON lint_waiver "
        "FOR EACH ROW EXECUTE FUNCTION lint_waiver_api_guard()"
    )
    op.execute("GRANT SELECT, INSERT ON lint_waiver TO ovlm_api")
    op.execute(
        "GRANT UPDATE (revoked_by, revoked_at, revoke_stepup_id, revoke_reason) ON lint_waiver TO ovlm_api"
    )
    op.execute("GRANT SELECT ON lint_waiver TO ovlm_worker")


def downgrade() -> None:
    op.execute("DROP TABLE lint_waiver")
    op.execute("DROP FUNCTION lint_waiver_api_guard()")
    op.execute("DROP FUNCTION lint_waiver_append_only()")
