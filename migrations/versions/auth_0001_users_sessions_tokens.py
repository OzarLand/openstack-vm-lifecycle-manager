"""Auth tables: users, enrolment links, sessions, step-up records, API tokens, role bindings, login attempts.

Revision ID: auth_0001
Revises: 0001_baseline

Grants (data-model.md section 12): ``ovlm_api`` reads and writes; ``ovlm_worker`` may only SELECT users (without
the credential columns), step-up records and role bindings, to re-validate approvals. Nothing on sessions,
tokens, enrolment links or login attempts.
"""

from alembic import op

revision = "auth_0001"
down_revision = "0001_baseline"
branch_labels = ("auth",)
depends_on = None

_ROLES = "('viewer','operator','approver','admin')"


def upgrade() -> None:
    op.execute(
        f"""
        CREATE TABLE app_user (
          id                  uuid PRIMARY KEY,
          username            text NOT NULL CHECK (username ~ '^[a-z0-9][a-z0-9._@-]{{2,63}}$'),
          display_name        text NOT NULL DEFAULT '',
          state               text NOT NULL CHECK (state IN ('pending_enrolment','active','disabled')),
          password_hash       text,
          password_changed_at timestamptz,
          totp_secret_enc     bytea,
          totp_confirmed_at   timestamptz,
          totp_last_step      bigint,
          created_via         text NOT NULL CHECK (created_via IN ('cli','admin')),
          created_by          uuid REFERENCES app_user(id),
          created_at          timestamptz NOT NULL DEFAULT now(),
          updated_at          timestamptz NOT NULL DEFAULT now(),
          credential_reset_by uuid REFERENCES app_user(id),
          credential_reset_at timestamptz,
          disabled_at         timestamptz,
          CHECK (state = 'pending_enrolment' OR password_hash IS NOT NULL),
          CHECK (totp_confirmed_at IS NULL OR totp_secret_enc IS NOT NULL)
        );
        CREATE UNIQUE INDEX app_user_username_key ON app_user (username);

        CREATE TABLE enrolment_link (
          id          uuid PRIMARY KEY,
          user_id     uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
          purpose     text NOT NULL CHECK (purpose IN ('enrol','reset')),
          secret_hash text NOT NULL,
          created_by  uuid REFERENCES app_user(id),
          created_at  timestamptz NOT NULL DEFAULT now(),
          expires_at  timestamptz NOT NULL,
          used_at     timestamptz,
          revoked_at  timestamptz
        );
        CREATE INDEX enrolment_link_user_idx ON enrolment_link (user_id);

        CREATE TABLE auth_session (
          id_hash      text PRIMARY KEY,
          user_id      uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
          csrf_token   text NOT NULL,
          auth_method  text NOT NULL CHECK (auth_method IN ('password','password+totp')),
          source_ip    text,
          created_at   timestamptz NOT NULL DEFAULT now(),
          last_seen_at timestamptz NOT NULL DEFAULT now(),
          expires_at   timestamptz NOT NULL
        );
        CREATE INDEX auth_session_user_idx ON auth_session (user_id);

        CREATE TABLE stepup (
          id              uuid PRIMARY KEY,
          user_id         uuid NOT NULL REFERENCES app_user(id),
          session_id_hash text NOT NULL,
          action          text NOT NULL CHECK (action <> ''),
          target_id       text NOT NULL CHECK (target_id <> ''),
          auth_method     text NOT NULL,
          created_at      timestamptz NOT NULL DEFAULT now(),
          expires_at      timestamptz NOT NULL,
          consumed_at     timestamptz,
          CHECK (expires_at <= created_at + interval '5 minutes')
        );
        CREATE INDEX stepup_user_idx ON stepup (user_id);

        CREATE TABLE api_token (
          id           uuid PRIMARY KEY,
          user_id      uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
          name         text NOT NULL,
          secret_hash  text NOT NULL,
          scopes       text[] NOT NULL CHECK (
                         cardinality(scopes) > 0 AND scopes <@ ARRAY['read','inventory:sync','operate']),
          project_scope text NOT NULL DEFAULT 'global'
                         CHECK (project_scope = 'global' OR project_scope ~ '^project:[A-Za-z0-9-]{{1,64}}$'),
          created_at   timestamptz NOT NULL DEFAULT now(),
          expires_at   timestamptz NOT NULL,
          last_used_at timestamptz,
          revoked_at   timestamptz,
          revoked_by   uuid REFERENCES app_user(id),
          CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days')
        );
        CREATE INDEX api_token_user_idx ON api_token (user_id);

        CREATE TABLE role_binding (
          id         uuid PRIMARY KEY,
          user_id    uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
          role       text NOT NULL CHECK (role IN {_ROLES}),
          scope      text NOT NULL CHECK (scope = 'global' OR scope ~ '^project:[A-Za-z0-9-]{{1,64}}$'),
          created_by uuid REFERENCES app_user(id),
          created_at timestamptz NOT NULL DEFAULT now(),
          revoked_at timestamptz,
          revoked_by uuid REFERENCES app_user(id)
        );
        CREATE UNIQUE INDEX role_binding_active_key ON role_binding (user_id, role, scope)
          WHERE revoked_at IS NULL;

        CREATE TABLE login_attempt (
          id        bigserial PRIMARY KEY,
          ts        timestamptz NOT NULL DEFAULT now(),
          kind      text NOT NULL CHECK (kind IN ('login','reauth','totp')),
          username  text NOT NULL,
          source_ip text,
          success   boolean NOT NULL
        );
        CREATE INDEX login_attempt_user_idx ON login_attempt (username, ts);
        CREATE INDEX login_attempt_ip_idx ON login_attempt (source_ip, ts);
        """
    )
    op.execute(
        """
        GRANT SELECT, INSERT, UPDATE ON app_user, enrolment_link, stepup, api_token, role_binding
          TO ovlm_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON auth_session TO ovlm_api;
        GRANT SELECT, INSERT, DELETE ON login_attempt TO ovlm_api;
        GRANT USAGE ON SEQUENCE login_attempt_id_seq TO ovlm_api;

        -- worker: re-validation only, never the credential columns
        GRANT SELECT (id, username, display_name, state, created_via, created_by, created_at,
                      credential_reset_by, credential_reset_at, totp_confirmed_at, disabled_at)
          ON app_user TO ovlm_worker;
        GRANT SELECT ON stepup, role_binding TO ovlm_worker;
        """
    )


def downgrade() -> None:
    for table in (
        "login_attempt",
        "role_binding",
        "api_token",
        "stepup",
        "auth_session",
        "enrolment_link",
        "app_user",
    ):
        op.execute(f"DROP TABLE {table}")
