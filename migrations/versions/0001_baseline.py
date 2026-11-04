"""Baseline: DB roles, grants skeleton and the ``schema_meta`` table. No domain tables.

Revision ID: 0001_baseline
Revises:

Roles (data-model.md section 12, security-model.md section 9):

* ``ovlm_owner``  - owns all objects, runs migrations (the ``migrate`` service only).
* ``ovlm_api``    - runtime role of the api process.
* ``ovlm_worker`` - runtime role of the worker process.

Roles are cluster-wide objects: they are created only when missing. In the Compose deployment the Postgres
init script creates all three (with passwords from secret files) before this migration runs, because the
migration itself connects as ``ovlm_owner`` (CREATEROLE, not superuser). Passwords are never set here.
Per-table grants are added by the migration that creates each table; this baseline only gives the runtime
roles the right to connect, to use the schema and to read ``schema_meta`` / ``alembic_version``.
"""

from alembic import op

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None

_ROLES = ("ovlm_owner", "ovlm_api", "ovlm_worker")


def upgrade() -> None:
    for role in _ROLES:
        # NOSUPERUSER etc. are the defaults but stated so a reader sees the intent.
        extra = " CREATEROLE" if role == "ovlm_owner" else ""
        op.execute(
            f"""
            DO $$
            BEGIN
              IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN
                CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS{extra};
              END IF;
            END
            $$;
            """
        )

    # Only the three roles (and superusers) may connect; no implicit access for PUBLIC.
    op.execute(
        """
        DO $$
        BEGIN
          EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
          EXECUTE format('GRANT CONNECT ON DATABASE %I TO ovlm_owner, ovlm_api, ovlm_worker', current_database());
        END
        $$;
        """
    )
    op.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA public TO ovlm_api, ovlm_worker")

    op.execute(
        """
        CREATE TABLE schema_meta (
          key   text PRIMARY KEY,
          value text NOT NULL
        )
        """
    )
    op.execute("INSERT INTO schema_meta (key, value) VALUES ('schema_family', 'ovlm')")
    op.execute("GRANT SELECT ON schema_meta TO ovlm_api, ovlm_worker")
    # Needed by the "schema at head" start-up/readiness check of api and worker.
    op.execute("GRANT SELECT ON alembic_version TO ovlm_api, ovlm_worker")


def downgrade() -> None:
    # Roles are cluster-wide and may own or be granted objects elsewhere: never dropped here.
    # Supported downgrade path is "restore backup" (architecture.md section 9).
    op.execute("REVOKE SELECT ON alembic_version FROM ovlm_api, ovlm_worker")
    op.execute("DROP TABLE schema_meta")
