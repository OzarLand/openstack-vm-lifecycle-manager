"""Connections and the credential store: cloud, project_connection, sealed_secret, credential_ref
(data-model.md sections 2 and 12, security-model.md 4.4 and 5.1).

Revision ID: connections_0001
Revises: renewal_0001

Own branch label. Deviation from "down_revision is the baseline" (as registry_0001 did): the schema checks need a
single head, so this revision follows the current head ``renewal_0001``; it changes no other module's table.
``service.project_connection_id`` keeps no foreign key here (the registry's table; the merge revision may add it).

Grants (data-model.md 12, narrowed):

* ``ovlm_api``: read/write ``cloud`` and ``project_connection``. ``sealed_secret``: INSERT and DELETE, and SELECT on
  the metadata columns only, **never** on ``wrapped_dek``, ``nonce`` or ``ciphertext``. ``credential_ref``: SELECT,
  INSERT (a trigger forces ``state = 'pending'`` and empty validation columns), DELETE, and UPDATE of
  ``validation_requested_at`` only. So the api can neither read ciphertext nor mark a credential valid or active.
* ``ovlm_worker``: SELECT on all four; UPDATE on ``sealed_secret`` wrap columns (KEK re-wrap) and on the
  ``credential_ref`` validation and state columns (it validates and switches credentials).
"""

from alembic import op

revision = "connections_0001"
down_revision = "renewal_0001"
branch_labels = ("connections",)
depends_on = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE cloud (
          id               uuid PRIMARY KEY,
          name             text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$'),
          auth_url         text NOT NULL CHECK (auth_url ~ '^https://[^/?#@\s]+(/[^?#\s]*)?$'),
          region           text NOT NULL CHECK (length(region) BETWEEN 1 AND 255),
          interface        text NOT NULL DEFAULT 'public' CHECK (interface IN ('public', 'internal')),
          ca_bundle_pem    text,
          ca_bundle_sha256 text CHECK (ca_bundle_sha256 ~ '^[0-9a-f]{64}$'),
          version          integer NOT NULL DEFAULT 1,
          created_by       uuid,
          created_at       timestamptz NOT NULL DEFAULT now(),
          updated_at       timestamptz NOT NULL DEFAULT now(),
          CHECK ((ca_bundle_pem IS NULL) = (ca_bundle_sha256 IS NULL))
        )
        """
    )
    op.execute(
        r"""
        CREATE TABLE project_connection (
          id                     uuid PRIMARY KEY,
          cloud_id               uuid NOT NULL REFERENCES cloud (id),
          openstack_project_id   text NOT NULL CHECK (openstack_project_id ~ '^[0-9a-f]{32}$'),
          openstack_project_name text NOT NULL CHECK (length(openstack_project_name) BETWEEN 1 AND 255),
          name                   text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$'),
          guest_access           jsonb NOT NULL DEFAULT '{}'::jsonb,
          enabled                boolean NOT NULL DEFAULT true,
          version                integer NOT NULL DEFAULT 1,
          created_by             uuid,
          created_at             timestamptz NOT NULL DEFAULT now(),
          updated_at             timestamptz NOT NULL DEFAULT now(),
          UNIQUE (cloud_id, openstack_project_id)
        )
        """
    )
    op.execute(
        r"""
        CREATE TABLE sealed_secret (
          id           uuid PRIMARY KEY,
          alg          text NOT NULL CHECK (alg = 'ovlm-env-v1'),
          kek_id       text NOT NULL CHECK (kek_id ~ '^[0-9a-f]{16}$'),
          wrapped_dek  bytea NOT NULL CHECK (octet_length(wrapped_dek) = 92),
          nonce        bytea NOT NULL CHECK (octet_length(nonce) = 12),
          ciphertext   bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 16400),
          created_at   timestamptz NOT NULL DEFAULT now(),
          rewrapped_at timestamptz
        )
        """
    )
    op.execute(
        r"""
        CREATE TABLE credential_ref (
          id                      uuid PRIMARY KEY,
          project_connection_id   uuid NOT NULL REFERENCES project_connection (id),
          kind                    text NOT NULL
                                  CHECK (kind IN ('os_read', 'os_write', 'ssh_key', 'vault_password', 'secret')),
          service_id              uuid,
          secret_id               uuid NOT NULL UNIQUE REFERENCES sealed_secret (id),
          app_credential_id       text CHECK (app_credential_id ~ '^[0-9a-f]{32}$'),
          ssh_public_key          text,
          expires_at              timestamptz,
          state                   text NOT NULL DEFAULT 'pending'
                                  CHECK (state IN ('pending', 'active', 'superseded', 'rejected')),
          superseded_by           uuid REFERENCES credential_ref (id) ON DELETE SET NULL,
          validation_requested_at timestamptz NOT NULL DEFAULT now(),
          last_validated_at       timestamptz,
          validation_result       jsonb,
          rotated_at              timestamptz,
          cloud_deletion_pending  boolean NOT NULL DEFAULT false,
          created_by              uuid,
          created_at              timestamptz NOT NULL DEFAULT now(),
          updated_at              timestamptz NOT NULL DEFAULT now(),
          CHECK (service_id IS NOT NULL OR kind IN ('os_read', 'os_write', 'ssh_key')),
          CHECK (kind NOT IN ('os_read', 'os_write') OR (app_credential_id IS NOT NULL AND expires_at IS NOT NULL)),
          CHECK (kind <> 'ssh_key' OR ssh_public_key IS NOT NULL)
        )
        """
    )
    # One active and one pending credential per (project, kind) for the per-project kinds (data-model.md 2).
    for state in ("active", "pending"):
        op.execute(
            f"CREATE UNIQUE INDEX credential_ref_one_{state} ON credential_ref (project_connection_id, kind) "
            f"WHERE state = '{state}' AND kind IN ('os_read', 'os_write', 'ssh_key')"
        )
    op.execute("CREATE INDEX credential_ref_due ON credential_ref (validation_requested_at)")
    op.execute("CREATE INDEX project_connection_created ON project_connection (created_at, id)")

    # The api may only insert an unvalidated, pending credential (it cannot vouch for one).
    op.execute(
        """
        CREATE FUNCTION credential_ref_api_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF current_user = 'ovlm_api' AND (
               NEW.state <> 'pending' OR NEW.last_validated_at IS NOT NULL OR NEW.validation_result IS NOT NULL
               OR NEW.superseded_by IS NOT NULL OR NEW.rotated_at IS NOT NULL OR NEW.cloud_deletion_pending) THEN
            RAISE EXCEPTION 'ovlm_api may only insert pending, unvalidated credentials';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER credential_ref_api_insert BEFORE INSERT ON credential_ref "
        "FOR EACH ROW EXECUTE FUNCTION credential_ref_api_insert_guard()"
    )

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON cloud, project_connection TO ovlm_api")
    op.execute("GRANT INSERT, DELETE ON sealed_secret TO ovlm_api")
    op.execute(
        "GRANT SELECT (id, alg, kek_id, created_at, rewrapped_at) ON sealed_secret TO ovlm_api"
    )
    op.execute("GRANT SELECT, INSERT, DELETE ON credential_ref TO ovlm_api")
    op.execute("GRANT UPDATE (validation_requested_at, updated_at) ON credential_ref TO ovlm_api")

    op.execute(
        "GRANT SELECT ON cloud, project_connection, sealed_secret, credential_ref TO ovlm_worker"
    )
    op.execute("GRANT UPDATE (kek_id, wrapped_dek, rewrapped_at) ON sealed_secret TO ovlm_worker")
    op.execute(
        "GRANT UPDATE (state, superseded_by, last_validated_at, validation_result, rotated_at, "
        "cloud_deletion_pending, updated_at) ON credential_ref TO ovlm_worker"
    )


def downgrade() -> None:
    op.execute("DROP TABLE credential_ref")
    op.execute("DROP FUNCTION credential_ref_api_insert_guard()")
    op.execute("DROP TABLE sealed_secret")
    op.execute("DROP TABLE project_connection")
    op.execute("DROP TABLE cloud")
