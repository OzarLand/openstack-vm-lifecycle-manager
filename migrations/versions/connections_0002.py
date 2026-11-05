"""Credential store review fixes (docs/reviews/review-credential-store.md): destination binding, no rebinding,
Keystone-verified expiry, worker key announcement, orphan sweep.

Revision ID: connections_0002
Revises: connections_0001

* ``credential_ref.cloud_id`` and ``endpoint_sha256`` (CS-1, CS-2): the destination a secret was sealed for; also in
  its AAD (format ``ovlm-env-v2``). Existing credentials were sealed with ``ovlm-env-v1`` (row only, no destination):
  pending and active ones are **rejected** here with a reason, and must be uploaded again. No real credential has
  been uploaded before this revision (the review blocked the lab), so this costs nothing in practice.
* No rebinding (CS-2): a trigger refuses any change of a binding column (id, connection, kind, secret, cloud,
  endpoint, Keystone id, uploaded expiry, SSH public key) by **every** role; deleted credential ids and secret ids are
  tomb-stoned (``credential_ref_tombstone``, written by a ``SECURITY DEFINER`` trigger) and can never be inserted
  again; the api's insert must name the connection's current cloud. ``ovlm_api`` loses ``UPDATE`` of
  ``project_connection.cloud_id`` and ``openstack_project_id`` (fixed once created, as the service already says).
* ``credential_ref.verified_expires_at`` (CS-3): the expiry Keystone reports, written by the worker only.
* ``kek_key`` (CS-5, CS-10): the key ids the worker holds; the api seals only to one of them.
* ``ovlm_worker`` gets ``DELETE`` on ``sealed_secret`` (orphan sweep, CS-9).
* ``sealed_secret.alg`` accepts ``ovlm-env-v2`` (``v1`` rows remain readable as metadata, refused by the worker).
"""

from alembic import op

revision = "connections_0002"
down_revision = "connections_0001"
branch_labels = None
depends_on = None

_LEGACY_REASON = (
    '{"ok": false, "reason": "sealed with the retired format ovlm-env-v1, not bound to its endpoint '
    '(credential store review CS-1/CS-2): upload the credential again", "roles": [], "user_id": null, '
    '"transient": false}'
)


def upgrade() -> None:
    op.execute("ALTER TABLE sealed_secret DROP CONSTRAINT sealed_secret_alg_check")
    op.execute(
        "ALTER TABLE sealed_secret ADD CONSTRAINT sealed_secret_alg_check "
        "CHECK (alg IN ('ovlm-env-v1', 'ovlm-env-v2'))"
    )

    op.execute(
        "ALTER TABLE credential_ref ADD COLUMN cloud_id uuid REFERENCES cloud (id), "
        "ADD COLUMN endpoint_sha256 text CHECK (endpoint_sha256 ~ '^[0-9a-f]{64}$'), "
        "ADD COLUMN verified_expires_at timestamptz"
    )
    # Legacy rows: bound to nothing; the all-zero digest never matches a live endpoint.
    op.execute(
        "UPDATE credential_ref r SET cloud_id = p.cloud_id, endpoint_sha256 = repeat('0', 64) "
        "FROM project_connection p WHERE p.id = r.project_connection_id"
    )
    op.execute(
        f"UPDATE credential_ref SET state = 'rejected', validation_result = '{_LEGACY_REASON}'::jsonb, "  # noqa: S608
        "last_validated_at = now(), updated_at = now() WHERE state IN ('pending', 'active')"
    )
    op.execute(
        "ALTER TABLE credential_ref ALTER COLUMN cloud_id SET NOT NULL, "
        "ALTER COLUMN endpoint_sha256 SET NOT NULL"
    )

    op.execute(
        """
        CREATE TABLE credential_ref_tombstone (
          id                    uuid PRIMARY KEY,
          secret_id             uuid NOT NULL UNIQUE,
          project_connection_id uuid NOT NULL,
          deleted_by_role       text NOT NULL,
          deleted_at            timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE FUNCTION credential_ref_tombstone_record() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
        BEGIN
          INSERT INTO credential_ref_tombstone (id, secret_id, project_connection_id, deleted_by_role)
          VALUES (OLD.id, OLD.secret_id, OLD.project_connection_id, session_user)
          ON CONFLICT DO NOTHING;
          RETURN OLD;
        END $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION credential_ref_tombstone_record() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER credential_ref_tombstone AFTER DELETE ON credential_ref "
        "FOR EACH ROW EXECUTE FUNCTION credential_ref_tombstone_record()"
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION credential_ref_api_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF EXISTS (SELECT 1 FROM credential_ref_tombstone t WHERE t.id = NEW.id OR t.secret_id = NEW.secret_id) THEN
            RAISE EXCEPTION 'credential id or secret id was used by a deleted credential: it cannot be re-inserted';
          END IF;
          IF current_user = 'ovlm_api' AND (
               NEW.state <> 'pending' OR NEW.last_validated_at IS NOT NULL OR NEW.validation_result IS NOT NULL
               OR NEW.superseded_by IS NOT NULL OR NEW.rotated_at IS NOT NULL OR NEW.cloud_deletion_pending
               OR NEW.verified_expires_at IS NOT NULL) THEN
            RAISE EXCEPTION 'ovlm_api may only insert pending, unvalidated credentials';
          END IF;
          IF NOT EXISTS (SELECT 1 FROM project_connection p
                         WHERE p.id = NEW.project_connection_id AND p.cloud_id = NEW.cloud_id) THEN
            RAISE EXCEPTION 'a credential must be bound to its connection''s cloud';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION credential_ref_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.id IS DISTINCT FROM OLD.id
             OR NEW.project_connection_id IS DISTINCT FROM OLD.project_connection_id
             OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
             OR NEW.cloud_id IS DISTINCT FROM OLD.cloud_id OR NEW.endpoint_sha256 IS DISTINCT FROM OLD.endpoint_sha256
             OR NEW.app_credential_id IS DISTINCT FROM OLD.app_credential_id
             OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
             OR NEW.ssh_public_key IS DISTINCT FROM OLD.ssh_public_key
             OR NEW.service_id IS DISTINCT FROM OLD.service_id THEN
            RAISE EXCEPTION 'the binding of a credential is immutable: upload a new credential instead';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER credential_ref_binding BEFORE UPDATE ON credential_ref "
        "FOR EACH ROW EXECUTE FUNCTION credential_ref_binding_guard()"
    )

    op.execute(
        """
        CREATE TABLE kek_key (
          kek_id       text PRIMARY KEY CHECK (kek_id ~ '^[0-9a-f]{16}$'),
          is_current   boolean NOT NULL,
          announced_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )

    op.execute("REVOKE UPDATE ON project_connection FROM ovlm_api")
    op.execute(
        "GRANT UPDATE (openstack_project_name, guest_access, enabled, version, updated_at) "
        "ON project_connection TO ovlm_api"
    )
    op.execute("GRANT SELECT ON credential_ref_tombstone, kek_key TO ovlm_api, ovlm_worker")
    op.execute("GRANT INSERT, UPDATE, DELETE ON kek_key TO ovlm_worker")
    op.execute("GRANT UPDATE (verified_expires_at) ON credential_ref TO ovlm_worker")
    op.execute("GRANT DELETE ON sealed_secret TO ovlm_worker")


def downgrade() -> None:
    op.execute("REVOKE DELETE ON sealed_secret FROM ovlm_worker")
    op.execute("REVOKE UPDATE ON project_connection FROM ovlm_api")
    op.execute("GRANT UPDATE ON project_connection TO ovlm_api")
    op.execute("DROP TABLE kek_key")
    op.execute("DROP TRIGGER credential_ref_binding ON credential_ref")
    op.execute("DROP FUNCTION credential_ref_binding_guard()")
    op.execute("DROP TRIGGER credential_ref_tombstone ON credential_ref")
    op.execute("DROP FUNCTION credential_ref_tombstone_record()")
    op.execute("DROP TABLE credential_ref_tombstone")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION credential_ref_api_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
    # v2 secrets are unreadable by v1 code: drop them with their credentials
    op.execute(
        "DELETE FROM credential_ref WHERE secret_id IN (SELECT id FROM sealed_secret WHERE alg <> 'ovlm-env-v1')"
    )
    op.execute(
        "ALTER TABLE credential_ref DROP COLUMN verified_expires_at, DROP COLUMN endpoint_sha256, "
        "DROP COLUMN cloud_id"
    )
    op.execute("ALTER TABLE sealed_secret DROP CONSTRAINT sealed_secret_alg_check")
    op.execute("DELETE FROM sealed_secret WHERE alg <> 'ovlm-env-v1'")
    op.execute(
        "ALTER TABLE sealed_secret ADD CONSTRAINT sealed_secret_alg_check CHECK (alg = 'ovlm-env-v1')"
    )
