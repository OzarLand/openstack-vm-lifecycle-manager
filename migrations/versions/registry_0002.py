"""Registry review fixes (docs/reviews/review-inventory-sync-host-keys.md IS-1): blue's host-key trust in the database.

Revision ID: registry_0002
Revises: connections_0002

Part of the ``registry`` branch (label set on ``registry_0001``). It sits after ``connections_0002``, the single head
when it was written, so the history stays linear and needs no merge revision.

``ovlm_api`` may INSERT and DELETE ``managed_vm`` and UPDATE only ``host_key_confirmed_*``. Before this revision it
could delete a confirmed VM and insert it again **under the same id** with its own fingerprint, already confirmed;
a plan resolved afterwards snapshot the forged key. This revision closes it, as ``connections_0002`` closed the same
pattern for credentials:

* **Insert guard** (``managed_vm_api_insert_guard``, as ``workflow_run_api_insert_guard``): for
  ``current_user = 'ovlm_api'``, ``ssh_host_key_fingerprint``, ``host_key_confirmed_by`` and
  ``host_key_confirmed_at`` must be NULL. Only the worker's scan writes a fingerprint, only a confirmation sets
  ``host_key_confirmed_*``.
* **Tombstone** (``managed_vm_tombstone``): every deleted ``managed_vm`` id is recorded by a ``SECURITY DEFINER``
  AFTER DELETE trigger with a fixed ``search_path``; the insert guard refuses a tombstoned id for **every** role.
  Re-registering the same server gets a new id (``register_managed_vm`` always draws one), so this costs nothing.
* **Confirmation follows the fingerprint** (``managed_vm_host_key_follow``): any change of
  ``ssh_host_key_fingerprint`` clears ``host_key_confirmed_by`` and ``host_key_confirmed_at``, whoever writes it.
  The worker's scan already refuses to replace a confirmed key (its ``WHERE``); this is the second line.
* **Consistency** (``managed_vm_host_key_confirmation``): a confirmation names its confirmer and a fingerprint.

The guard functions run with ``search_path = pg_catalog, public, pg_temp``: ``pg_temp`` last, so a temporary table
cannot shadow the tombstone (``ovlm_api`` has no TEMP privilege either; ``0001_baseline``).
"""

from alembic import op

revision = "registry_0002"
down_revision = "connections_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE managed_vm_tombstone (
          id                  uuid PRIMARY KEY,
          openstack_server_id text NOT NULL,
          deleted_by_role     text NOT NULL,
          deleted_at          timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE FUNCTION managed_vm_tombstone_record() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
        BEGIN
          INSERT INTO public.managed_vm_tombstone (id, openstack_server_id, deleted_by_role)
          VALUES (OLD.id, OLD.openstack_server_id, session_user)
          ON CONFLICT DO NOTHING;
          RETURN OLD;
        END $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION managed_vm_tombstone_record() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER managed_vm_tombstone AFTER DELETE ON managed_vm "
        "FOR EACH ROW EXECUTE FUNCTION managed_vm_tombstone_record()"
    )

    op.execute(
        """
        CREATE FUNCTION managed_vm_api_insert_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
        BEGIN
          IF EXISTS (SELECT 1 FROM public.managed_vm_tombstone t WHERE t.id = NEW.id) THEN
            RAISE EXCEPTION 'managed VM id % was used by a deleted managed VM: it cannot be re-inserted', NEW.id
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          IF current_user = 'ovlm_api' AND (
               NEW.ssh_host_key_fingerprint IS NOT NULL OR NEW.host_key_confirmed_by IS NOT NULL
               OR NEW.host_key_confirmed_at IS NOT NULL) THEN
            RAISE EXCEPTION 'ovlm_api may only insert managed VMs with no host key and no confirmation'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER managed_vm_api_insert_guard BEFORE INSERT ON managed_vm "
        "FOR EACH ROW EXECUTE FUNCTION managed_vm_api_insert_guard()"
    )

    op.execute(
        """
        CREATE FUNCTION managed_vm_host_key_follow() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
        BEGIN
          IF NEW.ssh_host_key_fingerprint IS DISTINCT FROM OLD.ssh_host_key_fingerprint THEN
            NEW.host_key_confirmed_by := NULL;
            NEW.host_key_confirmed_at := NULL;
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER managed_vm_host_key_follow BEFORE UPDATE ON managed_vm "
        "FOR EACH ROW EXECUTE FUNCTION managed_vm_host_key_follow()"
    )

    # A half-written confirmation is no confirmation (none exists in practice: confirm() sets both columns).
    op.execute(
        "UPDATE managed_vm SET host_key_confirmed_by = NULL, host_key_confirmed_at = NULL "
        "WHERE (host_key_confirmed_at IS NULL) <> (host_key_confirmed_by IS NULL) "
        "OR (host_key_confirmed_at IS NOT NULL AND ssh_host_key_fingerprint IS NULL)"
    )
    op.execute(
        "ALTER TABLE managed_vm ADD CONSTRAINT managed_vm_host_key_confirmation CHECK ("
        "(host_key_confirmed_at IS NULL) = (host_key_confirmed_by IS NULL) "
        "AND (host_key_confirmed_at IS NULL OR ssh_host_key_fingerprint IS NOT NULL))"
    )

    op.execute("GRANT SELECT ON managed_vm_tombstone TO ovlm_api, ovlm_worker")


def downgrade() -> None:
    op.execute("ALTER TABLE managed_vm DROP CONSTRAINT managed_vm_host_key_confirmation")
    op.execute("DROP TRIGGER managed_vm_host_key_follow ON managed_vm")
    op.execute("DROP FUNCTION managed_vm_host_key_follow()")
    op.execute("DROP TRIGGER managed_vm_api_insert_guard ON managed_vm")
    op.execute("DROP FUNCTION managed_vm_api_insert_guard()")
    op.execute("DROP TRIGGER managed_vm_tombstone ON managed_vm")
    op.execute("DROP FUNCTION managed_vm_tombstone_record()")
    op.execute("DROP TABLE managed_vm_tombstone")
