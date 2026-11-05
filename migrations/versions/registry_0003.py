"""Registry: the ``managed_vm`` insert guard recognises the api by role membership (review IS-12).

Revision ID: registry_0003
Revises: registry_0002

docs/reviews/verification-host-key-fixes.md IS-12: ``managed_vm_api_insert_guard`` identified the api by
``current_user = 'ovlm_api'``. A deployment that gave the api another login role, a member of ``ovlm_api`` that does
not ``SET ROLE``, would switch the guard off silently. The guard now applies to every role that is a member of
``ovlm_api`` (``pg_has_role(..., 'MEMBER')``, direct or inherited, ``NOINHERIT`` included). Superusers are left out:
``pg_has_role`` is always true for them, and a superuser can disable any trigger anyway (the owner seeds and the
migrations are not superusers, and are not members of ``ovlm_api``). Only the function body changes; the trigger,
the tombstone check and the ``search_path`` stay as ``registry_0002`` set them.
"""

from alembic import op

revision = "registry_0003"
down_revision = "registry_0002"
branch_labels = None
depends_on = None

_BODY = """
        CREATE OR REPLACE FUNCTION managed_vm_api_insert_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
        BEGIN
          IF EXISTS (SELECT 1 FROM public.managed_vm_tombstone t WHERE t.id = NEW.id) THEN
            RAISE EXCEPTION 'managed VM id % was used by a deleted managed VM: it cannot be re-inserted', NEW.id
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          IF {is_api} AND (
               NEW.ssh_host_key_fingerprint IS NOT NULL OR NEW.host_key_confirmed_by IS NOT NULL
               OR NEW.host_key_confirmed_at IS NOT NULL) THEN
            RAISE EXCEPTION 'ovlm_api may only insert managed VMs with no host key and no confirmation'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$
"""

_MEMBER = (
    "(pg_has_role(current_user, 'ovlm_api', 'MEMBER') "
    "AND NOT (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = current_user))"
)


def upgrade() -> None:
    op.execute(_BODY.format(is_api=_MEMBER))


def downgrade() -> None:
    op.execute(_BODY.format(is_api="current_user = 'ovlm_api'"))
