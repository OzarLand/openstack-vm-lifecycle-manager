"""Registry: service_group, service, managed_vm (data-model.md section 4, 12).

Revision ID: registry_0001
Revises: inventory_0001

Own branch label (docs/agent-working-rules.md). Deviation from "down_revision is the baseline": ``managed_vm``
has a real foreign key to ``observed_server``, so this revision sits after ``inventory_0001`` and my two
revisions form one linear chain with a single head. (``depends_on`` alone would leave two heads and break
``upgrade head`` on this branch.) ``service.project_connection_id`` and ``service.current_profile_id``
have no foreign key yet: ``project_connection`` and ``profile`` belong to other modules; the merge revision adds
the constraints. Grants follow data-model.md section 12: the api reads and writes ``service`` and inserts and
deletes ``managed_vm`` but cannot UPDATE ``managed_vm.role`` (only the worker moves a VM between roles).
"""

from alembic import op

revision = "registry_0001"
down_revision = "inventory_0001"
branch_labels = ("registry",)
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE service_group (
          id          uuid PRIMARY KEY,
          name        text NOT NULL UNIQUE,
          description text,
          version     integer NOT NULL DEFAULT 1,
          created_at  timestamptz NOT NULL DEFAULT now(),
          updated_at  timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        r"""
        CREATE TABLE service (
          id                    uuid PRIMARY KEY,
          name                  text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
          slug                  text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$'),
          service_group_id      uuid REFERENCES service_group (id),
          project_connection_id uuid NOT NULL,
          owner_contact         text,
          current_profile_id    uuid,
          version               integer NOT NULL DEFAULT 1,
          created_by            uuid,
          created_at            timestamptz NOT NULL DEFAULT now(),
          updated_at            timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE managed_vm (
          id                      uuid PRIMARY KEY,
          service_id              uuid NOT NULL REFERENCES service (id),
          observed_server_id      uuid NOT NULL REFERENCES observed_server (id),
          openstack_server_id     text NOT NULL UNIQUE,
          role                    text NOT NULL
                                  CHECK (role IN ('current', 'retained', 'candidate', 'retired')),
          registered_by           uuid,
          registered_at           timestamptz NOT NULL,
          ssh_host_key_fingerprint text,
          host_key_confirmed_by   uuid,
          host_key_confirmed_at   timestamptz,
          launched_at_effective   timestamptz,
          created_at              timestamptz NOT NULL DEFAULT now(),
          updated_at              timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    # One current VM per service (data-model.md section 4).
    op.execute(
        "CREATE UNIQUE INDEX managed_vm_one_current ON managed_vm (service_id) WHERE role = 'current'"
    )
    op.execute("CREATE INDEX managed_vm_service ON managed_vm (service_id)")
    op.execute("CREATE INDEX service_created ON service (created_at, id)")
    op.execute("CREATE INDEX managed_vm_created ON managed_vm (created_at, id)")

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON service_group, service TO ovlm_api")
    op.execute("GRANT SELECT ON service_group, service, managed_vm TO ovlm_worker")
    op.execute("GRANT SELECT, INSERT, DELETE ON managed_vm TO ovlm_api")
    op.execute(
        "GRANT UPDATE (host_key_confirmed_by, host_key_confirmed_at) ON managed_vm TO ovlm_api"
    )
    op.execute(
        "GRANT UPDATE (role, ssh_host_key_fingerprint, launched_at_effective, updated_at) "
        "ON managed_vm TO ovlm_worker"
    )
    # The api reads observed_server (inventory_0001 grants SELECT); registration never needs more.


def downgrade() -> None:
    op.execute("DROP TABLE managed_vm")
    op.execute("DROP TABLE service")
    op.execute("DROP TABLE service_group")
