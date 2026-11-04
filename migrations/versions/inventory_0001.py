"""Inventory: sync_run and observed_* tables with append-only revisions (data-model.md section 3, 12).

Revision ID: inventory_0001
Revises: 0001_baseline

One migration per module, own branch label (docs/agent-working-rules.md). ``project_connection_id`` has no
foreign key yet: the ``cloud``/``project_connection`` tables belong to another module and arrive in its own
migration; the merge revision adds the constraint. Grants: the worker reads and writes, the api only reads;
nobody can DELETE (resources are marked ``gone``, never deleted) and revisions are INSERT/SELECT only.
"""

from alembic import op

revision = "inventory_0001"
down_revision = "0001_baseline"
branch_labels = ("inventory",)
depends_on = None

_TEXT_ARRAY = "text[] NOT NULL DEFAULT '{}'"
_TYPED: dict[str, list[tuple[str, str]]] = {
    "server": [
        ("server_status", "text NOT NULL"), ("vm_state", "text"), ("task_state", "text"),
        ("power_state", "integer"), ("created", "timestamptz"), ("launched_at", "timestamptz"),
        ("nova_updated_at", "timestamptz"), ("flavor_original_name", "text"), ("flavor_vcpus", "integer"),
        ("flavor_ram", "integer"), ("flavor_disk", "integer"), ("image_id", "text"),
        ("availability_zone", "text"), ("locked", "boolean"), ("locked_reason", "text"),
        ("tags", _TEXT_ARRAY), ("metadata", "jsonb NOT NULL DEFAULT '{}'::jsonb"), ("host_id", "text"),
        ("is_minimal_construct", "boolean NOT NULL DEFAULT false"),
    ],
    "volume": [
        ("volume_status", "text NOT NULL"), ("size", "integer"), ("bootable", "boolean"),
        ("multiattach", "boolean"), ("availability_zone", "text"), ("volume_type", "text"),
        ("metadata", "jsonb NOT NULL DEFAULT '{}'::jsonb"),
    ],
    "volume_attachment": [
        ("server_openstack_id", "text NOT NULL"), ("volume_openstack_id", "text NOT NULL"),
        ("device", "text"), ("attachment_id", "text"), ("delete_on_termination", "boolean"),
    ],
    "port": [
        ("network_id", "text"), ("device_id", "text"), ("device_owner", "text"),
        ("fixed_ips", "jsonb NOT NULL DEFAULT '[]'::jsonb"), ("mac", "text"),
        ("security_group_ids", _TEXT_ARRAY), ("port_status", "text"),
    ],
    "floating_ip": [
        ("floating_ip_address", "text NOT NULL"), ("port_id", "text"), ("fixed_ip_address", "text"),
        ("router_id", "text"), ("floating_network_id", "text"), ("floating_ip_status", "text"),
        ("tags", _TEXT_ARRAY),
    ],
    "network": [
        ("network_status", "text"), ("is_external", "boolean NOT NULL DEFAULT false"),
        ("is_shared", "boolean NOT NULL DEFAULT false"),
    ],
    "image": [("image_status", "text"), ("visibility", "text"), ("owner_id", "text")],
    "flavor": [
        ("vcpus", "integer"), ("ram", "integer"), ("disk", "integer"), ("ephemeral", "integer"),
        ("is_public", "boolean"),
    ],
}  # fmt: skip


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE sync_run (
          id                    uuid PRIMARY KEY,
          project_connection_id uuid NOT NULL,
          kind                  text NOT NULL CHECK (kind IN ('full', 'servers_delta')),
          status                text NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
          started_at            timestamptz NOT NULL,
          finished_at           timestamptz,
          counts                jsonb NOT NULL DEFAULT '{}'::jsonb,
          versions              jsonb NOT NULL DEFAULT '{}'::jsonb,
          error                 jsonb,
          workflow_run_id       uuid
        )
        """
    )
    op.execute(
        "CREATE INDEX sync_run_project_started ON sync_run (project_connection_id, started_at DESC)"
    )
    op.execute("GRANT SELECT ON sync_run TO ovlm_api")
    op.execute("GRANT SELECT, INSERT, UPDATE ON sync_run TO ovlm_worker")

    for res, cols in _TYPED.items():
        table = f"observed_{res}"
        typed = ",\n          ".join(f"{name} {ddl}" for name, ddl in cols)
        op.execute(
            f"""
            CREATE TABLE {table} (
              id                    uuid PRIMARY KEY,
              project_connection_id uuid NOT NULL,
              openstack_id          text NOT NULL,
              name                  text,
              {typed},
              payload               jsonb NOT NULL,
              payload_hash          text NOT NULL,
              first_seen_sync_id    uuid NOT NULL REFERENCES sync_run (id),
              last_seen_sync_id     uuid NOT NULL REFERENCES sync_run (id),
              missed_syncs          integer NOT NULL DEFAULT 0 CHECK (missed_syncs >= 0),
              status                text NOT NULL DEFAULT 'present'
                                    CHECK (status IN ('present', 'gone', 'unknown')),
              gone_at               timestamptz,
              synced_at             timestamptz NOT NULL,
              created_at            timestamptz NOT NULL DEFAULT now(),
              updated_at            timestamptz NOT NULL DEFAULT now(),
              UNIQUE (project_connection_id, openstack_id),
              CHECK ((status = 'gone') = (gone_at IS NOT NULL))
            )
            """
        )
        op.execute(f"CREATE INDEX {table}_created ON {table} (created_at, id)")
        op.execute(
            f"CREATE INDEX {table}_project_status ON {table} (project_connection_id, status)"
        )
        op.execute(
            f"""
            CREATE TABLE {table}_revision (
              id            uuid PRIMARY KEY,
              {table}_id    uuid NOT NULL REFERENCES {table} (id),
              sync_run_id   uuid NOT NULL REFERENCES sync_run (id),
              payload       jsonb NOT NULL,
              payload_hash  text NOT NULL,
              observed_at   timestamptz NOT NULL
            )
            """
        )
        op.execute(
            f"CREATE INDEX {table}_revision_obs ON {table}_revision ({table}_id, observed_at)"
        )
        op.execute(f"GRANT SELECT ON {table}, {table}_revision TO ovlm_api")
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON {table} TO ovlm_worker")
        op.execute(f"GRANT SELECT, INSERT ON {table}_revision TO ovlm_worker")  # append-only


def downgrade() -> None:
    # Supported downgrade path is "restore backup" (architecture.md section 9).
    for res in reversed(list(_TYPED)):
        op.execute(f"DROP TABLE observed_{res}_revision")
        op.execute(f"DROP TABLE observed_{res}")
    op.execute("DROP TABLE sync_run")
