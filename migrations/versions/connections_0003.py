"""Endpoint rewrite signal (security follow-up SF-5, review N-4).

Revision ID: connections_0003
Revises: registry_0003

A change of a cloud's endpoint (``auth_url``, ``region``, ``interface``, CA bundle) through the API already asks the
worker to re-validate the cloud's credentials (``invalidate_cloud_credentials``). A **direct** write of the ``cloud``
row (the ``ovlm_api`` role, or the owner) did not: the credential stayed ``ok`` until the periodic re-validation, up
to 24 h later. Every use was refused meanwhile (the AAD binds the live endpoint), so only the signal was late.

A statement-level trigger on ``cloud`` now compares the old and new rows (transition tables) and bumps
``credential_ref.validation_requested_at`` of every pending or active credential of the changed clouds' connections,
whoever wrote the row. The worker then re-validates at once, finds the binding changed and marks them invalid without
decrypting anything. ``SECURITY DEFINER`` (owner) with a fixed ``search_path``, so a role without ``UPDATE`` on
``credential_ref`` still raises the signal; the function only ever touches that one column (and ``updated_at``).
The ``search_path`` ends with ``pg_temp`` (review SFR-4, the ``registry_0002`` convention): otherwise PostgreSQL
searches the session's temporary schema first, and a temporary table named ``credential_ref`` or
``project_connection`` would capture the ``UPDATE``.

Linear after ``registry_0003`` so the schema keeps a single head (``check_schema_at_head``).
"""

from alembic import op

revision = "connections_0003"
down_revision = "registry_0003"
branch_labels = ("connections_endpoint_signal",)
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION cloud_endpoint_change_signal() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
        BEGIN
          UPDATE credential_ref r SET validation_requested_at = now(), updated_at = now()
          WHERE r.state IN ('pending', 'active')
            AND r.project_connection_id IN (
              SELECT p.id FROM project_connection p
              JOIN cloud_endpoint_old o ON o.id = p.cloud_id
              JOIN cloud_endpoint_new n ON n.id = o.id
              WHERE o.auth_url IS DISTINCT FROM n.auth_url
                 OR o.region IS DISTINCT FROM n.region
                 OR o.interface IS DISTINCT FROM n.interface
                 OR o.ca_bundle_pem IS DISTINCT FROM n.ca_bundle_pem
                 OR o.ca_bundle_sha256 IS DISTINCT FROM n.ca_bundle_sha256);
          RETURN NULL;
        END $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION cloud_endpoint_change_signal() FROM PUBLIC")
    # A column list (UPDATE OF ...) cannot be combined with transition tables; the function compares the columns.
    op.execute(
        "CREATE TRIGGER cloud_endpoint_change_signal AFTER UPDATE ON cloud "
        "REFERENCING OLD TABLE AS cloud_endpoint_old NEW TABLE AS cloud_endpoint_new "
        "FOR EACH STATEMENT EXECUTE FUNCTION cloud_endpoint_change_signal()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER cloud_endpoint_change_signal ON cloud")
    op.execute("DROP FUNCTION cloud_endpoint_change_signal()")
