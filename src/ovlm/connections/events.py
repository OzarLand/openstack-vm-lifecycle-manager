"""Audit allowlists of the connections module (security-model.md 5.2, 8).

Secrets are never recorded: a credential's secret is registered as a secret field, so only ``secret_changed`` can
appear. The CA bundle is not secret but large: only its reference (SHA-256) is recorded."""

from __future__ import annotations

from ovlm import audit

audit.register_entity(
    "cloud",
    [
        "name",
        "auth_url",
        "region",
        "interface",
        "ca_bundle_ref",
        "version",
        "stepup_id",
        "invalidated_count",
    ],
)
audit.register_entity(
    "project_connection",
    [
        "cloud_id",
        "openstack_project_id",
        "openstack_project_name",
        "name",
        "guest_access",
        "enabled",
        "version",
        "stepup_id",
    ],
)
audit.register_entity(
    "credential_ref",
    [
        "kind", "project_connection_id", "app_cred_id", "expires_at", "state", "kek_id",
        "ssh_public_key_fingerprint", "validation_ok", "validation_reason", "superseded_by",
        "cloud_deletion_pending", "stepup_id", "cloud_id", "endpoint_sha256", "verified_expires_at",
    ],
    secret_fields=["secret"],
)  # fmt: skip
audit.register_entity("kek", ["kek_id", "rewrapped", "orphans_deleted"])
