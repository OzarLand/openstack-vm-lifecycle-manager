"""Merge the module migration heads (workflow, auth, audit, inventory/registry).

Each module adds its own migration off the baseline (docs/agent-working-rules.md); the integrator merges the heads.
No schema change.

Revision ID: 0003_merge
Revises: 0002_workflow, auth_0001, audit_0001, registry_0001
"""

from collections.abc import Sequence

revision: str = "0003_merge"
down_revision: str | Sequence[str] | None = (
    "0002_workflow",
    "auth_0001",
    "audit_0001",
    "registry_0001",
)
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
