"""Merge the wave-3 heads (auth_0002 RBAC, automation_0001, readiness_0001). No schema change.

Revision ID: 0005_merge
Revises: auth_0002, automation_0001, readiness_0001
"""

from collections.abc import Sequence

revision: str = "0005_merge"
down_revision: str | Sequence[str] | None = ("auth_0002", "automation_0001", "readiness_0001")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
