"""Merge the profiles and policies heads. No schema change.

Added on branch ``claude/ovlm-profiles`` so the schema has a single head for ``upgrade head`` and the tests; the
integrator may replace it with a merge covering all branches.

Revision ID: 0004_merge_profiles_policies
Revises: profiles_0001, policies_0001
"""

from collections.abc import Sequence

revision: str = "0004_merge_profiles_policies"
down_revision: str | Sequence[str] | None = ("profiles_0001", "policies_0001")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
