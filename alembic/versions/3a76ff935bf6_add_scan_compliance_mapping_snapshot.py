"""Add compliance_mapping_snapshot to scans.

Revision ID: 3a76ff935bf6
Revises: d8e4f6a1b2c3
Create Date: 2026-08-22 00:00:00.000000

This migration and PR #308's (severity contract v1, d8e4f6a1b2c3) were both
cut from the same parent, c7a2e9f1b3d4, which would have forked the Alembic
revision graph if both merged independently. Pointing down_revision at
d8e4f6a1b2c3 ahead of time was tried and reverted earlier in this PR's
history: Alembic resolves the full revision map from the files present in
the branch it's run against, so a revision that only existed on #308's
still-unmerged branch broke `alembic upgrade head` in this PR's own CI.
#308 has since merged, so d8e4f6a1b2c3 now exists on `dev` and this chains
onto it correctly - `alembic heads` returns exactly one head again.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "3a76ff935bf6"
down_revision: Union[str, Sequence[str], None] = "d8e4f6a1b2c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add a nullable JSONB snapshot of each framework's mapping-pack identity.

    Populated by DatabaseManager.save_scan() at scan-completion time, so a
    historical compliance report can show the framework name, edition,
    mapping-pack version and source that were actually in effect for that
    scan instead of reinterpreting it with whatever mapping pack is deployed
    now (issue #302).
    """
    op.add_column(
        "scans",
        sa.Column("compliance_mapping_snapshot", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    """Drop the compliance mapping snapshot column."""
    op.drop_column("scans", "compliance_mapping_snapshot")
