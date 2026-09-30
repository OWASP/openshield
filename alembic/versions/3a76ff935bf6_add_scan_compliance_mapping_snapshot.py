"""Add compliance_mapping_snapshot to scans.

Revision ID: 3a76ff935bf6
Revises: d4a8c1e6b2f9
Create Date: 2026-08-22 00:00:00.000000

This migration only adds a nullable column and is order-independent, so it
chains onto whatever the current `dev` head is. It previously sat on
3f59f83a5253 (#321's rule evaluation contract); #325's scan durability
migrations then merged into `dev` off that same parent and end at
d4a8c1e6b2f9. Pointing down_revision there keeps the graph linear so
`alembic heads` returns exactly one head.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "3a76ff935bf6"
down_revision: Union[str, Sequence[str], None] = "d4a8c1e6b2f9"
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
