"""Add compliance_mapping_snapshot to scans.

Revision ID: 3a76ff935bf6
Revises: 3f59f83a5253
Create Date: 2026-08-22 00:00:00.000000

This migration only adds a nullable column and is order-independent, so it
chains onto whatever the current `dev` head is. It was previously rebased
onto d8e4f6a1b2c3 (severity contract v1, #308); since then #321's rule
evaluation contract (3f59f83a5253) merged into `dev` off that same parent,
forking the revision graph into two heads. Pointing down_revision at
3f59f83a5253 - now present on `dev` - linearises the graph so `alembic
heads` returns exactly one head again.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "3a76ff935bf6"
down_revision: Union[str, Sequence[str], None] = "3f59f83a5253"
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
