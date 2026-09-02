"""Add database-enforced identities for scan findings.

Revision ID: f2b6d8e1a4c9
Revises: e4f7a9b2c6d8
Create Date: 2026-08-29 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f2b6d8e1a4c9"
down_revision: Union[str, Sequence[str], None] = "e4f7a9b2c6d8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_UNIQUE_INDEX = "uq_findings_scan_finding_key"


def upgrade() -> None:
    """Give every finding a stable identity so replayed results upsert."""
    op.add_column("findings", sa.Column("finding_key", sa.Text(), nullable=True))
    # Existing records predate the identity contract. Preserve each record as
    # distinct rather than attempting to infer equivalence from mutable text.
    op.execute("UPDATE findings SET finding_key = 'legacy:' || id::text WHERE finding_key IS NULL")
    op.alter_column("findings", "finding_key", nullable=False)

    with op.get_context().autocommit_block():
        # A previous interrupted CONCURRENTLY build leaves an unusable index
        # behind that would make this statement fail with "already exists".
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_UNIQUE_INDEX}")
        op.execute(f"CREATE UNIQUE INDEX CONCURRENTLY {_UNIQUE_INDEX} ON findings (scan_id, finding_key)")


def downgrade() -> None:
    """Remove the finding identity introduced by this revision."""
    with op.get_context().autocommit_block():
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_UNIQUE_INDEX}")
    op.drop_column("findings", "finding_key")
