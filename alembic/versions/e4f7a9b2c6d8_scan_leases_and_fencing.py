"""Add renewable ownership leases and fencing tokens to scans.

Revision ID: e4f7a9b2c6d8
Revises: d8e4f6a1b2c3
Create Date: 2026-08-29 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e4f7a9b2c6d8"
down_revision: Union[str, Sequence[str], None] = "d8e4f6a1b2c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add additive lease state and make legacy running work recoverable."""
    op.add_column("scans", sa.Column("lease_owner", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "scans",
        sa.Column("fencing_token", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
    )

    # A pre-lease running row belongs to an old worker that cannot satisfy the
    # new fencing contract. Marking its lease expired preserves the row and
    # lets the new worker recover it under a fresh owner/token.
    op.execute(
        """
        UPDATE scans
        SET lease_expires_at = CURRENT_TIMESTAMP
        WHERE status = 'running' AND lease_expires_at IS NULL
        """
    )

    # These indexes are additive and are created concurrently so a populated
    # production scans table remains available while the migration runs.
    with op.get_context().autocommit_block():
        op.execute(
            """
            CREATE INDEX CONCURRENTLY idx_scans_pending_started_at
            ON scans (started_at ASC)
            WHERE status = 'pending'
            """
        )
        op.execute(
            """
            CREATE INDEX CONCURRENTLY idx_scans_running_lease_expires_at
            ON scans (lease_expires_at ASC)
            WHERE status = 'running'
            """
        )


def downgrade() -> None:
    """Remove lease metadata; callers must be rolled back first."""
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_scans_running_lease_expires_at")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_scans_pending_started_at")
    op.drop_column("scans", "fencing_token")
    op.drop_column("scans", "last_heartbeat_at")
    op.drop_column("scans", "lease_expires_at")
    op.drop_column("scans", "lease_owner")
