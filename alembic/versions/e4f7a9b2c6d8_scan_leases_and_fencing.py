"""Add renewable ownership leases and fencing tokens to scans.

Revision ID: e4f7a9b2c6d8
Revises: d8e4f6a1b2c3
Create Date: 2026-08-29 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op


revision: str = "e4f7a9b2c6d8"
down_revision: Union[str, Sequence[str], None] = "3f59f83a5253"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add additive lease state and make legacy running work recoverable."""
    # autocommit_block() below commits everything issued before it, so a
    # failure while building the concurrent indexes leaves these columns in
    # place with alembic_version still on the previous revision. The retry has
    # to be able to walk back over them instead of failing on "column already
    # exists" before it reaches the index recovery.
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS lease_owner TEXT")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMPTZ")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS fencing_token BIGINT NOT NULL DEFAULT 0")

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
        # An interrupted CONCURRENTLY build leaves an INVALID index that still
        # owns the name and can never serve a query. Dropping first (rather
        # than CREATE ... IF NOT EXISTS, which would keep the broken one) makes
        # a retry rebuild it.
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_scans_pending_started_at")
        op.execute(
            """
            CREATE INDEX CONCURRENTLY idx_scans_pending_started_at
            ON scans (started_at ASC)
            WHERE status = 'pending'
            """
        )
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_scans_running_lease_expires_at")
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
