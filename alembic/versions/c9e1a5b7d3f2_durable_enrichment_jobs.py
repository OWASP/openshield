"""Add durable, fenced CVE enrichment jobs.

Revision ID: c9e1a5b7d3f2
Revises: a7c5e9d2f1b4
Create Date: 2026-08-29 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c9e1a5b7d3f2"
down_revision: Union[str, Sequence[str], None] = "a7c5e9d2f1b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create one resumable enrichment job per scan."""
    op.create_table(
        "enrichment_jobs",
        sa.Column("job_id", postgresql.UUID(), nullable=False),
        sa.Column("scan_id", postgresql.UUID(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "next_retry_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column("checkpoint", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.scan_id"], name="enrichment_jobs_scan_id_fkey"),
        sa.PrimaryKeyConstraint("job_id", name="enrichment_jobs_pkey"),
        sa.UniqueConstraint("scan_id", name="uq_enrichment_jobs_scan_id"),
        sa.CheckConstraint("status IN ('pending', 'running', 'completed', 'failed')", name="ck_enrichment_jobs_status"),
    )
    with op.get_context().autocommit_block():
        op.execute(
            """
            CREATE INDEX CONCURRENTLY idx_enrichment_jobs_pending_retry
            ON enrichment_jobs (next_retry_at ASC)
            WHERE status = 'pending'
            """
        )
        op.execute(
            """
            CREATE INDEX CONCURRENTLY idx_enrichment_jobs_running_lease
            ON enrichment_jobs (lease_expires_at ASC)
            WHERE status = 'running'
            """
        )


def downgrade() -> None:
    """Remove durable enrichment work state."""
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_enrichment_jobs_running_lease")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_enrichment_jobs_pending_retry")
    op.drop_table("enrichment_jobs")
