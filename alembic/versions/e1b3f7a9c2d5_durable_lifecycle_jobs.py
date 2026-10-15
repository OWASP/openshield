"""Add durable, fenced lifecycle application jobs.

Revision ID: e1b3f7a9c2d5
Revises: a8d9c2e4f601
Create Date: 2026-10-15 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "e1b3f7a9c2d5"
down_revision: Union[str, Sequence[str], None] = "a8d9c2e4f601"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create one resumable lifecycle job per scan, and persist rule outcomes."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_cols = {c["name"] for c in inspector.get_columns("scans")}
    if "rule_outcomes_json" not in existing_cols:
        op.add_column(
            "scans",
            sa.Column("rule_outcomes_json", postgresql.JSONB(), nullable=True),
        )
    if not inspector.has_table("lifecycle_jobs"):
        op.create_table(
            "lifecycle_jobs",
            sa.Column("job_id", postgresql.UUID(), nullable=False),
            sa.Column("scan_id", postgresql.UUID(), nullable=False),
            sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'pending'")),
            sa.Column("lease_owner", sa.Text(), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("fencing_token", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column(
                "next_retry_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.scan_id"], name="lifecycle_jobs_scan_id_fkey"),
            sa.PrimaryKeyConstraint("job_id", name="lifecycle_jobs_pkey"),
            sa.UniqueConstraint("scan_id", name="uq_lifecycle_jobs_scan_id"),
            sa.CheckConstraint(
                "status IN ('pending', 'running', 'completed', 'failed')",
                name="ck_lifecycle_jobs_status",
            ),
        )
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_jobs_pending_retry")
        op.execute(
            """
            CREATE INDEX CONCURRENTLY idx_lifecycle_jobs_pending_retry
            ON lifecycle_jobs (next_retry_at ASC)
            WHERE status = 'pending'
            """
        )
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_jobs_running_lease")
        op.execute(
            """
            CREATE INDEX CONCURRENTLY idx_lifecycle_jobs_running_lease
            ON lifecycle_jobs (lease_expires_at ASC)
            WHERE status = 'running'
            """
        )


def downgrade() -> None:
    """Remove durable lifecycle work state."""
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_jobs_running_lease")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_jobs_pending_retry")
    op.drop_table("lifecycle_jobs")
    op.drop_column("scans", "rule_outcomes_json")
