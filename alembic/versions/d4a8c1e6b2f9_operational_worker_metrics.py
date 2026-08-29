"""Persist worker liveness used by bounded operational metrics.

Revision ID: d4a8c1e6b2f9
Revises: c9e1a5b7d3f2
Create Date: 2026-08-29 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d4a8c1e6b2f9"
down_revision: Union[str, Sequence[str], None] = "c9e1a5b7d3f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Store one liveness timestamp per worker process."""
    op.create_table(
        "worker_heartbeats",
        sa.Column("worker_id", sa.Text(), nullable=False),
        sa.Column("worker_type", sa.Text(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("worker_id", "worker_type", name="worker_heartbeats_pkey"),
        sa.CheckConstraint("worker_type IN ('scan', 'enrichment')", name="ck_worker_heartbeats_type"),
    )
    op.create_index(
        "idx_worker_heartbeats_type_seen", "worker_heartbeats", ["worker_type", "last_seen_at"], unique=False
    )


def downgrade() -> None:
    """Remove durable worker heartbeat state."""
    op.drop_index("idx_worker_heartbeats_type_seen", table_name="worker_heartbeats")
    op.drop_table("worker_heartbeats")
