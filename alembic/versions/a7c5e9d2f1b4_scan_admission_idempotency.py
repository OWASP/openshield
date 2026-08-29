"""Enforce durable scan admission and idempotency.

Revision ID: a7c5e9d2f1b4
Revises: f2b6d8e1a4c9
Create Date: 2026-08-29 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a7c5e9d2f1b4"
down_revision: Union[str, Sequence[str], None] = "f2b6d8e1a4c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Persist idempotency semantics and prevent more than one active scan."""
    op.add_column("scans", sa.Column("idempotency_key", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("request_fingerprint", sa.Text(), nullable=True))
    with op.get_context().autocommit_block():
        op.execute(
            """
            CREATE UNIQUE INDEX CONCURRENTLY uq_scans_subscription_idempotency_key
            ON scans (subscription_id, idempotency_key)
            WHERE idempotency_key IS NOT NULL
            """
        )
        op.execute(
            """
            CREATE UNIQUE INDEX CONCURRENTLY uq_scans_one_active_per_subscription
            ON scans (subscription_id)
            WHERE status IN ('pending', 'running')
            """
        )


def downgrade() -> None:
    """Remove scan admission metadata and constraints."""
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS uq_scans_one_active_per_subscription")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS uq_scans_subscription_idempotency_key")
    op.drop_column("scans", "request_fingerprint")
    op.drop_column("scans", "idempotency_key")
