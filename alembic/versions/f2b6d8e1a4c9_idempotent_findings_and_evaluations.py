"""Add database-enforced identities for scan results.

Revision ID: f2b6d8e1a4c9
Revises: e4f7a9b2c6d8
Create Date: 2026-08-29 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "f2b6d8e1a4c9"
down_revision: Union[str, Sequence[str], None] = "e4f7a9b2c6d8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add stable finding keys and per-resource evaluation rows."""
    op.add_column("findings", sa.Column("finding_key", sa.Text(), nullable=True))
    # Existing records predate the identity contract. Preserve each record as
    # distinct rather than attempting to infer equivalence from mutable text.
    op.execute("UPDATE findings SET finding_key = 'legacy:' || id::text WHERE finding_key IS NULL")
    op.alter_column("findings", "finding_key", nullable=False)

    with op.get_context().autocommit_block():
        op.execute("CREATE UNIQUE INDEX CONCURRENTLY uq_findings_scan_finding_key ON findings (scan_id, finding_key)")

    op.create_table(
        "rule_evaluations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), server_default=sa.text("''"), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.scan_id"], name="rule_evaluations_scan_id_fkey"),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name="rule_evaluations_finding_id_fkey", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name="rule_evaluations_pkey"),
        sa.UniqueConstraint("scan_id", "rule_id", "resource_id", name="uq_rule_evaluations_scan_rule_resource"),
        sa.CheckConstraint(
            "status IN ('PASS', 'FAIL', 'UNKNOWN', 'ERROR', 'NOT_APPLICABLE')",
            name="ck_rule_evaluations_status_v1",
        ),
        sa.CheckConstraint("resource_id <> ''", name="ck_rule_evaluations_resource_id_not_empty"),
    )
    op.create_index("idx_rule_evaluations_scan_id", "rule_evaluations", ["scan_id"], unique=False)


def downgrade() -> None:
    """Remove idempotent-result storage introduced by this revision."""
    op.drop_index("idx_rule_evaluations_scan_id", table_name="rule_evaluations")
    op.drop_table("rule_evaluations")
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS uq_findings_scan_finding_key")
    op.drop_column("findings", "finding_key")
