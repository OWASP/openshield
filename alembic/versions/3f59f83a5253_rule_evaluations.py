"""Add rule_evaluations: per-resource coverage, not just findings (#263).

Revision ID: 3f59f83a5253
Revises: d8e4f6a1b2c3
Create Date: 2026-08-29 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "3f59f83a5253"
down_revision: Union[str, Sequence[str], None] = "d8e4f6a1b2c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_STATUS_CONSTRAINT = "ck_rule_evaluations_status_v1"
_SCOPE_CONSTRAINT = "ck_rule_evaluations_resource_id_not_empty"
_REASON_CONSTRAINT = "ck_rule_evaluations_reason_code_required"


def upgrade() -> None:
    op.create_table(
        "rule_evaluations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=True),
        # Nullable: only set for FAIL evaluations, and only once the finding
        # row exists. Populated in the same transaction as the finding insert
        # (see DatabaseManager.save_scan), never inferred after the fact.
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.scan_id"], name="rule_evaluations_scan_id_fkey"),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name="rule_evaluations_finding_id_fkey", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name="rule_evaluations_pkey"),
        # One coverage statement per rule per resource per scan. Also gives
        # the persistence-layer FAIL -> finding_id backfill a stable join key.
        sa.UniqueConstraint("scan_id", "rule_id", "resource_id", name="uq_rule_evaluations_scan_rule_resource"),
    )

    op.create_index("idx_rule_evaluations_scan_id", "rule_evaluations", ["scan_id"], unique=False)
    op.create_index("idx_rule_evaluations_rule_id", "rule_evaluations", ["rule_id"], unique=False)
    op.create_index("idx_rule_evaluations_status", "rule_evaluations", ["status"], unique=False)

    op.create_check_constraint(
        _STATUS_CONSTRAINT,
        "rule_evaluations",
        "status IN ('PASS', 'FAIL', 'UNKNOWN', 'ERROR', 'NOT_APPLICABLE')",
    )
    # A canonical scope identifier is required — never an empty string standing
    # in for "no specific resource" (that collides across rules/subscriptions).
    op.create_check_constraint(
        _SCOPE_CONSTRAINT,
        "rule_evaluations",
        "resource_id <> ''",
    )
    # UNKNOWN/ERROR/NOT_APPLICABLE must always explain themselves; only PASS
    # and FAIL are self-evident from the status alone.
    op.create_check_constraint(
        _REASON_CONSTRAINT,
        "rule_evaluations",
        "status NOT IN ('UNKNOWN', 'ERROR', 'NOT_APPLICABLE') OR (reason_code IS NOT NULL AND reason_code <> '')",
    )


def downgrade() -> None:
    op.drop_constraint(_REASON_CONSTRAINT, "rule_evaluations", type_="check")
    op.drop_constraint(_SCOPE_CONSTRAINT, "rule_evaluations", type_="check")
    op.drop_constraint(_STATUS_CONSTRAINT, "rule_evaluations", type_="check")
    op.drop_index("idx_rule_evaluations_status", table_name="rule_evaluations")
    op.drop_index("idx_rule_evaluations_rule_id", table_name="rule_evaluations")
    op.drop_index("idx_rule_evaluations_scan_id", table_name="rule_evaluations")
    op.drop_table("rule_evaluations")
