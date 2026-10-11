"""Add ci_scans and ci_scan_evaluations tables for GitHub CI/CD scanning.

Revision ID: e1f2a3b4c5d6
Revises: 3f59f83a5253
Create Date: 2026-10-10 00:00:00.000000

CI scans are GitHub-scoped (owner + repo), not Azure subscription-scoped,
so they live in their own tables rather than reusing ``scans``/``findings``.
``ci_scan_evaluations`` mirrors ``rule_evaluations`` but is keyed to
``ci_scans.scan_id`` and carries no finding_id — CI rules emit
RuleEvaluation objects directly; there is no separate findings table for
the CI engine.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "e1f2a3b4c5d6"
down_revision: Union[str, Sequence[str], None] = "3f59f83a5253"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_STATUS_CONSTRAINT = "ck_ci_scan_evaluations_status_v1"
_SCOPE_CONSTRAINT = "ck_ci_scan_evaluations_resource_id_not_empty"
_REASON_CONSTRAINT = "ck_ci_scan_evaluations_reason_code_required"
_CI_SCAN_STATUS_CONSTRAINT = "ck_ci_scans_status_v1"


def upgrade() -> None:
    op.create_table(
        "ci_scans",
        sa.Column("scan_id", postgresql.UUID(), nullable=False),
        sa.Column("owner", sa.Text(), nullable=False),
        sa.Column("repo", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.Text(), server_default=sa.text("'pending'"), nullable=False),
        sa.Column("total_evaluations", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("fail_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("scan_id", name="ci_scans_pkey"),
    )

    op.create_check_constraint(
        _CI_SCAN_STATUS_CONSTRAINT,
        "ci_scans",
        "status IN ('pending', 'running', 'completed', 'failed')",
    )

    op.create_index("idx_ci_scans_owner_repo", "ci_scans", ["owner", "repo"], unique=False)
    op.create_index("idx_ci_scans_started_at", "ci_scans", ["started_at"], unique=False)
    op.create_index("idx_ci_scans_status", "ci_scans", ["status"], unique=False)

    op.create_table(
        "ci_scan_evaluations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=True,
        ),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["ci_scans.scan_id"],
            name="ci_scan_evaluations_scan_id_fkey",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="ci_scan_evaluations_pkey"),
        # One coverage row per rule per resource per scan — same uniqueness
        # contract as rule_evaluations, enabling ON CONFLICT upserts on retry.
        sa.UniqueConstraint(
            "scan_id",
            "rule_id",
            "resource_id",
            name="uq_ci_scan_evaluations_scan_rule_resource",
        ),
    )

    op.create_index("idx_ci_scan_evaluations_scan_id", "ci_scan_evaluations", ["scan_id"], unique=False)
    op.create_index("idx_ci_scan_evaluations_rule_id", "ci_scan_evaluations", ["rule_id"], unique=False)
    op.create_index("idx_ci_scan_evaluations_status", "ci_scan_evaluations", ["status"], unique=False)

    op.create_check_constraint(
        _STATUS_CONSTRAINT,
        "ci_scan_evaluations",
        "status IN ('PASS', 'FAIL', 'UNKNOWN', 'ERROR', 'NOT_APPLICABLE')",
    )
    op.create_check_constraint(
        _SCOPE_CONSTRAINT,
        "ci_scan_evaluations",
        "resource_id <> ''",
    )
    # UNKNOWN/ERROR/NOT_APPLICABLE must carry a reason_code — PASS and FAIL
    # are self-evident.
    op.create_check_constraint(
        _REASON_CONSTRAINT,
        "ci_scan_evaluations",
        "status NOT IN ('UNKNOWN', 'ERROR', 'NOT_APPLICABLE') OR (reason_code IS NOT NULL AND reason_code <> '')",
    )


def downgrade() -> None:
    op.drop_constraint(_REASON_CONSTRAINT, "ci_scan_evaluations", type_="check")
    op.drop_constraint(_SCOPE_CONSTRAINT, "ci_scan_evaluations", type_="check")
    op.drop_constraint(_STATUS_CONSTRAINT, "ci_scan_evaluations", type_="check")
    op.drop_index("idx_ci_scan_evaluations_status", table_name="ci_scan_evaluations")
    op.drop_index("idx_ci_scan_evaluations_rule_id", table_name="ci_scan_evaluations")
    op.drop_index("idx_ci_scan_evaluations_scan_id", table_name="ci_scan_evaluations")
    op.drop_table("ci_scan_evaluations")

    op.drop_constraint(_CI_SCAN_STATUS_CONSTRAINT, "ci_scans", type_="check")
    op.drop_index("idx_ci_scans_status", table_name="ci_scans")
    op.drop_index("idx_ci_scans_started_at", table_name="ci_scans")
    op.drop_index("idx_ci_scans_owner_repo", table_name="ci_scans")
    op.drop_table("ci_scans")
