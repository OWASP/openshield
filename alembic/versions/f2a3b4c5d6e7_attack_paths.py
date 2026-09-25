"""Add attack_paths table for pre-computed BFS traversal results.

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-09-24 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "f2a3b4c5d6e7"
down_revision: Union[str, Sequence[str], None] = "e1f2a3b4c5d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attack_paths",
        sa.Column("path_id", postgresql.UUID(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("scan_id", sa.Text(), nullable=False),
        sa.Column("source_node_id", postgresql.UUID(), nullable=False),
        sa.Column("target_node_id", postgresql.UUID(), nullable=False),
        sa.Column("path_node_ids", postgresql.ARRAY(postgresql.UUID()), nullable=False),
        sa.Column("path_length", sa.Integer(), nullable=False),
        sa.Column("min_confidence", sa.Float(), nullable=False, server_default=sa.text("1.0")),
        sa.Column(
            "relationship_types", postgresql.ARRAY(sa.Text()), nullable=False, server_default=sa.text("ARRAY[]::text[]")
        ),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["source_node_id"],
            ["graph_nodes.node_id"],
            name="attack_paths_source_fkey",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_node_id"],
            ["graph_nodes.node_id"],
            name="attack_paths_target_fkey",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("path_id", name="attack_paths_pkey"),
    )
    op.create_index("idx_attack_paths_tenant_scan", "attack_paths", ["tenant_id", "scan_id"])
    op.create_index("idx_attack_paths_source", "attack_paths", ["source_node_id"])
    op.create_index("idx_attack_paths_target", "attack_paths", ["target_node_id"])
    op.create_index(
        "uq_attack_paths_source_target_scan",
        "attack_paths",
        ["source_node_id", "target_node_id", "scan_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_attack_paths_source_target_scan", table_name="attack_paths")
    op.drop_index("idx_attack_paths_target", table_name="attack_paths")
    op.drop_index("idx_attack_paths_source", table_name="attack_paths")
    op.drop_index("idx_attack_paths_tenant_scan", table_name="attack_paths")
    op.drop_table("attack_paths")
