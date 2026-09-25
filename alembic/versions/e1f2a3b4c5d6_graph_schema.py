"""Add graph_nodes, graph_edges, and finding_graph_nodes for attack graph.

Revision ID: e1f2a3b4c5d6
Revises: 3f59f83a5253
Create Date: 2026-09-24 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "e1f2a3b4c5d6"
down_revision: Union[str, Sequence[str], None] = "3f59f83a5253"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "graph_nodes",
        sa.Column("node_id", postgresql.UUID(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("subscription_id", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("location", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("resource_group", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("snapshot_id", sa.Text(), nullable=False),
        sa.Column("properties", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("node_id", name="graph_nodes_pkey"),
    )
    op.create_index("idx_graph_nodes_resource_id", "graph_nodes", ["resource_id"])
    op.create_index("idx_graph_nodes_tenant_subscription", "graph_nodes", ["tenant_id", "subscription_id"])
    op.create_index(
        "uq_graph_nodes_tenant_resource",
        "graph_nodes",
        ["tenant_id", "resource_id"],
        unique=True,
    )

    op.create_table(
        "graph_edges",
        sa.Column("edge_id", postgresql.UUID(), nullable=False),
        sa.Column("source_node_id", postgresql.UUID(), nullable=False),
        sa.Column("target_node_id", postgresql.UUID(), nullable=False),
        sa.Column("relationship_type", sa.Text(), nullable=False),
        sa.Column("evidence_source", sa.Text(), nullable=False),
        sa.Column("evidence_snapshot_id", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default=sa.text("1.0")),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("properties", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.ForeignKeyConstraint(
            ["source_node_id"], ["graph_nodes.node_id"], name="graph_edges_source_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["target_node_id"], ["graph_nodes.node_id"], name="graph_edges_target_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("edge_id", name="graph_edges_pkey"),
    )
    op.create_index("idx_graph_edges_source", "graph_edges", ["source_node_id"])
    op.create_index("idx_graph_edges_target", "graph_edges", ["target_node_id"])
    op.create_index(
        "uq_graph_edges_source_target_type",
        "graph_edges",
        ["source_node_id", "target_node_id", "relationship_type"],
        unique=True,
    )

    op.create_table(
        "finding_graph_nodes",
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("node_id", postgresql.UUID(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name="finding_graph_nodes_finding_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["node_id"], ["graph_nodes.node_id"], name="finding_graph_nodes_node_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("finding_id", "node_id", name="finding_graph_nodes_pkey"),
    )
    op.create_index("idx_finding_graph_nodes_node_id", "finding_graph_nodes", ["node_id"])


def downgrade() -> None:
    op.drop_index("idx_finding_graph_nodes_node_id", table_name="finding_graph_nodes")
    op.drop_table("finding_graph_nodes")

    op.drop_index("uq_graph_edges_source_target_type", table_name="graph_edges")
    op.drop_index("idx_graph_edges_target", table_name="graph_edges")
    op.drop_index("idx_graph_edges_source", table_name="graph_edges")
    op.drop_table("graph_edges")

    op.drop_index("uq_graph_nodes_tenant_resource", table_name="graph_nodes")
    op.drop_index("idx_graph_nodes_tenant_subscription", table_name="graph_nodes")
    op.drop_index("idx_graph_nodes_resource_id", table_name="graph_nodes")
    op.drop_table("graph_nodes")
