"""Track the explicit current snapshot for each tenant/subscription graph.

Revision ID: e2c4a6b8d013
Revises: e1f2a3b4c5d6
"""

from typing import Sequence, Union
from alembic import op

revision: str = "e2c4a6b8d013"
down_revision: str = "e1f2a3b4c5d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE graph_snapshot_scopes (
            tenant_id text NOT NULL,
            subscription_id text NOT NULL,
            snapshot_id text NOT NULL,
            status text NOT NULL CHECK (status IN ('COMPLETE', 'PARTIAL')),
            collected_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, subscription_id)
        )
    """)
    op.execute("""
        CREATE VIEW current_graph_nodes AS
        SELECT n.* FROM graph_nodes n
        JOIN graph_snapshot_scopes s
          ON s.tenant_id = n.tenant_id AND s.subscription_id = n.subscription_id
         AND s.snapshot_id = n.snapshot_id
    """)
    op.execute("""
        CREATE VIEW current_graph_edges AS
        SELECT e.* FROM graph_edges e
        JOIN current_graph_nodes src ON src.node_id = e.source_node_id
        JOIN current_graph_nodes tgt ON tgt.node_id = e.target_node_id
        WHERE src.tenant_id = tgt.tenant_id
          AND e.evidence_snapshot_id = src.snapshot_id
          AND e.evidence_snapshot_id = tgt.snapshot_id
    """)


def downgrade() -> None:
    op.execute("DROP VIEW current_graph_edges")
    op.execute("DROP VIEW current_graph_nodes")
    op.execute("DROP TABLE graph_snapshot_scopes")
