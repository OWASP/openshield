"""Upsert graph nodes from an InventorySnapshot and link findings to nodes."""
from __future__ import annotations

import json
import logging
import uuid
from typing import TYPE_CHECKING

import psycopg2
import psycopg2.extras

if TYPE_CHECKING:
    from scanner.arg_inventory import InventorySnapshot

logger = logging.getLogger(__name__)

_UPSERT_NODE_SQL = """
INSERT INTO graph_nodes (
    node_id, tenant_id, subscription_id, resource_id, resource_type,
    name, location, resource_group, snapshot_id, properties, created_at, updated_at
)
VALUES (
    %(node_id)s, %(tenant_id)s, %(subscription_id)s, %(resource_id)s, %(resource_type)s,
    %(name)s, %(location)s, %(resource_group)s, %(snapshot_id)s, %(properties)s,
    now(), now()
)
ON CONFLICT (tenant_id, resource_id)
DO UPDATE SET
    resource_type = EXCLUDED.resource_type,
    name = EXCLUDED.name,
    location = EXCLUDED.location,
    resource_group = EXCLUDED.resource_group,
    snapshot_id = EXCLUDED.snapshot_id,
    properties = EXCLUDED.properties,
    updated_at = now()
"""

_LINK_FINDINGS_SQL = """
INSERT INTO finding_graph_nodes (finding_id, node_id)
SELECT f.id, n.node_id
FROM findings f
JOIN graph_nodes n ON lower(f.resource_id) = lower(n.resource_id)
    AND n.tenant_id = %(tenant_id)s
WHERE f.scan_id = %(scan_id)s
ON CONFLICT DO NOTHING
"""


def populate_nodes(snapshot: InventorySnapshot, dsn: str) -> int:
    """Upsert graph_nodes from snapshot resources. Returns count of rows written."""
    if not snapshot.resources:
        return 0

    written = 0
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            for resource in snapshot.resources:
                cur.execute(_UPSERT_NODE_SQL, {
                    "node_id": str(uuid.uuid4()),
                    "tenant_id": resource.tenant_id,
                    "subscription_id": resource.subscription_id,
                    "resource_id": resource.resource_id,
                    "resource_type": resource.resource_type,
                    "name": resource.name,
                    "location": resource.location,
                    "resource_group": resource.resource_group,
                    "snapshot_id": resource.snapshot_id,
                    "properties": json.dumps(resource.properties),
                })
                written += 1
    return written


def link_findings_to_nodes(scan_id: str, tenant_id: str, dsn: str) -> int:
    """Link findings from this scan to their graph nodes by resource_id."""
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(_LINK_FINDINGS_SQL, {"scan_id": scan_id, "tenant_id": tenant_id})
            return cur.rowcount if cur.rowcount >= 0 else 0
