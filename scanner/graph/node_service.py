"""Upsert graph nodes from an InventorySnapshot and link findings to nodes."""

from __future__ import annotations

import json
import logging
import uuid
from contextlib import contextmanager
from typing import TYPE_CHECKING

import psycopg2


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
JOIN scans s ON s.scan_id = f.scan_id
JOIN current_graph_nodes n ON lower(f.resource_id) = lower(n.resource_id)
    AND n.tenant_id = %(tenant_id)s
    AND n.subscription_id = s.subscription_id
WHERE f.scan_id = %(scan_id)s
ON CONFLICT DO NOTHING
"""


@contextmanager
def graph_connection(dsn: str, existing=None):
    """Own a transaction only when no caller transaction was provided."""
    if existing is not None:
        yield existing
        return
    conn = psycopg2.connect(dsn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def populate_nodes(snapshot: InventorySnapshot, dsn: str, *, connection=None) -> int:
    """Upsert graph_nodes from snapshot resources. Returns count of rows written."""
    if not snapshot.resources:
        return 0

    written = 0
    with graph_connection(dsn, connection) as conn:
        with conn.cursor() as cur:
            for resource in snapshot.resources:
                if (
                    resource.tenant_id != snapshot.tenant_id
                    or resource.subscription_id not in snapshot.requested_subscriptions
                    or resource.snapshot_id != snapshot.snapshot_id
                ):
                    raise ValueError("resource is outside its snapshot scope")
                cur.execute(
                    _UPSERT_NODE_SQL,
                    {
                        "node_id": str(uuid.uuid4()),
                        "tenant_id": resource.tenant_id,
                        "subscription_id": resource.subscription_id,
                        "resource_id": resource.resource_id.lower(),
                        "resource_type": resource.resource_type,
                        "name": resource.name,
                        "location": resource.location,
                        "resource_group": resource.resource_group,
                        "snapshot_id": resource.snapshot_id,
                        "properties": json.dumps(resource.properties),
                    },
                )
                written += max(cur.rowcount, 0)
    return written


def link_findings_to_nodes(scan_id: str, tenant_id: str, dsn: str, *, connection=None) -> int:
    """Link findings from this scan to their graph nodes by resource_id."""
    with graph_connection(dsn, connection) as conn:
        with conn.cursor() as cur:
            cur.execute(_LINK_FINDINGS_SQL, {"scan_id": scan_id, "tenant_id": tenant_id})
            result = cur.rowcount if cur.rowcount >= 0 else 0
    return result


def lock_graph_scopes(conn, tenant_id: str, subscriptions) -> None:
    """Serialize all publications and traversals within the same scope."""
    with conn.cursor() as cur:
        for subscription in sorted(set(subscriptions)):
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"openshield-graph:{tenant_id}:{subscription}",),
            )
