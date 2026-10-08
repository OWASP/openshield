"""Orchestrate post-scan graph population: nodes, edges, finding links."""

from __future__ import annotations

import logging
import uuid
from dataclasses import replace as dc_replace
from typing import TYPE_CHECKING


from scanner.arg_inventory import InventoryResource, InventoryStatus
from scanner.graph.node_service import graph_connection, link_findings_to_nodes, lock_graph_scopes, populate_nodes
from scanner.graph.edge_detector import detect_all_edges

if TYPE_CHECKING:
    from scanner.arg_inventory import InventorySnapshot

logger = logging.getLogger(__name__)

_UPSERT_EDGE_SQL = """
INSERT INTO graph_edges (
    edge_id, source_node_id, target_node_id, relationship_type,
    evidence_source, evidence_snapshot_id, confidence, collected_at, properties
)
SELECT
    %(edge_id)s,
    src.node_id,
    tgt.node_id,
    %(relationship_type)s,
    %(evidence_source)s,
    %(evidence_snapshot_id)s,
    %(confidence)s,
    now(),
    '{}'::jsonb
FROM graph_nodes src, graph_nodes tgt
WHERE lower(src.resource_id) = lower(%(source_resource_id)s)
  AND src.tenant_id = %(tenant_id)s
  AND lower(tgt.resource_id) = lower(%(target_resource_id)s)
  AND tgt.tenant_id = %(tenant_id)s
  AND src.snapshot_id = %(evidence_snapshot_id)s
  AND tgt.snapshot_id = %(evidence_snapshot_id)s
ON CONFLICT (source_node_id, target_node_id, relationship_type) DO UPDATE SET
    confidence = EXCLUDED.confidence,
    evidence_source = EXCLUDED.evidence_source,
    evidence_snapshot_id = EXCLUDED.evidence_snapshot_id,
    collected_at = now()
"""


def _write_edges(edges: list, snapshot_id: str, tenant_id: str, dsn: str, *, connection=None) -> int:
    if not edges:
        return 0
    written = 0
    with graph_connection(dsn, connection) as conn:
        with conn.cursor() as cur:
            for edge in edges:
                cur.execute(
                    _UPSERT_EDGE_SQL,
                    {
                        "edge_id": str(uuid.uuid4()),
                        "source_resource_id": edge.source_resource_id,
                        "target_resource_id": edge.target_resource_id,
                        "relationship_type": edge.relationship_type,
                        "evidence_source": edge.evidence_source,
                        "evidence_snapshot_id": snapshot_id,
                        "tenant_id": tenant_id,
                        "confidence": edge.confidence,
                    },
                )
                written += max(cur.rowcount, 0)
    return written


_VNET_TYPE = "microsoft.network/virtualnetworks"
_SUBNET_TYPE = "microsoft.network/virtualnetworks/subnets"


def _synthesise_subnet_resources(snapshot: InventorySnapshot) -> list[InventoryResource]:
    """Return synthetic InventoryResource entries for subnets nested inside VNets.

    ARG Resources has no top-level rows for subnets; they appear only as
    properties.subnets on the parent VNet. Without this step, SubnetToResourceDetector
    and NsgToSubnetDetector produce edges whose target has no matching graph_node,
    and _UPSERT_EDGE_SQL silently drops them (INSERT ... SELECT JOIN graph_nodes).
    """
    subnets: list[InventoryResource] = []
    for resource in snapshot.resources:
        if resource.resource_type.lower() != _VNET_TYPE:
            continue
        for subnet in resource.properties.get("subnets") or []:
            subnet_id = subnet.get("id") if isinstance(subnet, dict) else None
            if not subnet_id:
                continue
            subnet_name = subnet.get("name", subnet_id.split("/")[-1])
            subnets.append(
                InventoryResource(
                    snapshot_id=resource.snapshot_id,
                    tenant_id=resource.tenant_id,
                    subscription_id=resource.subscription_id,
                    resource_id=subnet_id,
                    resource_type=_SUBNET_TYPE,
                    name=subnet_name,
                    location=resource.location,
                    resource_group=resource.resource_group,
                    tags={},
                    properties=subnet.get("properties") or {},
                )
            )
    return subnets


def populate_graph(scan_id: str, snapshot: InventorySnapshot, dsn: str) -> None:
    """Populate nodes, edges, and finding links for one scan. Failure is non-fatal."""
    subnet_resources = _synthesise_subnet_resources(snapshot)
    if subnet_resources:
        logger.debug("graph: synthesised %d subnet nodes from VNet properties", len(subnet_resources))

    augmented_snapshot = dc_replace(
        snapshot,
        resources=snapshot.resources + tuple(subnet_resources),
    )

    if snapshot.status == InventoryStatus.FAILED:
        return
    try:
        # Publish the new scope only after every write succeeds. Partial snapshots
        # retain historical rows, but the views expose only explicit current evidence.
        with graph_connection(dsn) as conn:
            lock_graph_scopes(conn, snapshot.tenant_id, snapshot.requested_subscriptions)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM graph_snapshot_scopes WHERE tenant_id=%s "
                    "AND subscription_id=ANY(%s) AND collected_at > %s::timestamptz LIMIT 1",
                    (snapshot.tenant_id, list(snapshot.requested_subscriptions), snapshot.collected_at),
                )
                if cur.fetchone() is not None:
                    logger.info("graph: ignored older snapshot for scan %s", scan_id)
                    return
            node_count = populate_nodes(augmented_snapshot, dsn, connection=conn)
            edges = detect_all_edges(augmented_snapshot)
            edge_count = _write_edges(edges, snapshot.snapshot_id, snapshot.tenant_id, dsn, connection=conn)
            with conn.cursor() as cur:
                params = {
                    "tenant": snapshot.tenant_id,
                    "subscriptions": list(snapshot.requested_subscriptions),
                    "snapshot": snapshot.snapshot_id,
                }
                if snapshot.status == InventoryStatus.COMPLETE:
                    cur.execute(
                        """
                        DELETE FROM graph_edges e USING graph_nodes src, graph_nodes tgt
                        WHERE src.node_id = e.source_node_id AND tgt.node_id = e.target_node_id
                          AND src.tenant_id = %(tenant)s AND tgt.tenant_id = %(tenant)s
                          AND (src.subscription_id = ANY(%(subscriptions)s)
                               OR tgt.subscription_id = ANY(%(subscriptions)s))
                          AND e.evidence_snapshot_id <> %(snapshot)s
                    """,
                        params,
                    )
                    cur.execute(
                        """
                        DELETE FROM graph_nodes
                        WHERE tenant_id = %(tenant)s AND subscription_id = ANY(%(subscriptions)s)
                          AND snapshot_id <> %(snapshot)s
                    """,
                        params,
                    )
                for subscription in snapshot.requested_subscriptions:
                    cur.execute(
                        """
                        INSERT INTO graph_snapshot_scopes
                          (tenant_id, subscription_id, snapshot_id, status, collected_at)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (tenant_id, subscription_id) DO UPDATE SET
                          snapshot_id = EXCLUDED.snapshot_id, status = EXCLUDED.status,
                          collected_at = EXCLUDED.collected_at
                    """,
                        (
                            snapshot.tenant_id,
                            subscription,
                            snapshot.snapshot_id,
                            snapshot.status.value,
                            snapshot.collected_at,
                        ),
                    )
            link_count = link_findings_to_nodes(scan_id, snapshot.tenant_id, dsn, connection=conn)
        logger.info(
            "graph: wrote %d nodes, %d edges, %d links for scan %s", node_count, edge_count, link_count, scan_id
        )
    except Exception:
        logger.warning("graph: population failed for scan %s", scan_id, exc_info=True)
