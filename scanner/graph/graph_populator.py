"""Orchestrate post-scan graph population: nodes, edges, finding links."""
from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

import psycopg2
import psycopg2.extras

from scanner.graph.node_service import link_findings_to_nodes, populate_nodes
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
  AND lower(tgt.resource_id) = lower(%(target_resource_id)s)
ON CONFLICT (source_node_id, target_node_id, relationship_type) DO UPDATE SET
    confidence = EXCLUDED.confidence,
    evidence_source = EXCLUDED.evidence_source,
    evidence_snapshot_id = EXCLUDED.evidence_snapshot_id,
    collected_at = now()
"""


def _write_edges(edges: list, snapshot_id: str, dsn: str) -> int:
    if not edges:
        return 0
    written = 0
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            for edge in edges:
                cur.execute(_UPSERT_EDGE_SQL, {
                    "edge_id": str(uuid.uuid4()),
                    "source_resource_id": edge.source_resource_id,
                    "target_resource_id": edge.target_resource_id,
                    "relationship_type": edge.relationship_type,
                    "evidence_source": edge.evidence_source,
                    "evidence_snapshot_id": snapshot_id,
                    "confidence": edge.confidence,
                })
                written += 1
    return written


def populate_graph(scan_id: str, snapshot: InventorySnapshot, dsn: str) -> None:
    """Populate nodes, edges, and finding links for one scan. Failure is non-fatal."""
    try:
        node_count = populate_nodes(snapshot, dsn)
        logger.info("graph: upserted %d nodes for scan %s", node_count, scan_id)
    except Exception as exc:
        logger.warning("graph: node population failed for scan %s: %s", scan_id, exc)
        return

    try:
        edges = detect_all_edges(snapshot)
        edge_count = _write_edges(edges, snapshot.snapshot_id, dsn)
        logger.info("graph: wrote %d edges for scan %s", edge_count, scan_id)
    except Exception as exc:
        logger.warning("graph: edge population failed for scan %s: %s", scan_id, exc)

    try:
        link_count = link_findings_to_nodes(scan_id, snapshot.tenant_id, dsn)
        logger.info("graph: linked %d findings to nodes for scan %s", link_count, scan_id)
    except Exception as exc:
        logger.warning("graph: finding link failed for scan %s: %s", scan_id, exc)
