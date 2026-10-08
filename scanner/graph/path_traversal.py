"""BFS path traversal over the attack graph stored in PostgreSQL.

Computes shortest paths from every finding-linked node to every reachable node
and persists them in attack_paths for API consumption.
"""

from __future__ import annotations

import logging
import uuid
from collections import deque
from typing import Any

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)

# Paths longer than this are not persisted â€” they're rarely actionable and
# keeping them would inflate the table for large graphs.
_MAX_PATH_LENGTH = 8

# Relationships whose edges are also traversed in reverse during BFS.
# MEMBER_OF and PROTECTS are excluded: reversing MEMBER_OF would let any two
# VMs in the same subnet reach each other via the subnet node.
_REVERSE_RELS: frozenset[str] = frozenset({"EXPOSES", "HAS_IDENTITY"})


def _load_adjacency(conn: Any, tenant_id: str) -> dict[str, list[tuple[str, str, float]]]:
    """Return {source_node_id: [(target_node_id, relationship_type, confidence)]}."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT e.source_node_id::text, e.target_node_id::text,
                   e.relationship_type, e.confidence
            FROM current_graph_edges e
            JOIN current_graph_nodes src ON src.node_id = e.source_node_id
            WHERE src.tenant_id = %(tenant_id)s
            """,
            {"tenant_id": tenant_id},
        )
        # Only traverse in reverse for relationships where the reverse direction
        # is semantically meaningful. MEMBER_OF and PROTECTS are not reversed:
        # reversing MEMBER_OF would let any two VMs in the same subnet reach
        # each other via the subnet node, producing spurious lateral-movement paths.
        adj: dict[str, list[tuple[str, str, float]]] = {}
        for src, tgt, rel, conf in cur.fetchall():
            adj.setdefault(src, []).append((tgt, rel, conf))
            if rel in _REVERSE_RELS:
                adj.setdefault(tgt, []).append((src, rel + "_REV", conf))
    return adj


def _load_finding_nodes(conn: Any, scan_id: str, tenant_id: str) -> list[str]:
    """Return node_ids linked to findings from this scan (same tenant)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT fgn.node_id::text
            FROM finding_graph_nodes fgn
            JOIN findings f ON f.id = fgn.finding_id
            JOIN current_graph_nodes n ON n.node_id = fgn.node_id
            WHERE f.scan_id = %(scan_id)s
              AND n.tenant_id = %(tenant_id)s
            """,
            {"scan_id": scan_id, "tenant_id": tenant_id},
        )
        return [row[0] for row in cur.fetchall()]


def _bfs_from(
    start: str,
    adj: dict[str, list[tuple[str, str, float]]],
) -> list[dict[str, Any]]:
    """BFS from start. Returns one path record per reachable node (shortest path)."""
    paths: list[dict[str, Any]] = []
    # queue: (current_node_id, path_so_far, min_confidence, relationship_types)
    queue: deque[tuple[str, list[str], float, list[str]]] = deque()
    queue.append((start, [start], 1.0, []))
    visited: set[str] = {start}

    while queue:
        node, path, min_conf, rels = queue.popleft()
        for neighbour, rel, conf in adj.get(node, []):
            if neighbour in visited:
                continue
            visited.add(neighbour)
            new_path = path + [neighbour]
            new_rels = rels + [rel]
            new_conf = min(min_conf, conf)
            paths.append(
                {
                    "target_node_id": neighbour,
                    "path_node_ids": new_path,
                    "path_length": len(new_path) - 1,
                    "min_confidence": new_conf,
                    "relationship_types": new_rels,
                }
            )
            if len(new_path) - 1 < _MAX_PATH_LENGTH:
                queue.append((neighbour, new_path, new_conf, new_rels))

    return paths


def _delete_stale_paths(conn: Any, scan_id: str, tenant_id: str) -> None:
    """Delete attack paths from previous scans for the same subscription, keeping only the current scan."""
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM attack_paths ap
            USING scans previous, scans current
            WHERE ap.tenant_id = %(tenant_id)s
              AND ap.scan_id <> %(scan_id)s
              AND previous.scan_id::text = ap.scan_id
              AND current.scan_id = %(scan_id)s::uuid
              AND current.status = 'completed'
              AND previous.subscription_id = current.subscription_id
            """,
            {"tenant_id": tenant_id, "scan_id": scan_id},
        )


def _write_paths(
    conn: Any,
    scan_id: str,
    tenant_id: str,
    source_node_id: str,
    paths: list[dict[str, Any]],
) -> int:
    if not paths:
        return 0
    with conn.cursor() as cur:
        rows = [
            (
                str(uuid.uuid4()),
                tenant_id,
                scan_id,
                source_node_id,
                p["target_node_id"],
                p["path_node_ids"],
                p["path_length"],
                p["min_confidence"],
                p["relationship_types"],
            )
            for p in paths
        ]
        psycopg2.extras.execute_values(
            cur,
            """
            INSERT INTO attack_paths
              (path_id, tenant_id, scan_id, source_node_id, target_node_id,
               path_node_ids, path_length, min_confidence, relationship_types)
            VALUES %s
            ON CONFLICT (source_node_id, target_node_id, scan_id) DO NOTHING
            """,
            rows,
            template="(%s, %s, %s, %s::uuid, %s::uuid, %s::uuid[], %s, %s, %s)",
        )
        inserted = cur.rowcount
    # cur.rowcount reflects actual inserts after ON CONFLICT DO NOTHING;
    # fall back to attempted count if the driver reports -1.
    return inserted if inserted >= 0 else len(rows)


def compute_attack_paths(scan_id: str, tenant_id: str, dsn: str) -> int:
    """Run BFS from every finding-linked node and persist paths. Returns path count."""
    try:
        conn = psycopg2.connect(dsn)
        conn.autocommit = False
        try:
            _delete_stale_paths(conn, scan_id, tenant_id)
            adj = _load_adjacency(conn, tenant_id)
            source_nodes = _load_finding_nodes(conn, scan_id, tenant_id)
            if not source_nodes:
                logger.info("graph path traversal: no finding-linked nodes for scan %s", scan_id)
                conn.commit()
                return 0

            total = 0
            for src in source_nodes:
                paths = _bfs_from(src, adj)
                total += _write_paths(conn, scan_id, tenant_id, src, paths)

            conn.commit()
            logger.info("graph path traversal: %d paths written for scan %s", total, scan_id)
            return total
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    except Exception:
        logger.error("graph path traversal failed for scan %s", scan_id, exc_info=True)
        return 0
