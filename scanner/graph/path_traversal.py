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

# Paths longer than this are not persisted — they're rarely actionable and
# keeping them would inflate the table for large graphs.
_MAX_PATH_LENGTH = 8


def _load_adjacency(conn: Any, tenant_id: str) -> dict[str, list[tuple[str, str, float]]]:
    """Return {source_node_id: [(target_node_id, relationship_type, confidence)]}."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT e.source_node_id::text, e.target_node_id::text,
                   e.relationship_type, e.confidence
            FROM graph_edges e
            JOIN graph_nodes src ON src.node_id = e.source_node_id
            WHERE src.tenant_id = %(tenant_id)s
            """,
            {"tenant_id": tenant_id},
        )
        adj: dict[str, list[tuple[str, str, float]]] = {}
        for src, tgt, rel, conf in cur.fetchall():
            adj.setdefault(src, []).append((tgt, rel, conf))
    return adj


def _load_finding_nodes(conn: Any, scan_id: str, tenant_id: str) -> list[str]:
    """Return node_ids linked to findings from this scan (same tenant)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT fgn.node_id::text
            FROM finding_graph_nodes fgn
            JOIN findings f ON f.id = fgn.finding_id
            JOIN graph_nodes n ON n.node_id = fgn.node_id
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
    return len(rows)


def compute_attack_paths(scan_id: str, tenant_id: str, dsn: str) -> int:
    """Run BFS from every finding-linked node and persist paths. Returns path count."""
    try:
        conn = psycopg2.connect(dsn)
        conn.autocommit = False
        try:
            adj = _load_adjacency(conn, tenant_id)
            source_nodes = _load_finding_nodes(conn, scan_id, tenant_id)
            if not source_nodes:
                logger.info("graph path traversal: no finding-linked nodes for scan %s", scan_id)
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
    except Exception as exc:
        logger.error("graph path traversal failed for scan %s: %s", scan_id, exc)
        return 0
