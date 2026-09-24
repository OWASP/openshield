"""Attack graph API: resource nodes, edges, and pre-computed attack paths."""

import logging
import os

import psycopg2
import psycopg2.extras
from flask import Blueprint, g, jsonify, request

from api.validation import ValidationError, positive_integer, uuid_string

attack_graph_bp = Blueprint("attack_graph", __name__)
logger = logging.getLogger(__name__)

_DEFAULT_LIMIT = 100
_MAX_LIMIT = 500


def _conn():
    if "graph_conn" not in g:
        g.graph_conn = psycopg2.connect(os.environ["DATABASE_URL"])
        g.graph_conn.autocommit = True
        psycopg2.extras.register_uuid(g.graph_conn)
    return g.graph_conn


def _tenant_id() -> str | None:
    """Resolve tenant_id from the verified principal.

    OIDC mode: the 'tenant' field is populated from the 'tid' claim in the token.
    Shared-secret mode: 'tenant' is always None; admins may supply
    X-Tenant-Id as a request header (never a query param, which leaks into
    logs and caches). Non-admin tokens cannot override the header.
    """
    user = getattr(g, "user", {}) or {}
    # OIDC path: tid claim decoded by the verifier into user["tenant"]
    tid = user.get("tenant")
    if tid:
        return tid
    # Shared-secret path: admin-only header override for multi-tenant deployments
    if user.get("role") == "admin":
        return request.headers.get("X-Tenant-Id") or None
    return None


@attack_graph_bp.teardown_app_request
def _close_conn(exc):
    conn = g.pop("graph_conn", None)
    if conn is not None:
        conn.close()


@attack_graph_bp.get("/api/attack-graph")
def get_attack_graph():
    """Return graph nodes and edges for the caller's tenant (latest snapshot).

    Query params: subscription_id (optional), limit (default 100, max 500)
    """
    try:
        limit = positive_integer(request.args.get("limit", _DEFAULT_LIMIT), "limit")
        if limit > _MAX_LIMIT:
            limit = _MAX_LIMIT
        subscription_id = request.args.get("subscription_id")
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    tenant_id = _tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_id not available"}), 400

    conn = _conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        node_filter = "WHERE n.tenant_id = %(tenant_id)s"
        params: dict = {"tenant_id": tenant_id, "limit": limit}
        if subscription_id:
            node_filter += " AND n.subscription_id = %(subscription_id)s"
            params["subscription_id"] = subscription_id

        cur.execute(
            f"""
            SELECT n.node_id::text, n.resource_id, n.resource_type, n.name,
                   n.location, n.resource_group, n.subscription_id, n.snapshot_id,
                   n.updated_at
            FROM graph_nodes n
            {node_filter}
            ORDER BY n.updated_at DESC
            LIMIT %(limit)s
            """,
            params,
        )
        nodes = cur.fetchall()

        node_ids = [row["node_id"] for row in nodes]
        edges: list = []
        if node_ids:
            cur.execute(
                """
                SELECT e.edge_id::text, e.source_node_id::text, e.target_node_id::text,
                       e.relationship_type, e.confidence, e.evidence_source, e.collected_at
                FROM graph_edges e
                WHERE e.source_node_id = ANY(%(node_ids)s::uuid[])
                   OR e.target_node_id = ANY(%(node_ids)s::uuid[])
                """,
                {"node_ids": node_ids},
            )
            edges = cur.fetchall()

    return jsonify({"nodes": [dict(r) for r in nodes], "edges": [dict(r) for r in edges]})


@attack_graph_bp.get("/api/attack-paths")
def list_attack_paths():
    """Return pre-computed attack paths for a scan.

    Query params: scan_id (required), limit (default 100, max 500)
    """
    scan_id = request.args.get("scan_id")
    if not scan_id:
        return jsonify({"error": "scan_id is required"}), 400
    try:
        scan_id = uuid_string(scan_id, "scan_id")
        limit = positive_integer(request.args.get("limit", _DEFAULT_LIMIT), "limit")
        if limit > _MAX_LIMIT:
            limit = _MAX_LIMIT
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    tenant_id = _tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_id not available"}), 400

    conn = _conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT ap.path_id::text, ap.source_node_id::text, ap.target_node_id::text,
                   ap.path_node_ids, ap.path_length, ap.min_confidence,
                   ap.relationship_types, ap.computed_at,
                   src.resource_type AS source_type, src.name AS source_name,
                   tgt.resource_type AS target_type, tgt.name AS target_name
            FROM attack_paths ap
            JOIN graph_nodes src ON src.node_id = ap.source_node_id
            JOIN graph_nodes tgt ON tgt.node_id = ap.target_node_id
            WHERE ap.scan_id = %(scan_id)s
              AND ap.tenant_id = %(tenant_id)s
            ORDER BY ap.path_length ASC, ap.min_confidence DESC
            LIMIT %(limit)s
            """,
            {"scan_id": scan_id, "tenant_id": tenant_id, "limit": limit},
        )
        rows = cur.fetchall()

    return jsonify({"scan_id": scan_id, "paths": [dict(r) for r in rows]})


@attack_graph_bp.get("/api/attack-paths/<path_id>")
def get_attack_path(path_id: str):
    """Return a single attack path with full node detail for each hop."""
    try:
        path_id = uuid_string(path_id, "path_id")
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    tenant_id = _tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_id not available"}), 400

    conn = _conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT ap.path_id::text, ap.scan_id, ap.source_node_id::text,
                   ap.target_node_id::text, ap.path_node_ids, ap.path_length,
                   ap.min_confidence, ap.relationship_types, ap.computed_at
            FROM attack_paths ap
            WHERE ap.path_id = %(path_id)s::uuid
              AND ap.tenant_id = %(tenant_id)s
            """,
            {"path_id": path_id, "tenant_id": tenant_id},
        )
        row = cur.fetchone()

    if row is None:
        return jsonify({"error": "not found"}), 404

    path = dict(row)

    # Fetch full node detail for each hop
    node_ids = [str(nid) for nid in path["path_node_ids"]]
    if node_ids:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT node_id::text, resource_id, resource_type, name,
                       location, resource_group, subscription_id
                FROM graph_nodes
                WHERE node_id = ANY(%(ids)s::uuid[])
                  AND tenant_id = %(tenant_id)s
                """,
                {"ids": node_ids, "tenant_id": tenant_id},
            )
            nodes_by_id = {r["node_id"]: dict(r) for r in cur.fetchall()}
        path["hops"] = [nodes_by_id.get(str(nid), {"node_id": str(nid)}) for nid in path["path_node_ids"]]

    path["path_node_ids"] = [str(nid) for nid in path["path_node_ids"]]
    return jsonify(path)
