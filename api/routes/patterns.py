"""Patterns routes: list and retrieve published security patterns."""

import logging
import os

import psycopg2.extras
from flask import Blueprint, g, jsonify, request

from api.models.finding import DatabaseManager

patterns_bp = Blueprint("patterns", __name__)
logger = logging.getLogger(__name__)

_ALLOWED_PATTERN_TYPES = frozenset(
    {"persistent_finding", "cross_resource_recurrence", "reopened_finding"}
)
_DEFAULT_LIMIT = 20
_MAX_LIMIT = 100
_MIN_LIMIT = 1

_VALIDATION_ERROR_MESSAGE = "Invalid request parameters"


class _ValidationError(ValueError):
    """Raised when a client-controlled value violates the public API contract."""


def _get_db() -> DatabaseManager:
    if "db" not in g:
        g.db = DatabaseManager(os.environ["DATABASE_URL"])
        g.db.connect()
    return g.db


def _validate_limit(raw: str) -> int:
    try:
        value = int(raw)
    except (ValueError, TypeError) as exc:
        raise _ValidationError("limit must be an integer") from exc
    if value < _MIN_LIMIT or value > _MAX_LIMIT:
        raise _ValidationError(f"limit must be between {_MIN_LIMIT} and {_MAX_LIMIT}")
    return value


def _row_to_dict(row: dict) -> dict:
    """Serialise a patterns table row to a JSON-safe dict."""
    result = dict(row)
    for key in ("created_at", "updated_at"):
        val = result.get(key)
        if val is not None and hasattr(val, "isoformat"):
            result[key] = val.isoformat()
    if result.get("scan_id") is not None:
        result["scan_id"] = str(result["scan_id"])
    return result


@patterns_bp.get("/api/v1/patterns")
def list_patterns():
    """Return published security patterns, optionally filtered.

    Query parameters:
        subscription_id - filter by Azure subscription
        pattern_type    - one of persistent_finding, cross_resource_recurrence,
                          reopened_finding
        limit           - 1-100, default 20
    """
    try:
        allowed_params = {"subscription_id", "pattern_type", "limit"}
        unknown = set(request.args) - allowed_params
        if unknown:
            raise _ValidationError(f"Unsupported query parameter: {sorted(unknown)[0]}")
        for key in request.args:
            if len(request.args.getlist(key)) != 1:
                raise _ValidationError(f"Query parameter {key} must be provided once")

        subscription_id = None
        if "subscription_id" in request.args:
            val = request.args["subscription_id"].strip()
            if not val or len(val) > 256:
                raise _ValidationError("subscription_id is invalid")
            subscription_id = val

        pattern_type = None
        if "pattern_type" in request.args:
            raw_pt = request.args["pattern_type"].strip()
            if raw_pt not in _ALLOWED_PATTERN_TYPES:
                raise _ValidationError("Unsupported pattern_type")
            pattern_type = raw_pt

        limit = _DEFAULT_LIMIT
        if "limit" in request.args:
            limit = _validate_limit(request.args["limit"])

        db = _get_db()
        conn = db._get_conn()

        # Tenant isolation: prefer subscription_id embedded in the JWT payload;
        # fall back to the query parameter.
        user = getattr(g, "user", {}) or {}
        effective_sub = user.get("subscription_id") or subscription_id

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, pattern_type, lifecycle_id, tenant_id,
                       subscription_id, scan_id, finding_ids, threshold,
                       algorithm_version, created_at, updated_at
                FROM patterns
                WHERE (%s IS NULL OR subscription_id = %s)
                  AND (%s IS NULL OR pattern_type = %s)
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (
                    effective_sub, effective_sub,
                    pattern_type, pattern_type,
                    limit,
                ),
            )
            rows = cur.fetchall()

            cur.execute(
                """
                SELECT COUNT(*) AS count
                FROM patterns
                WHERE (%s IS NULL OR subscription_id = %s)
                  AND (%s IS NULL OR pattern_type = %s)
                """,
                (effective_sub, effective_sub, pattern_type, pattern_type),
            )
            total_row = cur.fetchone()
            total = total_row["count"] if total_row else 0

        return jsonify(
            {
                "patterns": [_row_to_dict(r) for r in rows],
                "total": total,
            }
        )

    except _ValidationError:
        return jsonify({"error": _VALIDATION_ERROR_MESSAGE}), 400
    except Exception as exc:
        logger.error("Failed to list patterns: %s", exc)
        return jsonify({"error": "Failed to retrieve patterns"}), 500


@patterns_bp.get("/api/v1/patterns/<int:pattern_id>")
def get_pattern(pattern_id: int):
    """Return a single pattern by its integer ID."""
    try:
        if pattern_id <= 0:
            raise _ValidationError("pattern_id must be a positive integer")

        db = _get_db()
        conn = db._get_conn()

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, pattern_type, lifecycle_id, tenant_id,
                       subscription_id, scan_id, finding_ids, threshold,
                       algorithm_version, created_at, updated_at
                FROM patterns
                WHERE id = %s
                """,
                (pattern_id,),
            )
            row = cur.fetchone()

        if row is None:
            return jsonify({"error": "Pattern not found"}), 404

        return jsonify(_row_to_dict(row))

    except _ValidationError:
        return jsonify({"error": _VALIDATION_ERROR_MESSAGE}), 400
    except Exception as exc:
        logger.error("Failed to get pattern %s: %s", pattern_id, exc)
        return jsonify({"error": "Failed to retrieve pattern"}), 500
