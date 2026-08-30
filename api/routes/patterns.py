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


def _effective_tenant(effective_sub: str) -> str:
    """Return the tenant scope for this request.

    Uses OPENSHIELD_TENANT_ID env var when set (multi-tenant deployments).
    Falls back to effective_sub for single-tenant deployments where
    tenant_id == subscription_id by convention.
    """
    return os.environ.get("OPENSHIELD_TENANT_ID", effective_sub)


def _effective_subscription(subscription_id_param: str | None) -> str:
    """Return the subscription scope this request is authorized to see.

    The JWT subscription_id is always the authority. A query-param
    subscription_id may narrow the JWT scope but never widen it. If the
    JWT carries no subscription_id, the query param is accepted as the
    scope (single-tenant deployments that do not embed subscription_id in
    tokens). Either way the scope must be non-empty: an unscoped query
    would return patterns from every subscription, which is never correct.
    """
    user = getattr(g, "user", {}) or {}
    jwt_sub = user.get("subscription_id")

    if jwt_sub:
        if subscription_id_param and subscription_id_param != jwt_sub:
            raise _ValidationError("subscription_id does not match token scope")
        return jwt_sub

    if subscription_id_param:
        return subscription_id_param

    raise _ValidationError("subscription_id is required")


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
        subscription_id - filter by Azure subscription (must match JWT scope)
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

        subscription_id_param = None
        if "subscription_id" in request.args:
            val = request.args["subscription_id"].strip()
            if not val or len(val) > 256:
                raise _ValidationError("subscription_id is invalid")
            subscription_id_param = val

        pattern_type = None
        if "pattern_type" in request.args:
            raw_pt = request.args["pattern_type"].strip()
            if raw_pt not in _ALLOWED_PATTERN_TYPES:
                raise _ValidationError("Unsupported pattern_type")
            pattern_type = raw_pt

        limit = _DEFAULT_LIMIT
        if "limit" in request.args:
            limit = _validate_limit(request.args["limit"])

        effective_sub = _effective_subscription(subscription_id_param)
        tenant_id = _effective_tenant(effective_sub)

        db = _get_db()
        conn = db._get_conn()

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, pattern_type, lifecycle_id, tenant_id,
                       subscription_id, scan_id, finding_ids, threshold,
                       algorithm_version, created_at, updated_at
                FROM patterns
                WHERE tenant_id = %s
                  AND subscription_id = %s
                  AND (%s IS NULL OR pattern_type = %s)
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (tenant_id, effective_sub, pattern_type, pattern_type, limit),
            )
            rows = cur.fetchall()

            cur.execute(
                """
                SELECT COUNT(*) AS count
                FROM patterns
                WHERE tenant_id = %s
                  AND subscription_id = %s
                  AND (%s IS NULL OR pattern_type = %s)
                """,
                (tenant_id, effective_sub, pattern_type, pattern_type),
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
    """Return a single pattern by its integer ID.

    The pattern is only returned when its subscription_id matches the
    caller's authorized scope. An out-of-scope pattern returns 404 so
    that the existence of other subscriptions' patterns is not disclosed.
    """
    try:
        if pattern_id <= 0:
            raise _ValidationError("pattern_id must be a positive integer")

        # Resolve scope first so an unscoped caller cannot enumerate IDs.
        effective_sub = _effective_subscription(None)
        tenant_id = _effective_tenant(effective_sub)

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
                  AND tenant_id = %s
                  AND subscription_id = %s
                """,
                (pattern_id, tenant_id, effective_sub),
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
