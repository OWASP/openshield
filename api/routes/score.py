"""Score route: overall security posture score."""

import logging
import os
from flask import Blueprint, g, jsonify, request

from api.models.finding import DatabaseManager
from api.validation import VALIDATION_ERROR_MESSAGE, ValidationError, uuid_string

score_bp = Blueprint("score", __name__)
logger = logging.getLogger(__name__)


def _get_db() -> DatabaseManager:
    if "db" not in g:
        db_url = os.environ.get("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL environment variable is not set")
        g.db = DatabaseManager(db_url)
        g.db.connect()
    return g.db


@score_bp.get("/api/score")
def get_score():
    """Return the overall security posture score (0-100).

    Score calculation:
        Starts at 100. Deducts 20 per CRITICAL finding, 10 per HIGH,
        5 per MEDIUM, 2 per LOW, and 0 per INFO. Floors at 0.

    Accepts an optional ``?subscription_id=`` so a shared-database
    deployment scores its own subscription's latest scan rather than
    whichever subscription happened to scan most recently.
    """
    try:
        # Same scoping contract as GET /api/compliance/<framework>: explicit
        # query parameter first, then this deployment's configured default.
        subscription_id = request.args.get("subscription_id") or os.environ.get("AZURE_SUBSCRIPTION_ID")
        if subscription_id:
            subscription_id = uuid_string(subscription_id, "subscription_id")

        db = _get_db()
        result = db.get_score(subscription_id=subscription_id)
        return jsonify(result)
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400
    except Exception as exc:
        logger.error("Failed to calculate score: %s", exc)
        return jsonify({"error": "Failed to calculate score"}), 500


@score_bp.get("/api/score/cve-summary")
def get_cve_summary():
    """Return high-level CVE summary for the dashboard."""
    try:
        db = _get_db()
        result = db.get_cve_summary()
        return jsonify(result)
    except Exception as exc:
        logger.error("Failed to fetch CVE summary: %s", exc)
        return jsonify({"error": "Failed to fetch CVE summary"}), 500
