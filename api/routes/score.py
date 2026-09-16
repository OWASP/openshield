"""Score route: overall security posture score."""

import logging
import os
from flask import Blueprint, g, jsonify

from api.models.finding import DatabaseManager

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
    """
    try:
        db = _get_db()
        result = db.get_score()
        return jsonify(result)
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
