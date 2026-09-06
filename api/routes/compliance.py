"""Compliance routes: framework-specific posture breakdown."""

import logging
import os
from flask import Blueprint, g, jsonify, request

from api.models.finding import DatabaseManager
from api.validation import VALIDATION_ERROR_MESSAGE, ValidationError, choice, uuid_string

compliance_bp = Blueprint("compliance", __name__)
logger = logging.getLogger(__name__)

SUPPORTED_FRAMEWORKS = ("cis", "nist", "iso27001", "soc2", "ncsc_pqc", "enisa_pqc")


def _get_db() -> DatabaseManager:
    if "db" not in g:
        db_url = os.environ.get("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL environment variable is not set")
        g.db = DatabaseManager(db_url)
        g.db.connect()
    return g.db


@compliance_bp.get("/api/compliance/<framework>")
def get_compliance(framework: str):
    """Return technical-evidence coverage against a framework mapping pack.

    Supported frameworks: cis, nist, iso27001, soc2, ncsc_pqc, enisa_pqc

    This is versioned technical evidence coverage from the most recent
    completed scan, not a certification or a claim of full framework
    compliance. Each control also reports mapping_type, evidence_type,
    primary_source, rationale, owner and review_status; controls whose
    mapping_type is not_applicable or organizational are excluded from
    score_percent. If no completed scan exists yet, status is NO_SCAN_DATA
    and no PASS/FAIL is reported.
    """
    try:
        framework = choice(framework, "framework", SUPPORTED_FRAMEWORKS, case="lower")

        # Scope to a subscription so a shared-database deployment never
        # returns another subscription's latest scan/score. Falls back to
        # this deployment's configured default subscription, matching the
        # same AZURE_SUBSCRIPTION_ID fallback POST /api/scans uses.
        subscription_id = request.args.get("subscription_id") or os.environ.get("AZURE_SUBSCRIPTION_ID")
        if subscription_id:
            subscription_id = uuid_string(subscription_id, "subscription_id")

        db = _get_db()
        result = db.get_compliance_score(framework, subscription_id=subscription_id)

        if "error" in result:
            return jsonify(result), 500

        return jsonify(result)
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE, "supported": list(SUPPORTED_FRAMEWORKS)}), 400
    except FileNotFoundError as exc:
        logger.error("Frameworks directory not found: %s", exc)
        return jsonify({"error": "Compliance frameworks are not available"}), 500
    except Exception as exc:
        logger.error("Failed to retrieve compliance score for %s: %s", framework, exc)
        return jsonify({"error": "Compliance calculation failed"}), 500
