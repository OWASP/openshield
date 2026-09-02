"""Scan routes: list historical scans and trigger new ones."""

import logging
import os
import hashlib
import json
import uuid
from flask import Blueprint, g, jsonify, request

from api.models.finding import DatabaseManager, ScanAdmissionConflict, ScanQuotaExceeded
from api.validation import (
    VALIDATION_ERROR_MESSAGE,
    ValidationError,
    reject_unknown_fields,
    require_json_object,
    uuid_string,
)

scans_bp = Blueprint("scans", __name__)
logger = logging.getLogger(__name__)

_AUTHORIZED_SUBSCRIPTIONS_ENV = "OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS"
_MAX_SCANS_PER_HOUR_ENV = "OPENSHIELD_MAX_SCANS_PER_SUBSCRIPTION_PER_HOUR"


def _subscription_is_authorized(subscription_id: str) -> bool:
    """Return True unless an allowlist is configured and this ID isn't on it.

    OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS is a comma-separated allowlist an
    operator can set to bound which subscription_id values this deployment
    will accept for scanning - the single-tenant containment boundary issue
    #294 asks for until a real multi-tenant/OIDC boundary exists. Any
    authenticated operator/admin token can otherwise trigger a scan against
    an arbitrary subscription_id, since role alone doesn't say which
    subscription a caller is entitled to.

    Left unset (the default), every subscription_id is accepted - identical
    to today's behavior, so existing single-operator deployments aren't
    broken by this change. api.app's startup check warns loudly when it's
    left unset.
    """
    raw = os.environ.get(_AUTHORIZED_SUBSCRIPTIONS_ENV, "")
    allowlist = {value.strip().lower() for value in raw.split(",") if value.strip()}
    return not allowlist or subscription_id.lower() in allowlist


def _get_db() -> DatabaseManager:
    if "db" not in g:
        db_url = os.environ.get("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL environment variable is not set")
        g.db = DatabaseManager(db_url)
        g.db.connect()
    return g.db


def _configured_hourly_quota() -> int:
    """Return an optional policy quota; zero preserves existing no-limit policy."""
    raw_value = os.environ.get(_MAX_SCANS_PER_HOUR_ENV, "0")
    try:
        quota = int(raw_value)
    except ValueError:
        logger.warning("Invalid %s=%r; disabling hourly quota", _MAX_SCANS_PER_HOUR_ENV, raw_value)
        return 0
    return max(0, quota)


@scans_bp.get("/api/scans")
def list_scans():
    """Return all historical scan results ordered by most recent first."""
    try:
        db = _get_db()
        result = db.get_scans()
        return jsonify(result)
    except Exception as exc:
        logger.error("Failed to list scans: %s", exc)
        return jsonify({"error": "Failed to retrieve scans"}), 500


@scans_bp.get("/api/scans/<scan_id>")
def get_scan_status(scan_id):
    """Return the details and status of a specific scan."""
    try:
        scan_id = uuid_string(scan_id, "scan_id")
        db = _get_db()
        scan = db.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify(scan)
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400
    except Exception as exc:
        logger.error("Failed to get scan status: %s", exc)
        return jsonify({"error": "Database error"}), 500


@scans_bp.post("/api/scans/trigger")
def trigger_scan():
    """Trigger an asynchronous scan against the configured subscription.

    Accepts an optional JSON body with ``subscription_id``. Falls back to the
    ``AZURE_SUBSCRIPTION_ID`` environment variable if not provided.

    Returns 202 Accepted with the scan_id immediately.
    """
    try:
        raw_body = request.get_json(silent=True)
        body = {} if raw_body is None and not request.data else require_json_object(raw_body)
        reject_unknown_fields(body, {"subscription_id"})
        subscription_id = body.get("subscription_id") or os.environ.get("AZURE_SUBSCRIPTION_ID")

        if not subscription_id:
            return jsonify({"error": "subscription_id is required"}), 400
        subscription_id = uuid_string(subscription_id, "subscription_id")

        if not _subscription_is_authorized(subscription_id):
            logger.warning("Scan trigger rejected: subscription %s is not on the authorized allowlist", subscription_id)
            return jsonify({"error": "Subscription is not authorized for this deployment"}), 403

        idempotency_key = request.headers.get("Idempotency-Key")
        if idempotency_key is not None:
            idempotency_key = idempotency_key.strip()
            if not idempotency_key or len(idempotency_key) > 200:
                return jsonify({"error": "Idempotency-Key must be between 1 and 200 characters"}), 400
        request_fingerprint = hashlib.sha256(
            json.dumps({"subscription_id": subscription_id}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        scan_id = str(uuid.uuid4())

        try:
            db = _get_db()
            admitted, created = db.admit_scan(
                scan_id,
                subscription_id,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
                max_scans_per_hour=_configured_hourly_quota(),
            )
        except ScanAdmissionConflict:
            return jsonify({"error": "Idempotency-Key is already associated with a different request."}), 409
        except ScanQuotaExceeded:
            return jsonify({"error": "Scan quota exceeded for this subscription."}), 429
        except Exception as exc:
            logger.error("Failed to create pending scan: %s", exc, exc_info=True)
            return jsonify({"error": "Database error"}), 500

        response_scan_id = str(admitted["scan_id"])
        if not created:
            return jsonify(
                {
                    "scan_id": response_scan_id,
                    "status": admitted["status"],
                    "message": "Existing logical scan returned.",
                }
            ), 200
        logger.info("Async scan admitted for subscription %s (id: %s)", subscription_id, response_scan_id)
        return jsonify(
            {
                "scan_id": response_scan_id,
                "status": "pending",
                "message": "Scan has been queued and will start shortly.",
            }
        ), 202

    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400
    except Exception as exc:
        logger.error("Critical error in trigger_scan route: %s", exc, exc_info=True)
        return jsonify({"error": "Critical route failure"}), 500


_ENRICH_MESSAGES = {
    "created": "CVE enrichment queued; poll GET /api/scans/<scan_id> for completion.",
    "requeued": "Previously failed enrichment job requeued; poll GET /api/scans/<scan_id> for completion.",
    "active": "Existing enrichment job returned.",
    "completed": "Scan already enriched",
}


@scans_bp.post("/api/scans/<scan_id>/enrich")
def enrich_scan(scan_id):
    """Enqueue durable CVE enrichment; no request-owned thread is created."""
    try:
        scan_id = uuid_string(scan_id, "scan_id")
        db = _get_db()

        current_scan = db.get_scan(scan_id)

        if not current_scan:
            return jsonify({"error": "Scan not found"}), 404

        status = current_scan.get("cve_enrichment_status")
        if status == "COMPLETED":
            return jsonify({"message": "Scan already enriched", "scan_id": scan_id}), 200
        findings = db.get_findings({"scan_id": scan_id})
        if not findings:
            return jsonify({"error": "No findings found for this scan"}), 404

        job, outcome = db.enqueue_enrichment_job(scan_id)
        body = {
            "scan_id": scan_id,
            "job_id": str(job["job_id"]),
            "status": job["status"],
            "outcome": outcome,
            "message": _ENRICH_MESSAGES[outcome],
        }
        # A job that already finished is reported as-is rather than restarted;
        # every other outcome leaves exactly one queued or running job.
        return jsonify(body), 200 if outcome == "completed" else 202

    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400
    except Exception as exc:
        logger.error("Failed to start enrichment for scan %s: %s", scan_id, exc)
        return jsonify({"error": "Internal server error"}), 500
