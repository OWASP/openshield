"""Scan routes: list historical scans and trigger new ones."""

import logging
import os
import hashlib
import json
import threading
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
from scanner.cve_correlator import enrich_findings

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
        except ScanAdmissionConflict as exc:
            return jsonify({"error": str(exc)}), 409
        except ScanQuotaExceeded as exc:
            return jsonify({"error": str(exc)}), 429
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


def _run_enrichment_in_background(scan_id: str, findings: list, db_url: str) -> None:
    """Run CVE enrichment off the request thread and persist the result.

    Runs outside the Flask request/app context (it's started via
    threading.Thread), so it opens its own DatabaseManager rather than
    reusing flask.g.
    """
    db = DatabaseManager(db_url)
    try:
        enriched = enrich_findings(findings)
        db.update_cve_fields(enriched)
        db.update_scan_enrichment_status(scan_id, "COMPLETED")
        logger.info("Background CVE enrichment complete for scan %s (%d findings)", scan_id, len(enriched))
    except Exception as exc:
        logger.error("Background enrichment failed for scan %s: %s", scan_id, exc)
        try:
            # A failed write (e.g. in update_cve_fields) can leave db.conn in
            # an aborted-transaction state. Roll back first, or this status
            # update itself raises InFailedSqlTransaction and gets swallowed
            # below, leaving the scan stuck at ENRICHING forever.
            if db.conn is not None:
                db.conn.rollback()
            db.update_scan_enrichment_status(scan_id, "FAILED")
        except Exception as status_exc:
            logger.error("Failed to record FAILED status for scan %s: %s", scan_id, status_exc)
    finally:
        db.close()


def _run_enrichment_in_background(scan_id: str, findings: list, db_url: str) -> None:
    """Run CVE enrichment off the request thread and persist the result.

    Runs outside the Flask request/app context (it's started via
    threading.Thread), so it opens its own DatabaseManager rather than
    reusing flask.g.
    """
    db = DatabaseManager(db_url)
    try:
        enriched = enrich_findings(findings)
        db.update_cve_fields(enriched)
        db.update_scan_enrichment_status(scan_id, "COMPLETED")
        logger.info("Background CVE enrichment complete for scan %s (%d findings)", scan_id, len(enriched))
    except Exception as exc:
        logger.error("Background enrichment failed for scan %s: %s", scan_id, exc)
        try:
            # A failed write (e.g. in update_cve_fields) can leave db.conn in
            # an aborted-transaction state. Roll back first, or this status
            # update itself raises InFailedSqlTransaction and gets swallowed
            # below, leaving the scan stuck at ENRICHING forever.
            if db.conn is not None:
                db.conn.rollback()
            db.update_scan_enrichment_status(scan_id, "FAILED")
        except Exception as status_exc:
            logger.error("Failed to record FAILED status for scan %s: %s", scan_id, status_exc)
    finally:
        db.close()


@scans_bp.post("/api/scans/<scan_id>/enrich")
def enrich_scan(scan_id):
    """Kick off CVE enrichment for an existing scan in the background.

    Returns immediately with 202 and status ENRICHING; poll
    GET /api/scans/<scan_id> (cve_enrichment_status) for completion.
    Running enrichment synchronously here previously caused the request to
    time out on scans spanning many rule categories, since NVD lookups are
    rate-limited to one every ~7 seconds.
    """
    try:
        scan_id = uuid_string(scan_id, "scan_id")
        db = _get_db()

        # Check current status to avoid redundant NVD calls
        scans = db.get_scans()
        current_scan = next((s for s in scans if str(s["scan_id"]) == scan_id), None)

        if not current_scan:
            return jsonify({"error": "Scan not found"}), 404

        status = current_scan.get("cve_enrichment_status")
        if status == "COMPLETED":
            return jsonify({"message": "Scan already enriched", "scan_id": scan_id}), 200
        if status == "ENRICHING":
            return jsonify({"message": "Enrichment already in progress", "scan_id": scan_id}), 202

        findings = db.get_findings({"scan_id": scan_id})
        if not findings:
            return jsonify({"error": "No findings found for this scan"}), 404

        logger.info("Starting background CVE enrichment for %d findings in scan %s", len(findings), scan_id)
        db.update_scan_enrichment_status(scan_id, "ENRICHING")

        threading.Thread(
            target=_run_enrichment_in_background,
            args=(scan_id, findings, db.dsn),
            daemon=True,
        ).start()

        return jsonify(
            {
                "scan_id": scan_id,
                "status": "ENRICHING",
                "message": "CVE enrichment started; poll GET /api/scans/<scan_id> for completion.",
            }
        ), 202

    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400
    except Exception as exc:
        logger.error("Failed to start enrichment for scan %s: %s", scan_id, exc)
        return jsonify({"error": "Internal server error"}), 500
