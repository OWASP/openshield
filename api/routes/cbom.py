"""Cryptographic Bill of Materials routes for post-quantum findings."""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from flask import Blueprint, g, jsonify

from api.models.finding import DatabaseManager

cbom_bp = Blueprint("cbom", __name__)
logger = logging.getLogger(__name__)

_PQC_RULE_IDS = {"AZ-PQC-001", "AZ-PQC-002", "AZ-PQC-003"}
_MIGRATION_GUIDANCE = {
    "nist_fips_203": "https://csrc.nist.gov/pubs/fips/203/final",
    "nist_fips_204": "https://csrc.nist.gov/pubs/fips/204/final",
    "nist_fips_205": "https://csrc.nist.gov/pubs/fips/205/final",
    "ncsc_guidance": "https://www.ncsc.gov.uk/guidance/pqc-migration-timelines",
    "enisa_guidance": (
        "https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation"
    ),
}


def _get_db() -> DatabaseManager:
    if "db" not in g:
        g.db = DatabaseManager(os.environ["DATABASE_URL"])
        g.db.connect()
    return g.db


def _serialise(value: Any) -> Any:
    """Convert database date values to JSON-safe ISO strings."""
    return value.isoformat() if hasattr(value, "isoformat") else value


def _asset(finding: Dict[str, Any]) -> Dict[str, Any]:
    metadata = dict(finding.get("metadata") or {})
    quantum_risk = dict(finding.get("quantum_risk") or metadata.pop("quantum_risk", {}) or {})
    score = int(quantum_risk.get("quantum_risk_score", 1))
    return {
        "finding_id": finding.get("id"),
        "scan_id": str(finding.get("scan_id") or ""),
        "rule_id": finding.get("rule_id"),
        "resource_id": finding.get("resource_id"),
        "resource_name": finding.get("resource_name"),
        "resource_type": finding.get("resource_type"),
        "severity": finding.get("severity"),
        "description": finding.get("description"),
        "remediation": finding.get("remediation"),
        "detected_at": _serialise(finding.get("detected_at")),
        "metadata": metadata,
        **quantum_risk,
        "quantum_risk_score": score,
    }


def _summary(assets: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "total_classical_assets": len(assets),
        "tls_configurations": sum(a.get("cbom_asset_type") == "tls_configuration" for a in assets),
        "asymmetric_keys": sum(a.get("cbom_asset_type") == "asymmetric_key" for a in assets),
        "certificates": sum(a.get("cbom_asset_type") == "certificate" for a in assets),
        "high_risk_assets": sum(a["quantum_risk_score"] >= 8 for a in assets),
        "harvest_now_decrypt_later_exposed": sum(bool(a.get("harvest_now_decrypt_later_exposed")) for a in assets),
    }


def _latest_cbom() -> Dict[str, Any] | None:
    db = _get_db()
    scan = db.get_latest_completed_scan()
    if not scan:
        return None
    findings = db.get_findings({"scan_id": str(scan["scan_id"])})
    assets = sorted(
        (_asset(finding) for finding in findings if finding.get("rule_id") in _PQC_RULE_IDS),
        key=lambda asset: asset["quantum_risk_score"],
        reverse=True,
    )
    generated_at = scan.get("completed_at") or datetime.now(timezone.utc)
    return {
        "cbom_version": "1.0",
        "schema": "OpenShield-CBOM",
        "generated_at": _serialise(generated_at),
        "subscription_id": str(scan.get("subscription_id") or ""),
        "summary": _summary(assets),
        "migration_guidance": _MIGRATION_GUIDANCE,
        "assets": assets,
    }


@cbom_bp.get("/api/cbom")
def get_cbom():
    """Return the full CBOM from the latest completed scan."""
    try:
        cbom = _latest_cbom()
        if cbom is None:
            return jsonify({"error": "No completed scan found"}), 404
        return jsonify(cbom)
    except Exception as exc:
        logger.error("Failed to retrieve CBOM: %s", exc)
        return jsonify({"error": "Failed to retrieve CBOM"}), 500


@cbom_bp.get("/api/cbom/summary")
def get_cbom_summary():
    """Return the CBOM summary and five highest-risk assets."""
    try:
        cbom = _latest_cbom()
        if cbom is None:
            return jsonify({"error": "No completed scan found"}), 404
        return jsonify(
            {
                "generated_at": cbom["generated_at"],
                "subscription_id": cbom["subscription_id"],
                "summary": cbom["summary"],
                "top_risk_assets": cbom["assets"][:5],
            }
        )
    except Exception as exc:
        logger.error("Failed to retrieve CBOM summary: %s", exc)
        return jsonify({"error": "Failed to retrieve CBOM summary"}), 500


@cbom_bp.get("/api/cbom/migration-roadmap")
def get_migration_roadmap():
    """Return a three-phase migration roadmap grouped by quantum risk."""
    try:
        cbom = _latest_cbom()
        if cbom is None:
            return jsonify({"error": "No completed scan found"}), 404
        assets = cbom["assets"]
        phases = [
            {
                "phase": 1,
                "name": "Immediate",
                "timeline": "Immediate",
                "risk_score": ">= 8",
                "assets": [a for a in assets if a["quantum_risk_score"] >= 8],
            },
            {
                "phase": 2,
                "name": "Short term",
                "timeline": "12 months",
                "risk_score": "5-7",
                "assets": [a for a in assets if 5 <= a["quantum_risk_score"] <= 7],
            },
            {
                "phase": 3,
                "name": "Long term",
                "timeline": "24 months",
                "risk_score": "< 5",
                "assets": [a for a in assets if a["quantum_risk_score"] < 5],
            },
        ]
        for phase in phases:
            phase["asset_count"] = len(phase["assets"])
        return jsonify(
            {
                "generated_at": cbom["generated_at"],
                "subscription_id": cbom["subscription_id"],
                "phases": phases,
            }
        )
    except Exception as exc:
        logger.error("Failed to retrieve CBOM migration roadmap: %s", exc)
        return jsonify({"error": "Failed to retrieve CBOM migration roadmap"}), 500
