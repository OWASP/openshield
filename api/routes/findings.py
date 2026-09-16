"""Findings routes: list, retrieve, and get remediation playbooks for findings."""

import logging
import os
from pathlib import Path
from flask import Blueprint, g, jsonify, request

from api.models.finding import DatabaseManager
from api.validation import (
    CATEGORIES,
    RULE_ID_RE,
    VALIDATION_ERROR_MESSAGE,
    ValidationError,
    bounded_string,
    canonical_choice,
    positive_integer,
    severity_value,
    uuid_string,
)

_PLAYBOOKS_DIR = (Path(__file__).parent.parent.parent / "playbooks" / "cli").resolve()

# Known rule_id shape, e.g. AZ-STOR-001. Anything else is rejected before it
# ever reaches the filesystem, closing off path traversal via a crafted or
# corrupted rule_id.
findings_bp = Blueprint("findings", __name__)
logger = logging.getLogger(__name__)


def _get_db() -> DatabaseManager:
    if "db" not in g:
        g.db = DatabaseManager(os.environ["DATABASE_URL"])
        g.db.connect()
    return g.db


@findings_bp.get("/api/findings")
def list_findings():
    """Return findings, optionally filtered by severity, category, or rule_id.

    Query parameters:
        severity  - CRITICAL | HIGH | MEDIUM | LOW | INFO
        category  - Storage | Network | Identity | Database | Compute | KeyVault
        rule_id   - e.g. AZ-STOR-001
        scan_id   - UUID of a specific scan
    """
    try:
        allowed = {"severity", "category", "rule_id", "scan_id"}
        unknown = set(request.args) - allowed
        if unknown:
            raise ValidationError(f"Unsupported query parameter: {sorted(unknown)[0]}")
        for key in request.args:
            if len(request.args.getlist(key)) != 1:
                raise ValidationError(f"Query parameter {key} must be provided once")

        filters = {}
        if "severity" in request.args:
            filters["severity"] = severity_value(request.args["severity"])
        if "category" in request.args:
            filters["category"] = canonical_choice(request.args["category"], "category", CATEGORIES)
        if "rule_id" in request.args:
            filters["rule_id"] = bounded_string(
                request.args["rule_id"].upper(), "rule_id", maximum=64, pattern=RULE_ID_RE
            )
        if "scan_id" in request.args:
            filters["scan_id"] = uuid_string(request.args["scan_id"], "scan_id")
        db = _get_db()
        findings = db.get_findings(filters)
        return jsonify({"count": len(findings), "findings": findings})
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400
    except Exception as exc:
        logger.error("Failed to list findings: %s", exc)
        return jsonify({"error": "Failed to retrieve findings"}), 500


@findings_bp.get("/api/findings/<int:finding_id>")
def get_finding(finding_id: int):
    """Return a single finding by its integer ID."""
    try:
        finding_id = positive_integer(finding_id, "finding_id")
        db = _get_db()
        finding = db.get_finding_by_id(finding_id)
        if not finding:
            return jsonify({"error": "Finding not found"}), 404
        return jsonify(finding)
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400
    except Exception as exc:
        logger.error("Failed to get finding %d: %s", finding_id, exc)
        return jsonify({"error": "Database error"}), 500


@findings_bp.get("/api/findings/<int:finding_id>/playbook")
def get_playbook(finding_id: int):
    """Return a structured remediation playbook for a finding.

    Loads the pre-written Azure CLI script from playbooks/cli/ (keyed by rule_id)
    and combines it with the finding's remediation guidance and any CVE references.
    """
    try:
        finding_id = positive_integer(finding_id, "finding_id")
        db = _get_db()
        finding = db.get_finding_by_id(finding_id)
        if not finding:
            return jsonify({"error": "Finding not found"}), 404

        rule_id = finding.get("rule_id", "")
        remediation = finding.get("remediation", "")
        cve_refs = finding.get("cve_references") or []

        cli_commands = []
        script_path = None
        if RULE_ID_RE.match(rule_id or ""):
            # Map rule_id (e.g. AZ-STOR-001) to script filename (fix_az_stor_001.sh)
            script_name = "fix_" + rule_id.lower().replace("-", "_") + ".sh"
            candidate = (_PLAYBOOKS_DIR / script_name).resolve()
            if candidate.is_relative_to(_PLAYBOOKS_DIR):
                script_path = candidate
        else:
            logger.warning("Rejected malformed rule_id for playbook lookup: %r", rule_id)

        if script_path is not None and script_path.exists():
            raw = script_path.read_text()
            # Strip comment-only lines and blank lines; join multi-line commands
            lines = raw.splitlines()
            cmd_lines = [
                line
                for line in lines
                if line.strip() and not line.strip().startswith("#") and line.strip() not in ("set -e",)
            ]
            cli_commands = ["\n".join(cmd_lines)] if cmd_lines else []

        portal_steps = [remediation] if remediation else []

        validation_steps = [
            "Open the Azure Portal and navigate to the resource.",
            f"Verify the security configuration matches the remediation guidance for {rule_id}.",
            "Re-run an OpenShield scan and confirm this finding no longer appears.",
        ]

        references = []
        for cve in cve_refs:
            cve_id = cve.get("cve_id", "")
            if cve_id:
                references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        if not references:
            references.append("https://learn.microsoft.com/en-us/azure/security/")

        return jsonify(
            {
                "portal_steps": portal_steps,
                "cli_commands": cli_commands,
                "validation_steps": validation_steps,
                "references": references,
            }
        )

    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400
    except Exception as exc:
        logger.error("Failed to get playbook for finding %d: %s", finding_id, exc)
        return jsonify({"error": "Failed to retrieve playbook"}), 500
