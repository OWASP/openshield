"""CSPM agent tool functions.

Each function takes a psycopg2 connection as its first argument so callers
can inject a real or fake connection. Tenant isolation is enforced through
explicit tenant_id parameters — never trust user input for this.

No Flask imports: this module must be importable outside a Flask request
context.
"""

import logging
import uuid

logger = logging.getLogger(__name__)

_VALID_FRAMEWORKS = {"mcsb", "cis", "iso27001"}


def scan_subscription(db_manager, subscription_id: str, tenant_id: str) -> dict:
    """Queue a scan through the shared admission path.

    Unlike the other tools, the first argument is a ``DatabaseManager`` (not a
    raw connection) so the scan goes through ``admit_scan``: an advisory lock,
    idempotency, and the one-active-scan rule, exactly like the REST scan route.
    This prevents a prompt-injected or buggy loop from stampeding scans.

    Returns ``{"scan_id": str, "status": str, "created": bool}`` where
    ``created`` is False when an existing pending/running scan was reused.
    """
    scan_id = str(uuid.uuid4())
    try:
        row, created = db_manager.admit_scan(scan_id, subscription_id)
    except Exception:
        logger.exception(
            "scan_subscription failed for subscription_id=%s tenant_id=%s",
            subscription_id,
            tenant_id,
        )
        raise RuntimeError("Failed to queue scan")

    row = row or {}
    return {
        "scan_id": str(row.get("scan_id", scan_id)),
        "status": str(row.get("status", "pending")),
        "created": bool(created),
    }


def get_findings(
    db_conn,
    subscription_id: str,
    tenant_id: str,
    severity: str = None,
    state: str = None,
) -> list:
    """Return findings for the subscription, filtered by severity and/or state.

    Returns a list of dicts with keys:
        finding_id, rule_id, resource_id, severity, state
    """
    params = [tenant_id, subscription_id]
    where_clauses = [
        "fl.tenant_id = %s",
        "sro.subscription_id = %s",
    ]
    if severity is not None:
        where_clauses.append("UPPER(sro.severity) = UPPER(%s)")
        params.append(severity)
    if state is not None:
        where_clauses.append("UPPER(fl.state) = UPPER(%s)")
        params.append(state)

    sql = (
        "SELECT fl.finding_id, ff.rule_id, ff.resource_id, sro.severity, fl.state"
        " FROM finding_lifecycles fl"
        " JOIN finding_fingerprints ff ON ff.fingerprint_id = fl.fingerprint_id"
        " JOIN scan_rule_outcomes sro ON sro.outcome_id = fl.outcome_id"
        " WHERE " + " AND ".join(where_clauses) + " LIMIT 200"  # nosec B608 — clauses are static strings; only values use %s placeholders
    )
    try:
        with db_conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            return [
                {
                    "finding_id": row[0],
                    "rule_id": row[1],
                    "resource_id": row[2],
                    "severity": row[3],
                    "state": row[4],
                }
                for row in rows
            ]
    except Exception:
        try:
            db_conn.rollback()
        except Exception:
            pass
        logger.exception(
            "get_findings failed for subscription_id=%s tenant_id=%s",
            subscription_id,
            tenant_id,
        )
        return [{"error": "db_error"}]


def get_compliance_posture(db_conn, framework: str, subscription_id: str, tenant_id: str) -> dict:
    """Return compliance posture for a framework.

    Valid frameworks: "mcsb", "cis", "iso27001"
    Raises ValueError for unknown framework.

    If no data exists yet returns zeroed-out structure.
    """
    if framework.lower() not in _VALID_FRAMEWORKS:
        raise ValueError(f"Unknown compliance framework: {framework!r}. Valid options: {sorted(_VALID_FRAMEWORKS)}")

    sql = (
        "SELECT score, pass_count, fail_count, gaps"
        " FROM compliance_scores"
        " WHERE LOWER(framework) = LOWER(%s)"
        "   AND subscription_id = %s"
        "   AND tenant_id = %s"
        " LIMIT 1"
    )
    empty = {
        "framework": framework,
        "score": 0.0,
        "pass_count": 0,
        "fail_count": 0,
        "gaps": [],
    }
    try:
        with db_conn.cursor() as cur:
            cur.execute(sql, (framework, subscription_id, tenant_id))
            row = cur.fetchone()
            if row is None:
                return empty
            return {
                "framework": framework,
                "score": float(row[0]),
                "pass_count": int(row[1]),
                "fail_count": int(row[2]),
                "gaps": row[3] if row[3] is not None else [],
            }
    except Exception:
        try:
            db_conn.rollback()
        except Exception:
            pass
        logger.exception(
            "get_compliance_posture failed for framework=%s subscription_id=%s tenant_id=%s",
            framework,
            subscription_id,
            tenant_id,
        )
        return empty


def get_attack_paths(db_conn, scan_id: str, tenant_id: str) -> list:
    """Return BFS attack paths for a scan.

    STUB: returns empty list until PRs #352-354 merge.
    """
    logger.warning(
        "get_attack_paths called for scan_id=%s but attack paths are not yet available (pending PRs #352-354)",
        scan_id,
    )
    return []


def explain_finding(db_conn, finding_id: int, tenant_id: str) -> dict | None:
    """Return full detail for a finding including playbook.

    Returns None if the finding does not exist or belongs to a different tenant.
    """
    sql = (
        "SELECT fl.finding_id, ff.rule_id, ff.resource_id, sro.severity,"
        "       sro.description, sro.remediation, fl.state"
        " FROM finding_lifecycles fl"
        " JOIN finding_fingerprints ff ON ff.fingerprint_id = fl.fingerprint_id"
        " JOIN scan_rule_outcomes sro ON sro.outcome_id = fl.outcome_id"
        " WHERE fl.finding_id = %s"
        "   AND fl.tenant_id = %s"
        " LIMIT 1"
    )
    try:
        with db_conn.cursor() as cur:
            cur.execute(sql, (finding_id, tenant_id))
            row = cur.fetchone()
            if row is None:
                return None
            return {
                "finding_id": row[0],
                "rule_id": row[1],
                "resource_id": row[2],
                "severity": row[3],
                "description": row[4],
                "remediation": row[5],
                "state": row[6],
            }
    except Exception:
        try:
            db_conn.rollback()
        except Exception:
            pass
        logger.exception(
            "explain_finding failed for finding_id=%s tenant_id=%s",
            finding_id,
            tenant_id,
        )
        return {"error": "db_error"}


def suggest_remediation(db_conn, finding_id: int, tenant_id: str) -> dict | None:
    """Return step-by-step remediation for a finding.

    Reuses explain_finding internally. Returns None if finding not found or
    belongs to a different tenant.
    """
    detail = explain_finding(db_conn, finding_id, tenant_id)
    if detail is None:
        return None
    return {
        "finding_id": detail["finding_id"],
        "rule_id": detail["rule_id"],
        "steps": detail["remediation"],
        "resource_id": detail["resource_id"],
    }
